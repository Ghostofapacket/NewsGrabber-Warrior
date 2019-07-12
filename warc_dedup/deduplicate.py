import aiohttp
import asyncio
import datetime
import os
import re
import urllib.parse

from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter

from warc_dedup.log import Log
from warc_dedup.utils import get


class Warc:
    def __init__(self, warc_source: str, warc_target: str=None):
        self.warc_source = warc_source
        self.warc_target = warc_target
        self._response_records = {}
        self._log = Log()
        self._log.log('Original WARC file is {}.'.format(self.warc_source))
        self._log.log('Deduplicated WARC file is {}.'.format(self.warc_target))
        if os.path.isfile(self.warc_target):
            self._log.log('File {} already exists.'.format(self.warc_target))
            raise Exception('File {} already exists.'.format(self.warc_target))

    def deduplicate(self):
        self._log.log('Start deduplication process.')

        iaData = {} # dict of (payload digest, URL) => IA response|None
        with open(self.warc_source, 'rb') as s:
            for record in ArchiveIterator(s):
                if record.rec_headers.get_header('WARC-Type') == 'response':
                    iaData[(record.rec_headers.get_header('WARC-Payload-Digest'), record.rec_headers.get_header('WARC-Target-URI'))] = None

        self.fetch_from_ia(iaData)

        with open(self.warc_source, 'rb') as s, \
                open(self.warc_target, 'wb') as t:
            writer = WARCWriter(filebuf=t, gzip=self.warc_target.endswith('.gz'))
            for record in ArchiveIterator(s):
                url = record.rec_headers.get_header('WARC-Target-URI')
                record_id = record.rec_headers.get_header('WARC-Record-ID')
                self._log.log('Processing record {}.'.format(record_id))
                if url is not None and url.startswith('<'):
                    url = re.search('^<(.+)>$', url).group(1)
                    self._log.log('Replacing URL in record {} with {}.'
                                  .format(record_id, url))
                    record.rec_headers.replace_header('WARC-Target-URI', url)
                if record.rec_headers.get_header('WARC-Type') == 'response':
                    self._log.log('Deduplicating record {}.'.format(record_id))
                    key = (record.rec_headers.get_header('WARC-Payload-Digest'), record.rec_headers.get_header('WARC-Target-URI'))
                    assert key in iaData
                    if iaData[key]:
                        self._log.log('Record {} is a duplicate from {}.'
                                      .format(record_id, iaData[key]))
                        writer.write_record(
                            self.response_to_revisit(writer, record, iaData[key])
                        )
                    else:
                        if iaData[key] is False:
                            self._log.log('Record {} could not be deduplicated.'
                                .format(record_id))
                        else:
                            self._log.log('Record {} is not a duplicate.'
                                .format(record_id))
                        self.register_response(record)
                        writer.write_record(record)
                elif record.rec_headers.get_header('WARC-Type') == 'warcinfo':
                    self._log.set_warcinfo(record.rec_headers.get_header('WARC-Record-ID'))
                    record.rec_headers.replace_header('WARC-Filename', self.warc_target)
                    writer.write_record(record)
                else:
                    writer.write_record(record)
            self._log.log('Writing log to WARC.')
            writer.write_record(self._log.create_record(writer))

    def register_response(self, record):
        key = (
            record.rec_headers.get_header('WARC-Payload-Digest'),
            record.rec_headers.get_header('WARC-Target-URI')
        )
        self._response_records[key] = {
            'record-id': record.rec_headers.get_header('WARC-Record-ID'),
            'date': record.rec_headers.get_header('WARC-Date'),
            'target-uri': record.rec_headers.get_header('WARC-Target-URI')
        }

    @staticmethod
    def response_to_revisit(writer, record, data):
        warc_headers = record.rec_headers
        if 'record-id' in data and data['record-id'] is not None:
            warc_headers.replace_header('WARC-Refers-To', data['record-id'])
        warc_headers.replace_header('WARC-Refers-To-Date', data['date'])
        warc_headers.replace_header('WARC-Refers-To-Target-URI',
                                    data['target-uri'])
        warc_headers.replace_header('WARC-Type', 'revisit')
        warc_headers.replace_header('WARC-Truncated', 'length')
        warc_headers.replace_header('WARC-Profile',
                                    'http://netpreserve.org/warc/1.0/' \
                                    'revisit/identical-payload-digest')
        warc_headers.remove_header('WARC-Block-Digest')
        warc_headers.remove_header('Content-Length')
        return writer.create_warc_record(
            record.rec_headers.get_header('WARC-Target-URI'),
            'revisit',
            warc_headers=warc_headers,
            http_headers=record.http_headers
        )

    async def fetch_single(self, key, session):
        digest, uri = key
        for tofrom, date in (('to', '201905310000'), ('from', '20190703000')):
            for i in range(10):
                try:
                    async with session.get(
                      'http://wwwb-dedup.us.archive.org:8083/cdx/search'
                      '?url={}'.format(urllib.parse.quote(uri)) +
                      '&limit=100'
                      '&filter=digest:{}'.format(digest.split(':')[1]) +
                      '&fl=timestamp,original'
                      '&{}={}'.format(tofrom, date) +
                      '&filter=!mimetype:warc\/revisit') as resp:
                        return key, await resp.text()
                except aiohttp.ClientError as e:
                    pass
        return key, None

    async def fetch_from_ia_async(self, iaData):
        async with aiohttp.ClientSession(connector = aiohttp.TCPConnector(limit = 10)) as session:
            pending = []
            for key in iaData:
                pending.append(asyncio.ensure_future(self.fetch_single(key, session)))

            done, pending = await asyncio.wait(pending)
            assert len(pending) == 0
            for task in done:
                key, response = await task
                iaData[key] = self.parse_ia_response(key, response)

    def fetch_from_ia(self, iaData: dict):
        self._log.log('Fetching dedupe info from IA')
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.fetch_from_ia_async(iaData))
        loop.close()
        self._log.log('Fetched dedupe info from IA')

    def parse_ia_response(self, key, response):
        # Parse response (str or None), returns False if an error occurred, None if there is no previous record, or a dict if there is.
        if response is None:
            self._log.log('Key {} got no or a bad CDX API response.'.format(key))
            return False
        if len(response.strip()) == 0:
            return None
        if 'org.archive.wayback.exception.RobotAccessControlException' in response:
            self._log.log('Key {} is blocked by robots.txt.'.format(key))
            return False
        if 'org.archive.wayback.exception.AdministrativeAccessControlException' in response:
            self._log.log('Key {} is excluded from the CDX API.'.format(key))
            return False
        if 'Requested Line is too large' in response:
            self._log.log('Key {} has a too large URL.'.format(key))
            return False
        for line in response.splitlines():
            if not re.search('^[0-9]{14}\s+https?://', line):
                continue
            break
        else:
            self._log.log('Key {} for an invalid CDX API response'.format(key))
            return False
        data = line.strip().split(' ', 1)
        return {
            'target-uri': data[1],
            'date': datetime.datetime.strptime(data[0], '%Y%m%d%H%M%S'). \
                strftime('%Y-%m-%dT%H:%M:%SZ')
        }

    @property
    def warc_target(self) -> str:
        return self._warc_target

    @warc_target.setter
    def warc_target(self, value: str):
        if value is not None:
            self._warc_target = value
        self._warc_target = create_warc_target(self.warc_source)


def create_warc_target(warc_source: str) -> str:
    if warc_source.endswith('.warc.gz'):
        return warc_source.rsplit('.', 2)[0] + '.deduplicated.warc.gz'
    elif warc_source.endswith('.warc'):
        return warc_source.rsplit('.', 1)[0] + '.deduplicated.warc'
