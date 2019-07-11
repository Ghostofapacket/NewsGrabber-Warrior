# encoding=utf8
import sys
import re
import time
import requests
import random
import warcio
from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter
from datetime import datetime

assert hasattr(warcio, 'ATWARCIO'), 'warcio was not imported correctly. Location: ' + warcio.__file__

def ia_available(url, digest):
    print('Deduplicating digest ' + digest + ', url ' + url)
    assert digest.startswith('sha1:')
    digest = digest.split(':', 1)[1]
    verification_re = re.compile('^\d{14}\ http?s://')
    tries = 0
    delay = 1
    while True:
        try:
            if tries <= 9:
                pass
            else:
                raise Exception('Internet Archive CDX API Offline - Aborting')
            tries += 1
            ia_data = requests.get(
                'http://wwwb-dedup.us.archive.org/cdx/search/cdx?url={url}&gzip=false&limit=1&filter=digest:{digest}&fl=timestamp,original&to=201905310000' \
                .format(url=url, digest=digest), timeout=3)
        except requests.ConnectionError as error:
                print("Error connecting to web.archive.org/cdx/search - Sleeping for " + str(round(delay, 2)) + " seconds.")
                time.sleep(delay)
                delay += delay + (random.randint(0,1000)/1000)
                continue
        break
    if re.search(verification_re, str(ia_data.text)):
        return ia_data.text.split(' ', 1)
    tries = 0
    delay = 1
    while True:
        try:
            if tries <= 9:
                pass
            else:
                raise ValueError('Internet Archive CDX API Offline - Aborting')
                exit(1)
            ia_data = requests.get(
                'http://wwwb-dedup.us.archive.org/cdx/search/cdx?url={url}&gzip=false&limit=1&filter=digest:{digest}&fl=timestamp,original&from=20190703000' \
                .format(url=url, digest=digest), timeout=3)
        except requests.ConnectionError as error:
            print("Error connecting to web.archive.org/cdx/search - Sleeping for " + str(round(delay, 2)) + " seconds.")
            time.sleep(delay)
            delay += delay + (random.randint(0, 1000) / 1000)
            continue
        break
    if re.search(verification_re, str(ia_data.text)):
        return ia_data.text.split(' ', 1)
    return False

def revisit_record(writer, record, ia_record):
    warc_headers = record.rec_headers
    warc_headers.replace_header('WARC-Refers-To-Date',
                                '-'.join([ia_record[0][:4], ia_record[0][4:6], ia_record[0][6:8]]) + 'T' +
                                ':'.join([ia_record[0][8:10], ia_record[0][10:12], ia_record[0][12:14]]) + 'Z')
    warc_headers.replace_header('WARC-Refers-To-Target-URI', ia_record[1])
    warc_headers.replace_header('WARC-Type', 'revisit')
    warc_headers.replace_header('WARC-Truncated', 'length')
    warc_headers.replace_header('WARC-Profile', 'http://netpreserve.org/warc/1.0/revisit/identical-payload-digest')
    warc_headers.remove_header('WARC-Block-Digest')
    warc_headers.remove_header('Content-Length')

    return writer.create_warc_record(
        record.rec_headers.get_header('WARC-Target-URI'),
        'revisit',
        warc_headers=warc_headers,
        http_headers=record.http_headers
    )

def process(filename_in, filename_out):
    starttime = datetime.now()
    dedupemiss = 0
    dedupehit = 0
    with open(filename_in, 'rb') as file_in:
        with open(filename_out, 'wb') as file_out:
            writer = WARCWriter(filebuf=file_out, gzip=True)
            for record in ArchiveIterator(file_in):
                if record.rec_headers.get_header('WARC-Type') == 'response':
                    record_url = record.rec_headers.get_header('WARC-Target-URI')
                    record_digest = record.rec_headers.get_header('WARC-Payload-Digest')
                    ia_record = ia_available(record_url, record_digest)
                    if not ia_record:
                        writer.write_record(record)
                    else:
                        print('Found duplicate, writing revisit record.')
                        writer.write_record(revisit_record(writer, record, ia_record))
                        dedupehit = dedupehit + 1
                else:
                    writer.write_record(record)
                    dedupemiss = dedupemiss + 1
    print(str(dedupehit) + " Hits")
    print(str(dedupemiss) + " Misses")
    print("took " + str(datetime.now() - starttime) + " to execute")

if __name__ == '__main__':
    filename_in = sys.argv[1]
    filename_out = sys.argv[2]
    process(filename_in, filename_out)
