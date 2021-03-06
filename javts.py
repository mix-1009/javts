
__version__ = '0.2'
__author__ = 'Sergii Naumov'

import os
import sys
import hashlib
import argparse
import ntpath
import json
import re
import datetime
from multiprocessing.dummy import Pool as ThreadPool

from virus_total import VirusTotal
from vt_report import VTReport
from vt_report_generator import VTReportOutputGenerator


parser = argparse.ArgumentParser()
parser.add_argument(
    '-get', action='store_true', help='Get existing report from Virus Total.'
    )
parser.add_argument(
    '-submit',
    action='store_true',
    help='Submit files on Virus Total. Not supported yet.'
    )
parser.add_argument('-hash', metavar='', help='File hash.')
parser.add_argument('-f', metavar='', help='File name.')
parser.add_argument('-d', metavar='', help='Directory with files.')
parser.add_argument(
    '-hash_file', metavar='', help='File with sha1/sha256/md5 hashes.'
    )
parser.add_argument('-log', metavar='', help='Store results to log file.')
parser.add_argument(
    '-v_off',
    action='store_true',
    help='Turn off verbose mode. Works only if log on.'
    )


valid_hash = re.compile('([a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64})$')
re_hash_file = re.compile(
    '([a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64})(?:\s|,|$)'
    )


def create_requests_pool(instance, data):
    vt = VirusTotal(instance)
    pool = ThreadPool(4)
    pool.map(vt.execute, data)
    pool.close()
    pool.join()
    return vt.Reports


def submit_files_to_vt(data):
    results = create_requests_pool('submit', TEST_DATA)


def seconds_to_h_m_s(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return [int(h), int(m), int(s)]


def file_sha1sum(fname):
    hash_sha1 = hashlib.sha1()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()


def is_valid_hash(file_hash):
    return valid_hash.match(file_hash) is not None


def check_files_on_vt(data, log_file=None):
    if len(data) > 0:
        vt_generator = VTReportOutputGenerator()
        estimated_time_s = 4  # Emperical value
        estimated_time = [0, 0, estimated_time_s]

        if len(data) > VirusTotal.REQUEST_LIMIT:
            estimated_time_s = (len(data)
                                / VirusTotal.REQUEST_LIMIT
                                * VirusTotal.TIME_INTERVAL)
            estimated_time = seconds_to_h_m_s(estimated_time_s)
        t = (datetime.datetime.now()
             + datetime.timedelta(seconds=estimated_time_s))

        print('{0} file(s) will be checked on VT.'.format(len(data)))
        print('Current VT limit: {0} requests per {1} seconds.\n'.format(
            VirusTotal.REQUEST_LIMIT, VirusTotal.TIME_INTERVAL)
        )
        print('Current time: {}'.format(
            datetime.datetime.now().strftime("%H:%M:%S"))
        )
        print('Estimated delta time: {0:02}:{1:02}:{2:02}'.format(
            *estimated_time)
        )
        print('Estimated completion time: {}\n'.format(
            t.time().strftime("%H:%M:%S"))
        )

        results = create_requests_pool('check', list(data.keys()))
        vt_report = VTReport(results)
        vt_generator.print_results(vt_report, data)

        if log_file:
            vt_generator.save_results(vt_report, data, log_file)


def is_valid_arguments(args):
    if len(sys.argv) < 3:
        return False
    if not (args.get ^ args.submit):
        return False
    if args.submit and args.hash:
        return False
    if ((args.log is None) and (args.v_off is True)):
        return False
    return (int(args.hash is not None)
            + int(args.f is not None)
            + int(args.d is not None)
            + int(args.hash_file is not None)) == 1


if __name__ == '__main__':
    with open('logos/logo.txt', 'r') as f:
        print(f.read())
    print('Just Another Virus Total Submitter.')
    print('version = {0}\n'.format(__version__))

    with open('config.json', 'r') as f:
        config = json.load(f)
        if not is_valid_hash(config['VirusTotalKey']):
            print(
                'Invalid key. '
                'Please add valid VirusTotal key in config.json file.\n'
                )
            sys.exit(0)

        VirusTotal.API_KEY = config['VirusTotalKey']

    args = parser.parse_args()
    entities = {}

    if not is_valid_arguments(args):
        parser.print_help()
        sys.exit(0)

    if args.v_off:
        VTReportOutputGenerator.VERBOSE_MODE = False

    if args.submit:
        print('Submit method not yet implemented.')
    else:
        if args.hash is not None:
            if is_valid_hash(args.hash):
                entities[args.hash] = args.hash

        elif args.f is not None:
            entities[file_sha1sum(args.f)] = args.f

        elif args.d is not None:
            if os.path.isdir(args.d):
                for root, sub_folders, files in os.walk(args.d):
                    for f in files:
                        fpath = os.path.join(root, f)
                        entities[file_sha1sum(fpath)] = fpath

        elif args.hash_file is not None:
            with open(args.hash_file, 'r') as f:
                result = re_hash_file.findall(f.read())
                print('{} hashes was read from {}'.format(
                    len(result), args.hash_file)
                )
                result = set(result)
                print('({} unique hashes.)\n'.format(len(result)))
                for h in result:
                    entities[h] = h

        check_files_on_vt(entities, args.log)

    print('\n')
    print('°º¤ø,¸¸,ø¤º°`°º¤ø,¸,ø¤°º¤ø,¸¸,ø¤º°`°º¤ø,¸')
