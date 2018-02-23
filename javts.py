
__version__ = '0.2'
__author__ = 'Sergii Naumov'

import os
import sys
import argparse
import ntpath
import datetime
from multiprocessing.dummy import Pool as ThreadPool

from virus_total import VirusTotal
from vt_report import VTReport
from vt_report_generator import VTReportOutputGenerator
from javts_config import JavtsConfig
from generic import *

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

END_OF_OUTPUT = '\n°º¤ø,¸¸,ø¤º°`°º¤ø,¸,ø¤°º¤ø,¸¸,ø¤º°`°º¤ø,¸\n'


def create_requests_pool(instance, data):
    vt = VirusTotal(instance)
    pool = ThreadPool(4)
    pool.map(vt.execute, data)
    pool.close()
    pool.join()
    return vt.Reports


def submit_files_to_vt(data, log_file=None):
    if len(data) > 0:
        estimated_time, t = get_estimated_time(
            len(data), VirusTotal.REQUEST_LIMIT, VirusTotal.TIME_INTERVAL)

        print('{0} file(s) will be submitted to VT.'.format(len(data)))
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

        results = create_requests_pool('submit', list(data.values()))
 


def check_files_on_vt(data, log_file=None):
    if len(data) > 0:
        vt_generator = VTReportOutputGenerator()
        estimated_time, t = get_estimated_time(
            len(data), VirusTotal.REQUEST_LIMIT, VirusTotal.TIME_INTERVAL)

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


if __name__ == '__main__':
    with open('logos/logo.txt', 'r') as f:
        print(f.read())
    print('Just Another Virus Total Submitter.')
    print('version = {0}\n'.format(__version__))

    # load config file
    jconfig = JavtsConfig()
    jconfig.load_config_file()
    if not jconfig.is_correct:
        print(jconfig.message)
        print(END_OF_OUTPUT)
        sys.exit(0)

    VirusTotal.API_KEY = jconfig.API_KEY

    # parse cmd args
    if len(sys.argv) == 1:
        parser.print_help()
        print(END_OF_OUTPUT)
        sys.exit(0)

    args = parser.parse_args()
    jconfig.load_command_arguments(args)
    if not jconfig.is_correct:
        print(jconfig.message)
        print(END_OF_OUTPUT)
        sys.exit(0)

    VTReportOutputGenerator.VERBOSE_MODE = jconfig.VERBOSE

    entities = {}

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

    if args.submit:
        submit_files_to_vt(entities, jconfig.LOG_NAME)
    else:
        check_files_on_vt(entities, jconfig.LOG_NAME)

    print('\n')
    print(END_OF_OUTPUT)
