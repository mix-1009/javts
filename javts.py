
__version__ = '0.1'
__author__ = 'Sergii Naumov'

import os
import sys
import hashlib
import argparse
import ntpath
import json
import re

from multiprocessing.dummy import Pool as ThreadPool 
from virus_total import VirusTotal
from vt_report_generator import VTReportOutputGenerator


parser = argparse.ArgumentParser()
parser.add_argument('-get', action='store_true', help='Get existing report from Virus Total.')
parser.add_argument('-submit', action='store_true', help='Submit files on Virus Total. Not supported yet.')
parser.add_argument('-hash', metavar = '', help='File hash.')
parser.add_argument('-f', metavar = '', help='File name.')
parser.add_argument('-d', metavar = '', help='Directory with files.')

valid_hash = re.compile('([a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64})$')


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


def sha1(fname):
    hash_sha1 = hashlib.sha1()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()


def is_valid_hash(file_hash):
    return valid_hash.match(file_hash) != None


def check_files_on_vt(data):
    if len(data) > 0:
        vt_generator = VTReportOutputGenerator()
        print('{0} file(s) will be checked on VT.'.format(len(data)))
        print('Current VT limit: {0} requests per {1} seconds.'.format(VirusTotal.REQUEST_LIMIT, VirusTotal.TIME_INTERVAL))
        estimated_time = [0, 0, 4] # Emperical value
        if len(data) > VirusTotal.REQUEST_LIMIT:
            estimated_time = len(data)/VirusTotal.REQUEST_LIMIT * VirusTotal.TIME_INTERVAL
            estimated_time = seconds_to_h_m_s(estimated_time)

        print('Estimated time: {0:02}:{1:02}:{2:02}'.format(*estimated_time))
        print('\n')

        results = create_requests_pool('check', data)
        vt_generator.print_results(results)


def is_valid_arguments(args):
    if len(sys.argv) < 3:
        return False
    if not (args.get ^ args.submit):
        return False

    return (int(args.hash != None) + int(args.f != None) + int(args.d != None)) == 1


if __name__ == '__main__':
    with open('logos/logo.txt', 'r') as f:
        print(f.read())
    print('Just Another Virus Total Submitter.')
    print('version = {0}\n'.format(__version__))

    with open('config.json', 'r') as f:
        config = json.load(f)
        VirusTotal.API_KEY = config['VirusTotalKey']

    args = parser.parse_args()
    entities = []

    if is_valid_arguments(args):
        if args.hash != None:
            if is_valid_hash(args.hash):
                entities.append(args.hash)    
        
        elif args.f != None:
            entities.append(sha1(args.f))
        
        elif args.d != None:
            if os.path.isdir(args.d):
                for root, sub_folders, files in os.walk(args.d):
                    for f in files:
                        fpath = os.path.join(root, f)
                        entities.append(sha1(fpath))

        check_files_on_vt(entities)        
    else:
        parser.print_help()

    print('\n')
    print('°º¤ø,¸¸,ø¤º°`°º¤ø,¸,ø¤°º¤ø,¸¸,ø¤º°`°º¤ø,¸')