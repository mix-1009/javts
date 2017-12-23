from datetime import datetime

class VTReportOutputGenerator:

    SORT_BY_POSITIVES = True


    def __init__(self):
        pass

    def print_results(self, data):
        print('\n')
        print('{:#^64}'.format(''))
        print('Virus Total Report {0}'.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        print('{:#^64}'.format(''))
        
        if VTReportOutputGenerator.SORT_BY_POSITIVES:
            data = sorted(data, reverse=True, key=lambda x: x[1]['response_code'])
            firs_zero_rc_idx = len(data)
            try:
                firs_zero_rc_idx = next(idx for x, idx in zip(data, range(len(data))) if x[1]['response_code']==0)
            except StopIteration:
                pass
            data[:firs_zero_rc_idx] = sorted(data[:firs_zero_rc_idx], reverse=True, key=lambda x:x[1]['positives'])

        for v in data:
            if v[1]['response_code'] == 1:
                self._print(v)
            else:
                print('{0:-^64}\n{1}\n'.format(v[0], v[1]['verbose_msg']))


    def _print(self, report):
        entity = report[0]
        file_report = report[1]

        print('{:-^64}'.format(entity))
        print('sha1: {0}'.format(file_report['sha1']))
        print('md5: {0}'.format(file_report['md5']))
        print('sha256: {0}'.format(file_report['sha256']))
        print('Scan date: {0}'.format(file_report['scan_date']))
        print('Rate: {0}/{1}'.format(file_report['positives'], file_report['total']))
        print('permalink: {0}'.format(file_report['permalink']))
        print('Detects: ')
        
        for av, results in file_report['scans'].items():
            if results['detected'] == True:
                print(' - {0} ({1} {2}): {3}'.format(av, results['version'], results['update'], results['result']))
        print('\n')

