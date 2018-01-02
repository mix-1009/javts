from datetime import datetime

class VTReportOutputGenerator:


    def __init__(self):
        pass

    def print_results(self, report, entities):
        print('\n')
        print('{:#^64}'.format(''))
        print('{:^64}'.format('Virus Total Report {0}'.format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))
        print('{:#^64}\n'.format(''))
        
        positives = report.get_positive_reports()
        clear = report.get_clear_reports()
        empty = report.get_empty_reports()
        bad_requests = report.get_bad_requests()

        for v in (positives+clear):
            self._print(v.request_result, v.original_entity)

        for v in empty:
            print('{0:-^64}\n{1} : {2}\n'.format(v.original_entity, v.request_result['resource'], v.request_result['verbose_msg']))

        for v in bad_requests:
            print('{0:-^64}\n{1}'.format(v.original_entity, v.request_result['verbose_msg']))

        print('{:#^64}'.format(' Statistics '))
        print('Total entities was requested: {}'.format(len(entities)))
        print('Total reports was received: {}'.format(len(positives)+len(clear)))
        print('  positives scans: {}'.format(len(positives)))
        print('  clean scans: {}'.format(len(clear)))
        print('Not among the finished, queued or pending scans: {}'.format(len(empty)))
        if len(bad_requests) > 0:
            print('Responces FAILED: {}'.format(len(bad_requests)))


    def _print(self, file_report, origin_entity):
        print('{:-^64}'.format(origin_entity))
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

