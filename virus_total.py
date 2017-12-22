import time
import requests
import logging

class VirusTotal:
    
    API_KEY = ''
    REQUEST_LIMIT = 4
    TIME_INTERVAL = 60


    def __init__(self, instance):
        self.RequestList = []
        self.Reports = []
        self.logger = self._get_logger()

        if instance == 'submit':
            self.instance = self._submit
        elif instance == 'check':
            self.instance = self._check
        else:
            self.instance = None


    def execute(self, v):
        result = None
        if VirusTotal.REQUEST_LIMIT == 0:
            """Full Virus Toltal version
            Without limits.
            """
            result = self.instance(v)
        else:
            while True:
                if len(self.RequestList) < VirusTotal.REQUEST_LIMIT:
                    self.RequestList.append(int(time.time()))
                    result = self.instance(v)
                    self.logger.info('INFO: Received {0}'.format(v))
                    # print('INFO: Received {0}'.format(v))
                    break
                else:
                    t = self.RequestList[0]
                    delta_t = int(time.time()) - t
                    if delta_t >= VirusTotal.TIME_INTERVAL:
                        del self.RequestList[0]
                    else:
                        time.sleep(delta_t)
            
        self.Reports.append((v, result))


    def _submit(self, req_file):
        json_response = None
        params = {'apikey': VirusTotal.API_KEY}
        files = {'file': (req_file, open(req_file, 'rb'))}

        try:
            response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
            json_response = response.json()
        except requests.exceptions.RequestException as e:
            pass
        except ValueError as e:
            pass
        
        return json_response


    def _check(self, file_hash):
        json_response = None
        params = {'apikey': VirusTotal.API_KEY, 'resource': file_hash}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent" : "gzip,  My Python requests library example client or username"
        }

        try:
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
            json_response = response.json()
        except requests.exceptions.RequestException as e:
            pass
        except ValueError as e:
            pass

        return json_response
        
    def _get_logger(self):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)

        return logger

        