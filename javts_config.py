import json
import sys

from generic import *

class JavtsConfig:

    def __init__(self, f_conf='config.json'):
        self.f_conf = f_conf
        self.is_correct = True
        self.config = None
        self.message = None
        self.default_log_name = 'jlog_{}.txt'

        self.args = None
        self.API_KEY = None
        self.LOG_ON = False
        self.LOG_NAME = None
        self.LOG_REWRITE = False
        self.VERBOSE = True

    def load_config_file(self):
        try:
            with open(self.f_conf, 'r') as f:
                self.config = json.load(f)
                self.is_correct = self._load_config()
        except FileNotFoundError:
            self.message = 'ERROR: config.json not found.'
            self.is_correct = False


    # Command arguments overwrite config parameters
    def load_command_arguments(self, args):
        if not self._is_valid_arguments(args):
            self.message = 'ERROR: invalid command arguments.'
            self.is_correct = False
        else:
            self.args = args
            if args.v_off:
                self.VERBOSE = False
            if args.log:
                self.LOG_NAME = args.log


    def _is_valid_arguments(self, args):
        if len(sys.argv) < 3:
            return False
        if not (args.get ^ args.submit):
            return False
        if args.submit and args.hash:
            return False
        # Verbose mode used only with Log file on.
        if (((args.log is None) and (not self.LOG_ON)) and (args.v_off is True)):
            return False
        return (int(args.hash is not None)
                + int(args.f is not None)
                + int(args.d is not None)
                + int(args.hash_file is not None)) == 1


    def _load_config(self):
        if not is_valid_hash(self.config['VirusTotalKey']):
            self.message = (
                            'Invalid key. '
                            'Please add valid VirusTotal key in config.json file.\n'
                            )
            return False
        self.API_KEY = self.config['VirusTotalKey']
        self.LOG_ON = self.config['log']['on']
        if self.config['log']['on'] is True:
            if self.config['log']['name'] == '':
                self.LOG_NAME = self.default_log_name.format(get_str_timestamp())
            else:
                self.LOG_NAME = self.config['log']['name']
        self.LOG_REWRITE = self.config['log']['rewrite']
        self.VERBOSE = self.config['verbose']

        return True
