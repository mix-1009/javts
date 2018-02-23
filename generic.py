import re
import hashlib
import datetime


valid_hash = re.compile('([a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64})$')
re_hash_file = re.compile(
    '([a-fA-F\d]{32}|[a-fA-F\d]{40}|[a-fA-F\d]{64})(?:\s|,|$)'
    )


def is_valid_hash(file_hash):
    return valid_hash.match(file_hash) is not None


def file_sha1sum(fname):
    hash_sha1 = hashlib.sha1()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()


def seconds_to_h_m_s(seconds):
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return [int(h), int(m), int(s)]


def get_str_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")


def get_estimated_time(data_len, req_limit, time_interval):
    estimated_time_s = 4  # Emperical value
    estimated_time = [0, 0, estimated_time_s]

    if data_len > req_limit:
        estimated_time_s = (data_len
                            / req_limit
                            * time_interval)
        estimated_time = seconds_to_h_m_s(estimated_time_s)
    
    completion_time = (datetime.datetime.now()
         + datetime.timedelta(seconds=estimated_time_s))
    
    return estimated_time, completion_time


def provide_estimated_time(info_str):
        estimated_time, t = get_estimated_time(
            len(data), VirusTotal.REQUEST_LIMIT, VirusTotal.TIME_INTERVAL)

        print('{0} {0}'.format(len(data, info_str)))
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