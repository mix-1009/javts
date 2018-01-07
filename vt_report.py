from heapq import heappush, heappop


class VTReport:

    def __init__(self, data):
        self.clear_reports = []
        self.positive_reports = []
        self.empty_reports = []
        self.bad_requests = []
        heap = []

        for record in data:
            report = record.request_result
            if report['response_code'] == 1:
                if report['positives'] == 0:
                    self.clear_reports.append(record)
                else:
                    heappush(heap, record)
            elif report['response_code'] == 0:
                self.empty_reports.append(record)
            else:
                self.bad_requests.append(record)

        while heap:
            self.positive_reports.insert(0, heappop(heap))

    def get_positive_reports(self):
        return self.positive_reports

    def get_clear_reports(self):
        return self.clear_reports

    def get_empty_reports(self):
        return self.empty_reports

    def get_bad_requests(self):
        return self.bad_requests
