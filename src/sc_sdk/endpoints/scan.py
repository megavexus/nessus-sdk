from enum import Enum
from sc_sdk.api import SCApi

class ScanStatus(Enum):
    # TODO: Completar
    COMPLETED = 'Completed'
    CANCELED = 'Canceled'
    STOPPED = 'Stopped'
    RUNNING = 'Running'
    ERROR = 'Error'

class Scan(object):
    def __init__(self, sc_api:SCApi):
        self.api = sc_api
    
    def list_results(self, name=None, **kwargs):
        """
        Return a list of the scanners filtered by the fields parameters
        """
        fields = kwargs.get('fields', ["id","name","status","owner","groups","createdTime","startTime","finishTime"])
        name = kwargs.get('name')
        status = kwargs.get('status')
        start_time = kwargs.get('start_time', 1)
        end_time = kwargs.get('end_time')
        usability = kwargs.get('usability', "usable")

        scanners_results = self.api.scan_instances.list(fields, start_time, end_time)
        scanners_results = scanners_results[usability]
        if name or status:
            filtered_results = []
            for scanner in scanners_results:
                if status and status.value != scanner['status']:
                    continue
                if name and name.lower() not in scanner['name'].lower():
                    continue
                filtered_results.append(scanner)
            scanners_results = filtered_results
        return scanners_results

    def details(self, scan_id):
        scan_details = self.api.scan_instances.details(scan_id)
        return scan_details


    def results(self, scan_id, *filters, **kw):
        """
        Get the details of a scan
        Args:
            filters: The filters will be in the form of tuples, for example:
                - self.get_scan_results(scan_id=10, filters = [("severity", "=", "4), )=])
            kw: The parameters of the api. For more information: 
                https://github.com/tenable/pyTenable/blob/6eb7ea3b12022f5093c30051a21400fbfb60f8e9/tenable/sc/analysis.py#L212
            
        """
        vulns = []
        scan_results = self.api.analysis.vulns(*filters, scan_id=scan_id, **kw)
        for vuln in scan_results:
            vulns.append(vuln)
        return vulns


    def inspect(self, scan_id=None, scan_name=None, filters=None):
        if scan_name and not scan_id:
            scans = self.list_results(name=scan_name)
            if len(scans) > 1:
                last_scan_id = scans[0]['id']
                for scan in scans[1:]:
                    if int(last_scan_id) < int(scan['id']):
                        last_scan_id = scan['id']
                scan_id = last_scan_id
        elif scan_id == None:
            raise ValueError("Not id or name provided")
        
        scan_details = self.details(scan_id)
        scan_results = self.results(scan_id, filters=filters)
        scan_details['vulnerabilities'] = scan_results
        return scan_details


    def status(self, scan_id):
        scan_info = self.details(scan_id)
        return scan_info['status']



    ### TODO:
    def create(self):
        pass

    def delete(self):
        pass

    def update(self):
        pass

    ### TODO:
    def run(self):
        pass

    def pause(self):
        pass

    def stop(self):
        pass