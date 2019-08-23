import time
from copy import deepcopy
from enum import Enum
from recurrent import RecurringEvent
from datetime import datetime
from sc_sdk.api import SCApi
from sc_sdk.exceptions import WrongParametersException

class ScanStatus(Enum):
    COMPLETED = 'Completed'
    CANCELED = 'Canceled'
    STOPPING = 'Stopping'
    PAUSING = 'Pausing'
    STOPPED = 'Stopped'
    PAUSED = "Paused"
    RUNNING = 'Running'
    ERROR = 'Error'
    QUEUED = 'Queued'
    PENDING = 'Pending'
    VERIFYING = 'Verifying targets'
    PREPARING = 'Preparing'
    INITIALIZING = 'Initializing Scanners'

class Scan(object):
    def __init__(self, sc_api:SCApi):
        self.api = sc_api
        self.DEFAULT_LOCALE = "Europe/Madrid"
    
    def list_scans(self, type_scan="manageable", name=None):
        active_scanners = self.api.scans.list()[type_scan]
        if name:
            for scan in active_scanners:
                if scan['name'].lower() == name.lower():
                    return scan
            return []

        return active_scanners

    def list(self, **kwargs):
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


    def get(self, scan_instance_id):
        scan_details = self.api.scan_instances.details(scan_instance_id)
        return scan_details

    def get_scan(self, scan_id):
        """
        Get the details of a Object Scan, not an instance
        """
        scan_details = self.api.scans.details(scan_id)
        return scan_details


    def results(self, scan_id, *filters, **kwargs):
        """
        Get the results of a scan instance
        Args:
            filters: The filters will be in the form of tuples, for example:
                - self.get_scan_results(scan_id=10, filters = [("severity", "=", "4), )=])
            kwargs: The parameters of the api. For more information: 
                https://github.com/tenable/pyTenable/blob/6eb7ea3b12022f5093c30051a21400fbfb60f8e9/tenable/sc/analysis.py#L212
            
        """
        vulns = []
        scan_results = self.api.analysis.vulns(*filters, scan_id=scan_id, **kwargs)
        for vuln in scan_results:
            vulns.append(vuln)
        return vulns

    def parse_report_to_events(self, results, scan_id):
        data_events = []
        host_data = {}
        
        scan_info = self.get(scan_id)

        for plugin_res in results:
            target = plugin_res['ip']

            if target not in host_data:
                device_info = self.api.get("deviceInfo", params={"ip": target}).json()['response']

                target_name = device_info.get("netbiosName", "")
                if len(target_name) == 0:
                    target_name = device_info.get("dnsName", "")

                host_data[target] = {
                    'scan_id': scan_info['id'],
                    'scan_name': scan_info['name'],
                    'scan_start': scan_info['startTime'],
                    'scan_end': scan_info['finishTime'],
                    'scan_policy': "-",
                    'os': device_info["os"],
                    'osCPE': device_info["osCPE"],
                    'target': target,
                    'target_name': target_name,
                }
            
            # AHORA SACAMOS LOS DATOS DE VULN Y LAS OCURRENCIAS
            vuln_data = extract_vulnerability_data(plugin_res)
            vuln_data.update(host_data[target])
            data_events.append(vuln_data)

        #grouper = itemgetter('target', 'scan_id', 'plugin_id')
        #data_events = groupby(sorted(data_events, key = grouper), grouper)

        return data_events


    def results_events(self, scan_id, *filters, **kwargs):
        results = self.results(scan_id, *filters, **kwargs)
        events_results = self.parse_report_to_events(results, scan_id)
        return events_results


    def results_string(self, scan_id, *filters, **kwargs):
        results = self.results_events(scan_id, *filters, **kwargs)
        string_results = self.api.parse_events_to_strings(results)
        return string_results


    def inspect(self, scan_id=None, scan_name=None, filters=None):
        if scan_name and not scan_id:
            scans = self.list(name=scan_name)
            if len(scans) > 1:
                last_scan_id = scans[0]['id']
                for scan in scans[1:]:
                    if int(last_scan_id) < int(scan['id']):
                        last_scan_id = scan['id']
                scan_id = last_scan_id
        elif scan_id == None:
            raise ValueError("Not id or name provided")
        
        scan_details = self.get(scan_id)
        scan_results = self.results(scan_id, filters=filters)
        scan_details['vulnerabilities'] = scan_results
        return scan_details


    def status(self, scan_id):
        scan_info = self.get(scan_id)
        return scan_info['status']


    def create(self, name, repo, policy_id, **kwargs):
        '''
        Creates a scan definition.
        :sc-api:`scan: create <Scan.html#scan_POST>`
        Args:
            name (str): The name of the scan.
            repo (int):
                The repository id for the scan.
            auto_mitigation (int, optional):
                How many days to hold on to data before mitigating it?  The
                default value is 0.
            asset_lists (list, optional):
                A list of asset list ids to run the scan against.  A logical OR
                will be performed to compute what hosts to scan against.
            creds (list, optional):
                A list of credential ids to use for the purposes of this scan.
                This list should be treated as an un-ordered list of credentials.
            description (str, optional): A description for the scan.
            email_complete (bool, optional):
                Should we notify the owner upon completion of the scan?  The
                default is ``False``.
            email_launch (bool, optional):
                Should we notify the owner upon launching the scan?  The default
                is ``False``.
            host_tracking (bool, optional):
                Should DHCP host tracking be enabled?  The default is False.
            max_time (int, optional):
                The maximum amount of time that the scan may run in seconds.
                The default is ``3600`` seconds.
            policy_id (int, optional):
                The policy id to use for a policy-based scan.
            plugin_id (int, optional):
                The plugin id to use for a plugin-based scan.
            reports (list, optional):
                What reports should be run upon completion of the scan?  Each
                report dictionary requires an id for the report definition and
                the source for which to run the report against.  Example:
                ``{'id': 1, 'reportSource': 'individual'}``.
            rollover (str, optional):
                How should rollover scans be created (assuming the scan is
                configured to create a rollover scan with the timeout action).
                The available actions are to automatically start the ``nextDay``
                at the same time the scan was originally configured to run, and
                to generate a rollover ``template``.  The default action is to
                generate a ``template``.
            scan_zone (int, optional):
                The zone identifier to use for the scan.  If non is selected
                then the default of "0" or "All Zones" is selected.
            schedule (dict, optional):
                A dictionary detailing the repeating schedule of the scan.
                For more information refer to `Schedule Dictionaries`_
            targets (list, optional):
                A list of valid targets.  These targets could be IPs, FQDNs,
                CIDRs, or IP ranges.
            timeout (str, optional):
                How should an incomplete scan be handled?  The available actions
                are ``discard``, ``import``, and ``rollover``.  The default
                action is ``import``.
            vhosts (bool, optional):
                Should virtual host logic be enabled for the scan?  The default
                is ``False``.
        '''
        allowed_keys = [
            "name","repo","auto_mitigation","asset_lists","creds",
            "description","email_complete","email_launch","host_tracking",
            "max_time","policy_id","plugin_id","reports","rollover",
            "scan_zone","schedule","targets","timeout","vhosts"
        ]
        self.api._check_kwargs(allowed_keys, **kwargs)

        if "targets" in kwargs and type(kwargs['targets']) == str:
            kwargs['targets'] = kwargs['targets'].split(',')
        scan = self.api.scans.create(name, repo, policy_id=policy_id, **kwargs)
        return scan

    def delete(self, scan_id):
        ids = self.api.scans.delete(scan_id)
        return ids

    def update(self, scan_id, **kwargs):
        allowed_keys = [
            'id','auto_migration','asset_lists','creds','description',
            'email_complete','email_launch','host_tracking','max_time',
            'name','policy','policy_id','plugin','reports','repo','rollover',
            'scan_zone','schedule','targets','timeout','vhosts'
        ]
        self.api._check_kwargs(allowed_keys, **kwargs)

        scan = self.api.scans.edit(scan_id, **kwargs)
        return scan

    def _traduct_scheduling(self, start_time:int=None, recurrence_string:str=None, locale=None):
        """
        Transform the parameters of an scheduling format in the SC format. The format is:
        Input:
            - start_time: a datetime structure with the scanning start date
            - recurrence_string: A string describing the recurrence. 
            for examples: https://github.com/kvh/recurrent
        Output: A dictionary with:
            - type: (never|ical). 
            - start: time in form ical (https://tools.ietf.org/html/rfc5545#section-3.3.5)
            - rrule: Recurrence rule in format iCal (https://tools.ietf.org/html/rfc5545#section-3.3.10)
        For more info: https://pytenable.readthedocs.io/en/latest/sc.html#schedule-dictionaries
        """
        schedule_dict = {"type":"ical"}
        if start_time:
            schedule_dict['start'] = self._get_ical_time(start_time, locale)

        if recurrence_string:
            rrule = self._get_ical_rrule(recurrence_string)
            if rrule:
                schedule_dict['repeatRule'] = rrule

        if not 'start' in schedule_dict and not "repeatRule" in schedule_dict:
            return {"type":"never"}

        return schedule_dict

        
    def _get_ical_time(self, epoch_time:int, locale=None):
        if not locale:
            locale = self.DEFAULT_LOCALE

        datetime_time = datetime.fromtimestamp(epoch_time)
        date = "{}{:>02d}{:>02d}".format(datetime_time.year, datetime_time.month, datetime_time.day) 
        time = "{}{:>02d}{:>02d}".format(datetime_time.hour, datetime_time.minute, datetime_time.second) 
        ical_datetime = "TZID={}:{}T{}".format(locale, date, time)
        return ical_datetime

    def _get_ical_rrule(self, recurrence_string):
        r = RecurringEvent()
        r.parse(recurrence_string)
        rrules = r.get_RFC_rrule()
        rrules = rrules.split('\n')
        for rule in rrules:
            print(rule[:6])
            if rule[:6] == 'RRULE:' :
                return rule[6:]

    def run(self, scan_id, wait=False, wait_to_finish=False):
        running_scan = self.api.scans.launch(scan_id)
        scan_instance = running_scan['scanResult']
        scan_result = running_scan['scanResult']
        if wait:
            self._wait_scan_until_status(scan_instance['id'], ScanStatus.RUNNING.value)
            scan_result = self.get(scan_instance['id'])
        if wait_to_finish:
            self._wait_scan_until_status(scan_instance['id'], [ScanStatus.COMPLETED.value, ScanStatus.PAUSED.value, ScanStatus.ERROR.value])
            scan_result = self.get(scan_instance['id'])
        return scan_result
 

    def stop(self, scan_instance_id, wait=False):
        # Esto se mete para evitar bug de escaneo cuando se para estando encolado.
        scan_data = self.get(scan_instance_id)
        print("PRESTOP STATUS: {}".format(scan_data['status']))
        if scan_data['status'] in [ScanStatus.PENDING.value, ScanStatus.QUEUED.value]:
            self._wait_scan_until_status(scan_instance_id, ScanStatus.RUNNING.value)

        scan_data = self.get(scan_instance_id)
        print("STOP STATUS: {}".format(scan_data['status']))
        stopped_scan = self.api.scan_instances.stop(scan_instance_id)
        if wait:
            self._wait_scan_until_status(stopped_scan['id'], ScanStatus.STOPPING.value)
            scan_result = self.get(stopped_scan['id'])
            return scan_result
        return stopped_scan


    def pause(self, scan_instance_id, wait=False):
        paused_scan = self.api.scan_instances.pause(scan_instance_id)
        if wait:
            self._wait_scan_until_status(paused_scan['id'], ScanStatus.PAUSED.value)
            scan_result = self.get(paused_scan['id'])
            return scan_result
        return paused_scan


    def resume(self, scan_instance_id, wait=False):
        scan_data = self.get(scan_instance_id)
        print("RESUME STATUS: {}".format(scan_data['status']))
        if scan_data['status'] != "Paused":
            self._wait_scan_until_status(scan_instance_id, ScanStatus.PAUSED.value)

        resumed_scan = self.api.scan_instances.resume(scan_instance_id)
        if wait:
            self._wait_scan_until_status(resumed_scan['id'], ScanStatus.RUNNING.value)
            scan_result = self.get(resumed_scan['id'])
            return scan_result

        return resumed_scan

    def _wait_scan_until_status(self, id_scan_instance, status, timeout=150):
        details = self.get(id_scan_instance)
        scan_status = details['status']
        if type(status) != list:
            status = [status]

        current_time_step = 0
        time_steps = 2

        while (scan_status in status) == False:
            if current_time_step >= timeout:
                raise TimeoutError("Status: {}".format(scan_status))

            time.sleep(time_steps)
            current_time_step += time_steps

            details = self.get(id_scan_instance)
            scan_status = details['status']
            self.api.logger.info("[{}s]: Status = {}".format(current_time_step, scan_status))

        return scan_status in status
    

def extract_vulnerability_data(vuln_information):
    plugin_output = vuln_information.get("pluginText","")\
        .replace("<plugin_output>","")\
        .replace("<\\plugin_output>","")
    vuln_data = {
        "plugin_id": vuln_information["pluginID"],
        "plugin_name": vuln_information["pluginName"],
        "plugin_fname": vuln_information['family']['name'],
        "plugin_family": vuln_information["family"]['id'],
        "severity": vuln_information['severity']['id'],
        "risk_factor": vuln_information["riskFactor"],
        "plugin_version": vuln_information["version"],
        "synopsis": vuln_information.get("synopsis", ""),
        "description": vuln_information['description'],
        "see_also": vuln_information.get('see_also',""),
        "solution": vuln_information.get('solution',""),
        "port": vuln_information['port'],
        "protocol": vuln_information['protocol'].lower(),
        "plugin_output": plugin_output,
        #
        #"cwe": plugin_attributes.get('cwe', ""),
        #"iavb": plugin_attributes.get('iavb', ""),
        #"edb-id": plugin_attributes.get('edb-id', ""),
        "cve": vuln_information['cve'],
        #
        "cvss_vector": vuln_information.get("cvssVector", ""),
        "cvssv3_vector": vuln_information.get("cvssV3Vector", ""),
        "cvssv3_temporal_score": vuln_information.get("cvssV3TemporalScore", ""),
        "cvssv3_base_score": vuln_information.get("cvssV3BaseScore", ""),
        #
        "cpe": vuln_information.get("cpe", ""),
        "exploitability_ease": vuln_information.get("exploitEase", ""),
        "exploit_available": vuln_information.get("exploitAvailable", ""),
        "exploit_frameworks": vuln_information.get("exploitFrameworks", ""),
        "vuln_publication_date": vuln_information.get("vulnPubDate", ""),
        "patch_publication_date": vuln_information.get("patchPubDate", "")
    }
    
    return vuln_data