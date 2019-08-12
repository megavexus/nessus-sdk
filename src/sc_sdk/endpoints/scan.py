from enum import Enum
from recurrent import RecurringEvent
from datetime import datetime
from sc_sdk.api import SCApi
from sc_sdk.exceptions import WrongParametersException

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


    def details(self, scan_id):
        scan_details = self.api.scan_instances.details(scan_id)
        return scan_details


    def results(self, scan_id, *filters, **kwargs):
        """
        Get the details of a scan
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
        
        scan_details = self.details(scan_id)
        scan_results = self.results(scan_id, filters=filters)
        scan_details['vulnerabilities'] = scan_results
        return scan_details


    def status(self, scan_id):
        scan_info = self.details(scan_id)
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
        self._check_kwargs(allowed_keys, **kwargs)

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
            'name','policy','plugin','reports','repo','rollover',
            'scan_zone','schedule','targets','timeout','vhosts'
        ]
        self._check_kwargs(allowed_keys, **kwargs)

        scan = self.api.scans.edit(scan_id, **kwargs)
        return scan


    def _check_kwargs(self, allowed_keys, **kwargs):
        invalid_args = []
        for key in kwargs.keys():
            if not key in allowed_keys:
                invalid_args.append(key)
        
        if len(invalid_args) > 0: 
            raise WrongParametersException(invalid_args)

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

    ### TODO:
    def run(self):
        pass

    def pause(self):
        pass

    def stop(self):
        pass