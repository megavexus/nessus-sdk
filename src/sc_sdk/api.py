# -*- coding: utf-8 -*-

from .screst import SCScanner
from .exceptions import *
from copy import deepcopy
import time
import logging
import os
import requests
from operator import itemgetter
from enum import Enum

class ScanStatus(Enum):
    # TODO: Completar
    COMPLETED = 'Completed'
    CANCELED = 'Canceled'
    STOPPED = 'Stopped'
    RUNNING = 'Running'
    ERROR = 'Error'

class Scanner(object):

    def __init__(self, host, username='', password='', unsecure=False, scheme="https", port=443, http_proxy=None):
        if scheme == "http" and port == 443:
            port = 80

        session = requests.Session()
        if os.environ.get('http_proxy') not in ["", None]:
            http_proxy = os.environ.get('http_proxy')
        if http_proxy:
            proxies = {
                'http': http_proxy,
                'https': http_proxy,
            }    
            session.proxies = proxies

        self.scan_api = SCScanner(
            host=host, 
            scheme=scheme,
            ssl_verify=unsecure == False,
            session = session,
        )
        self._init_logger()
        self.scan_api.login(username, password)
            
    def _init_logger(self):
        self.logger = logging.getLogger('sc_api')
        if not len(self.logger.handlers):
            logger_handler = logging.StreamHandler()
            logger_handler.setLevel(logging.DEBUG)

            logger_format_style = "%(asctime)s (%(name)s) [%(levelname)s]: %(message)s"
            logger_formatter = logging.Formatter(logger_format_style)
            logger_handler.setFormatter(logger_formatter)

            self.logger.addHandler(logger_handler)

    ## SCANS
    def list_scan_results(self, fields=None, name=None, status:ScanStatus=None, start_time=None, end_time=None):
        """
        Return a list of the scanners filtered by the fields parameters
        """
        scanners_results = self.scan_api.scans.scan_instances.list(fields, start_time, end_time)
        scanners_results = scanners_results['manageable']
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


    def get_scan_details(self, scan_id):
        """
        Get the details of a scan
        """
        scan_details = self.scan_api.scan_instances.details(scan_id)
        return scan_details


    def scan_inspect(self, scan_id=None, scan_name=None, tool="vulndetails"):
        """
        Fetch the details of the requested scan
        """
        
        if scan_name and not scan_id:
            scans = self.list_scan_results(name=scan_name)
            if len(scans) > 1:
                last_scan_id = scans[0]['id']
                for scan in scans[1:]:
                    if int(last_scan_id) < int(scan['id']):
                        last_scan_id = scan['id']
                scan_id = last_scan_id
        elif scan_id == None:
            raise ValueError("Not id or name provided")
        
        scan_details = self.get_scan_details(scan_id)
        scan_results = self.get_scan_results(scan_id, tool=tool)
        scan_details['vulnerabilities'] = scan_results
        return scan_details

    

    def scan_status(self, scan_id):
        scan_info = self.get_scan_details(scan_id)
        return scan_info['status']
        
    ##################
    ### RESULTADOS ###
    ##################

    def get_scan_results(self, scan_id, *filters, **kw):
        """
        Get the details of a scan
        Args:
            filters: The filters will be in the form of tuples, for example:
                - self.get_scan_results(scan_id=10, filters = [("severity", "=", "4), )=])
            kw: The parameters of the api. For more information: 
                https://github.com/tenable/pyTenable/blob/6eb7ea3b12022f5093c30051a21400fbfb60f8e9/tenable/sc/analysis.py#L212
            
        """
        vulns = []
        scan_results = self.scan_api.analysis.vulns(*filters, scan_id=scan_id, **kw)
        for vuln in scan_results:
            vulns.append(vuln)
        return vulns

    def get_results(self, scan_id):
        # TODO: Adaptar al SC
        status = self.scan_status(scan_id)

        if status != ScanStatus.COMPLETED.value:
            return None
        
        results = self._extract_scan_results(scan_id)
        return results


    def _extract_scan_results(self, scan_id, diff_id=None):
        #history_id_params = "?history_id={}".format(history_id)   
        #if diff_id:
        #    history_id_params = history_id_params + "&diff_id={}".format(diff_id)
        #self.scan_api._scan_status() # No esperamos a que termine
        scan_info = self.scan_inspect(scan_id)
        results = {
            "scan_id": scan_id,
            "scan_uuid": scan_info.get("uuid"),
            "scan_name": scan_info["name"],
            "scan_start": scan_info["startTime"],
            "scan_end": scan_info["finishTime"],
            "scan_policy": scan_info.get("details", ""),
            "hosts":{}
        }

        results['hosts'] = {}
        for vuln in scan_info["vulnerabilities"]:
            vuln_data = self._extract_vulnerability_data(vuln)
            
            hostname = vuln["ip"]
            if hostname not in results['hosts']:
                host_dict = {
                    'target': hostname,
                    'dnsname': vuln.get('dnsName'),
                    'compliance': [],
                    'vulnerabilities': []
                }

                    # TODO: Get host info
                    #host_dict['os'] = self.scan_api.res['info'].get('operating-system')
                    #res_host_info = deepcopy(self.scan_api.res)
                results['hosts'][hostname] = host_dict
            
            results['hosts'][hostname]['vulnerabilities'].append(vuln_data)      
            
            #for compliance in res_host_info['compliance']:
                # TODO: Hacer cuando tengamos muestras con credenciales
                #pass

        return results

    def _extract_vulnerability_data(self, vuln_information):
        # TODO: Adaptar al SC

        vuln_data = {}

        port_data = ""
        occurences = []
        ports = []
        """
        for output in vuln_information['outputs']:
            for ports_value, ports_info in output['ports'].items():
                for hosts_portinfo in ports_info:
                    if hosts_portinfo['hostname'] == hostname:
                        
                        port_data = ports_value.split(" / ")
                        ports.append(port_data[0])
                        occurences.append({
                            "port":port_data[0],
                            "protocol":port_data[1],
                            "server_protocol":port_data[2],
                            "plugin_output": output["plugin_output"]
                        })
                        break
        """
        occurences.append(
            {
                "port":[vuln_information['port']],
                "protocol":vuln_information['protocol'].lower(),
                "server_protocol":"-",
                "plugin_output":vuln_information['pluginText'],
            }
        )
        ports = [vuln_information['port']]

        plugin_synopsis = vuln_information['synopsis'] 
        plugin_description = vuln_information['description'] 
        plugin_solution = vuln_information['solution'] 
        plugin_output = vuln_information['pluginText']
        cve = vuln_information['cve']
        cvss_vector = vuln_information['cvssV3Vector']
        if cvss_vector == "":
            cvss_vector = vuln_information['cvssVector']

        vuln_data = {
            "plugin_id": vuln_information["pluginID"],
            "plugin_name": vuln_information["pluginName"],
            "plugin_fname": vuln_information['family']['name'],
            "plugin_family": vuln_information['family']['id'],
            "severity": vuln_information['severity']['id'],
            "risk_factor": vuln_information['riskFactor'],
            "plugin_version": vuln_information["version"],
            "synopsis": plugin_synopsis,
            "description": plugin_description,
            "see_also": vuln_information['seeAlso'],
            "solution": plugin_solution,
            "occurences": occurences,
            "ports": ports,
            #
            # TODO: ESTOS!! SACAR DE XREF
            "cwe": "",
            "iavb": "",
            "edb-id": "",
            "cve": cve,
            #
            "cvss_vector": cvss_vector,
            "cvss_temporal_vector": "",
            "cvss_temporal_score": vuln_information['temporalScore'],
            "cvss_base_score": vuln_information['baseScore'],
            #
            "exploitability_ease": vuln_information.get("exploitEase", ""),
            "cpe": vuln_information.get("cpe", ""),
            "exploit_available": vuln_information.get("exploitAvailable", "") in ["Exploits are available"],
            "vuln_publication_date": vuln_information.get("vulnPubDate", ""),
            "patch_publication_date": vuln_information.get("patchPubDate", "")
        }
        
        return vuln_data

    def get_results_events(self, scan_id):
        # TODO: Adaptar al SC
        results = self.get_results(scan_id)
        return self.parse_report_to_events(results)

    def parse_report_to_events(self, results):
        data_events = []
        for host, host_data in results['hosts'].items():
            event_host_base = {
                'scan_id': results['scan_id'],
                'scan_uuid': results.get('scan_uuid'),
                'scan_name': results['scan_name'],
                'scan_start': results['scan_start'],
                'scan_end': results['scan_end'],
                'scan_policy': results['scan_policy'],
                'os': host_data.get('os'),
                'target': host,
            }
            if len(host_data['vulnerabilities']):
                for vulns in host_data['vulnerabilities']:
                    vulns.update(event_host_base)
                    occurrences = vulns.pop('occurences')
                    # Quitamos ports ya que la información la da occurences
                    vulns.pop('ports')
                    for occurrence in occurrences:
                        data_vuln_event = deepcopy(vulns)
                        data_vuln_event['port'] = occurrence['port']
                        data_vuln_event['protocol'] = occurrence['protocol']
                        data_vuln_event['server_protocol'] = occurrence['server_protocol']
                        data_vuln_event['plugin_output'] = occurrence['plugin_output']
                        data_events.append(data_vuln_event)
            else:
                data_events.append(event_host_base)

        return data_events

    def parse_events_to_strings(self, result_events):
        string_results = []
        for result in result_events:
            string_results.append(
                ", ".join([self._key_value_to_string(key, value) for key,value in result.items()])
            )
        return string_results

    def get_results_string(self, scan_id):
        results = self.get_results_events(scan_id)
        string_results = self.parse_events_to_strings(results)
        return string_results


    def _key_value_to_string(self, key, value):
        if type(value) in [int, float]:
                return '{}={}'.format(key, value)
        elif type(value) in [str, bytes]:
            try:
                return "{}={}".format(key, int(value))
            except ValueError:
                return '{}="{}"'.format(key, value.replace("\"", "'"))
        elif type(value) == bool:
            return "{}={}".format(key, value)
        elif type(value) == list:
            return "{}={}".format(key, ",".join(value))
        elif value == None:
            return '{}=""'.format(key)
        else:
            raise Exception(type(value))

    ### TODO: HASTA AQUÍ ###

    ## Program
    def update_targets(self, scan_id, targets):
        # TODO:
        raise NotImplementedError()
        self.scan_api.scan_id = scan_id
        if type(targets) == list:
            targets = ",".join(target.strip() for target in targets)
        self.scan_api.scan_update_targets(targets)
        return scan_id


    def scan_create_from_name(self,  scan_name, targets, policy_name, folder_name, description=""):
        # TODO:
        raise NotImplementedError()
        scan_id = self.search_scan_id(scan_name)

        if type(targets) == list:
            targets = ",".join(target.strip() for target in targets)
            
        if scan_id == None:
            self._set_scan_metadata(policy_name, folder_name, description)
            self.scan_api.scan_add(targets, name=scan_name)
            return self.scan_api.scan_id
        else:
            return self.scan_create(scan_id, targets, policy_name, folder_name, description)

    def scan_create(self, scan_id, targets, policy_name, folder_name, description=""):
        """
        # TODO:
        Crea un scan con las opciones de policy indicadas.
        Si se policy_options policy_name, lo cogerá si existe.
        """
        raise NotImplementedError()
        self._set_scan_metadata(policy_name, folder_name, description)
        return self.update_targets(scan_id, targets)

    def _set_scan_metadata(self, policy_name, folder_name, description):
        # TODO:
        raise NotImplementedError()
        self.scan_api._scan_tag(folder_name)
        if description != "":
            self.scan_api.description = description
        policy_exists = self.scan_api.policy_exists(policy_name)
        if policy_exists == False:
            raise KeyError("The policy {} doesnt exists".format(policy_name))


    def scan_delete(self, scan_id):
        """
        # TODO:
        Start the scan and save the UUID to query the status
        """
        raise NotImplementedError()
        self.scan_api.action(action="scans/{}".format(scan_id) , method="DELETE")
        if 'error' in self.scan_api.res:
            return self.scan_api.res
        else:
            return True

    
    def scan_run(self, scan_id, custom_targets=None, wait_to_finish=False):
        """
        # TODO:
        Start the scan and save the UUID to query the status
        """
        raise NotImplementedError()
        custom_targets = self._get_custom_targets(custom_targets)

        self.scan_api.action(action="scans/{}/launch".format(scan_id), method="POST", extra=custom_targets)
        scan_info = self.scan_inspect(scan_id = scan_id)
        self.logger.info(scan_info['info'])

        if wait_to_finish:
            self._wait_scan_to_finish(scan_id, scan_info['info']["uuid"])
        self.logger.info(scan_info['info'])
        return scan_info['info']["uuid"]

    def _get_custom_targets(self, custom_targets):
        """
        # TODO:
        Admite: host1,host2,host3 o [host1, host2, ...]
        """
        raise NotImplementedError()

        if type(custom_targets) == str and len(custom_targets) > 0:
            custom_targets = custom_targets.split(',')
            return self._get_custom_targets(custom_targets)
        elif type(custom_targets) == list and len(custom_targets) > 0:

            custom_targets = [
                target.strip() 
                for target in set(custom_targets)
                if type(target) == str and len(target) > 0
            ]

            return {"alt_targets":custom_targets} if len(custom_targets) else {}

        else:
            return {}

    def _wait_scan_to_finish(self, scan_id, scan_uuid):
        # TODO:
        raise NotImplementedError()
        running = True
        counter = 0

        while running:
            scan_status = self.scan_status(scan_id, scan_uuid=scan_uuid)
            self.logger.info("- Waiting scan to finish [ID:{}] [UUID:{}]".format(scan_id, scan_uuid))
            if scan_status == "running" or scan_status == "pending":
                time.sleep(2)
                counter += 2
                self.logger.debug(".")
                if counter % 60 == 0:
                    self.logger.debug(" ")
            else:
                self.logger.debug("\t- Status detected: {}".format(scan_status))
                running = False

        self.logger.info("-Complete! Run time: %d seconds." % counter)


    def scan_stop(self, scan_id):
        '''
        Stop the scan instances which are running
        '''
        raise NotImplementedError()
        self.scan_api.action(action="scans/{}/stop".format(scan_id), method="POST")
        scan_info = self.scan_inspect(scan_id)
        return scan_info['info']["uuid"]
        

    def scan_pause(self, scan_id):
        '''
        Pause the scan instances which are running
        '''
        raise NotImplementedError()
        self.scan_api.action(action="scans/{}/pause".format(scan_id), method="POST")
        scan_info = self.scan_inspect(scan_id)
        return scan_info['info']["uuid"]


    def scan_list_from_folder(self, folder_id):
        '''
        # TODO: Deprecado?
        Fetch a list with scans from a specified folder
        '''
        raise NotImplementedError()
        self.scan_api.scan_list()
        scans = self.scan_api.res['scans']

        results = []
        for scan in scans:
            if str(scan['folder_id']) == str(folder_id):
                results.append(scan)

        return results

    def _get_history_id(self, scan_id, scan_uuid):
        raise NotImplementedError()
        history_id = ""
        details_uri = "scans/{}".format(scan_id)
        self.scan_api.action(action=details_uri, method="GET")
        for historic_data in self.scan_api.res['history']:
            if scan_uuid == historic_data["uuid"]:
                history_id = historic_data["history_id"]
                self.scan_api.action(action=details_uri+"?history_id={}".format(history_id), method="GET")
                if self.scan_api.res['info']['uuid'] != scan_uuid:
                    raise ValueError("{} != {}".format(scan_uuid, self.scan_api.res['info']['uuid']))
                break
        return history_id

            
    def get_diff(self, scan_id, scan_uuid_orig=None, scan_uuid_target=None):
        """
        Compara el ultimo scaneo con el penultimo, y devuelve los resultados.
        Si se ha indicado scan_uuid_orig y scan_uuid_target, usará esos dos para compararlos
        """
        # TODO:
        raise NotImplementedError()
        scan_history = self._get_scan_history(scan_id)
        scan_history = [ scan for scan in scan_history if scan['status'] == 'completed' ]
        
        if scan_uuid_orig == None:
            # Obtiene los uuid de origen y target
            scan_history_id_orig = scan_history[0]['history_id']
            scan_history_id_target = scan_history[1]['history_id']
        else:
            scan_history_id_orig = [scanner["history_id"] for scanner in scan_history if scanner['uuid'] == scan_uuid_orig][0]

            if scan_uuid_target:
                scan_history_id_target = [scanner["history_id"] for scanner in scan_history if scanner['uuid'] == scan_uuid_target][0]
            else:
                # Si no hay anterior, coge el inmediatamente anterior al acual
                # Si no lo encuentra, coge el ultimo que haya (primero)
                last_scan = scan_history[0]
                for scanner in scan_history:
                    if last_scan['uuid'] == scan_uuid_orig:
                        last_scan = scanner
                        break

                    last_scan = scanner
                scan_history_id_target = last_scan["history_id"]

        # obtiene el diff: 
        diff_post_uri = "scans/{}/diff?history_id={}".format(scan_id, scan_history_id_target)
        self.scan_api.action(action=diff_post_uri, method="POST", extra={'diff_id': scan_history_id_orig})
        
        # Coge los resultados
        diff_get_results_uri = "scans/{}?diff_id={}&history_id={}".format(scan_id, scan_history_id_orig, scan_history_id_target)
        self.scan_api.action(action=diff_get_results_uri, method="GET")
        results = self._extract_scan_results(scan_id, history_id=scan_history_id_target, diff_id=scan_history_id_orig)
            
        return results
        

    def _get_scan_history(self, scan_id):
        # TODO:
        raise NotImplementedError()
        details_uri = "scans/{}".format(scan_id)
        self.scan_api.action(action=details_uri, method="GET")
        history = []
        for historic_data in self.scan_api.res['history']:
            if historic_data['alt_targets_used'] != False:
                # Descarta los custom
                continue
            history.append({
                'uuid':historic_data['uuid'],
                'creation_date': historic_data['creation_date'],
                'history_id': historic_data['history_id'],
                'status':historic_data['status'],
                'last_modification_date': historic_data['last_modification_date'],
            })
        
        ordered_historial = sorted(history, key=itemgetter('creation_date'), reverse=True)
        return ordered_historial


    def get_running_scanners(self):
        # TODO:
        raise NotImplementedError()
        """
        Returns a list with the scanners currently running
        """
        self.scan_api.action("scans", method="GET")
        all_scans = self.scan_api.res['scans']

        running_scanners = []
        for scan in all_scans:
            if scan['status'] == "running":
                running_scanners.append(scan)

        return running_scanners