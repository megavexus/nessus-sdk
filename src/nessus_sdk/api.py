# -*- coding: utf-8 -*-

from .nessrest import NessusScanner
from .exceptions import *
from copy import deepcopy
from operator import itemgetter

class Scanner(object):

    def __init__(self, url, login='', password='', api_akey='', api_skey='', insecure=False, bypass_proxy=False):
        self.scan_api = NessusScanner(
            url=url, 
            login=login, 
            password=password, 
            api_akey=api_akey,
            api_skey=api_skey, 
            insecure=insecure, 
            bypass_proxy=bypass_proxy
        )

    def scan_list(self):
        return self.scan_api.scan_list()

    def search_scan_id(self, scan_name):
        scan_exists = self.scan_api.scan_exists(scan_name)
        return self.scan_api.scan_id if scan_exists else None


    def update_targets(self, scan_id, targets):
        self.scan_api.scan_id = scan_id
        self.scan_api.scan_update_targets(targets)
        return scan_id


    def scan_create_from_name(self,  scan_name, targets, policy_name, folder_name, description=""):
        scan_id = self.search_scan_id(scan_name)
        if scan_id == None:
            self._set_scan_metadata(policy_name, folder_name, description)
            self.scan_api.scan_add(targets, name=scan_name)
            return self.scan_api.scan_id
        else:
            return self.scan_create(scan_id, targets, policy_name, folder_name, description)

    def scan_create(self, scan_id, targets, policy_name, folder_name, description=""):
        """
        Crea un scan con las opciones de policy indicadas.
        Si se policy_options policy_name, lo cogerá si existe.
        """
        self._set_scan_metadata(policy_name, folder_name, description)
        return self.update_targets(scan_id, targets)

    def _set_scan_metadata(self, policy_name, folder_name, description):
        self.scan_api._scan_tag(folder_name)
        if description != "":
            self.scan_api.description = description
        policy_exists = self.scan_api.policy_exists(policy_name)
        if policy_exists == False:
            raise KeyError("The policy {} doesnt exists".format(policy_name))


    def scan_delete(self, scan_id):
        """
        Start the scan and save the UUID to query the status
        """
        self.scan_api.action(action="scans/{}".format(scan_id) , method="DELETE")
        if 'error' in self.scan_api.res:
            return self.scan_api.res
        else:
            return True

    
    def scan_run(self, scan_id, custom_targets="", wait_to_finish=False):
        """
        Start the scan and save the UUID to query the status
        """
        custom_targets = []
        if len(custom_targets) > 0:
            custom_targets = custom_targets.split(',')

        self.scan_api.action(action="scans/{}/launch".format(scan_id), method="POST", extra=custom_targets)
        scan_info = self.scan_inspect(scan_id = scan_id)

        if wait_to_finish:
            self.scan_api._scan_status()

        return scan_info['info']["uuid"]


    def scan_stop(self, scan_id):
        '''
        Stop the scan and save the UUID to query the status
        '''
        self.scan_api.action(action="scans/{}/stop".format(scan_id), method="POST")
        scan_info = self.scan_inspect(scan_id)
        return scan_info['info']["uuid"]
        

    def scan_pause(self, scan_id):
        '''
        Start the scan and save the UUID to query the status
        '''
        self.scan_api.action(action="scans/{}/pause".format(scan_id), method="POST")
        scan_info = self.scan_inspect(scan_id)
        return scan_info['info']["uuid"]


    def scan_list_from_folder(self, folder_id):
        '''
        Fetch a list with scans from a specified folder
        '''
        self.scan_api.scan_list()
        scans = self.scan_api.res['scans']

        results = []
        for scan in scans:
            if str(scan['folder_id']) == str(folder_id):
                results.append(scan)

        return results

    def scan_inspect(self, scan_id=None, scan_name=None, scan_uuid=None):
        """
        Fetch the details of the requested scan
        """
        if scan_id != None:
            details_uri = "scans/{}".format(scan_id)
            self.scan_api.action(action=details_uri, method="GET")
            if scan_uuid != None:
                history_id = None
                for historic_data in self.scan_api.res['history']:
                    if scan_uuid == historic_data["uuid"]:
                        history_id = historic_data["history_id"]
                        self.scan_api.action(action=details_uri+"?history_id={}".format(history_id), method="GET")
                        if self.scan_api.res['info']['uuid'] != scan_uuid:
                            raise ValueError("{} != {}".format(
                                scan_uuid, self.scan_api.res['info']['uuid']))
                        break
                else:
                    raise ScanNotFoundException("UUID {} doesnt exists in the scan {}".format(
                        scan_uuid, scan_id
                    ))
        elif scan_name != None:
            self.scan_api.scan_details(scan_name)
        else: 
            return None

        if 'error' in self.scan_api.res:
            raise KeyError(self.scan_api.res['error'])

        return self.scan_api.res

    def _get_history_id(self, scan_id, scan_uuid):
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
    
    def scan_status(self, scan_id=None, scan_name=None):
        scan_info = self.scan_inspect(scan_id, scan_name)
        return scan_info['info']['status']


    def get_results(self, scan_id, scan_uuid=None):
        self.scan_id = scan_id
        self.scan_inspect(self.scan_id, scan_uuid=scan_uuid)

        if self.scan_api.res['info']['status'] != "completed":
            return None
        results = self._extract_scan_results(scan_id)
        return results

    def _extract_scan_results(self, scan_id):

        history_id = self._get_history_id(
            scan_id, self.scan_api.res['info']['uuid'])
        history_id_params = "?history_id={}".format(history_id)
        #self.scan_api._scan_status() # No esperamos a que termine
        results = {
            "scan_id": self.scan_api.res["info"]["object_id"],
            "scan_uuid": self.scan_api.res["info"]["uuid"],
            "scan_name": self.scan_api.res["info"]["name"],
            "scan_start": self.scan_api.res["info"]["scan_start"],
            "scan_end": self.scan_api.res["info"]["scan_end"],
            "scan_policy": self.scan_api.res["info"]["policy"],
            "hosts":{}
        }
        
        for host in self.scan_api.res["hosts"]:
            host_dict = {
                'target': host["hostname"],
                'compliance': [],
                'vulnerabilities': []
            }
            self.scan_api.action("scans/{}/hosts/{}{}".format(
                scan_id, host["host_id"], history_id_params), 
                method="GET")
            
            # Get host info
            host_dict['os'] = self.scan_api.res['info']['operating-system']
            res_host_info = deepcopy(self.scan_api.res)
            for vulnerability in res_host_info['vulnerabilities']:
                plugin_id = vulnerability['plugin_id']
                vuln_index = vulnerability['vuln_index']

                self.scan_api.action("scans/{}/hosts/{}/plugins/{}{}".format(scan_id, host["host_id"], plugin_id, history_id_params), method="GET")
                
                vuln_data = self._extract_vulnerability_data(self.scan_api.res, host["hostname"])
                host_dict['vulnerabilities'].append(deepcopy(vuln_data))

            for compliance in res_host_info['compliance']:
                # TODO: Hacer
                pass

            results['hosts'][host["hostname"]] = deepcopy(host_dict)

        return results

    def _extract_vulnerability_data(self, vuln_information, hostname):
        vuln_data = {}

        port_data = ""
        ports = []
        protocols = []
        server_protocols = []

        for output in vuln_information['outputs']:
            for ports_value, ports_info in output['ports'].items():
                for hosts_portinfo in ports_info:
                    if hosts_portinfo['hostname'] == hostname:
                        port_data = ports_value.split(" / ")
                        ports.append(port_data[0])
                        protocols.append(port_data[1])
                        server_protocols.append(port_data[2])
                        plugin_output = output["plugin_output"]
                        break

        plugin_description = vuln_information['info']["plugindescription"] 
        plugin_attributes = plugin_description['pluginattributes'] 
        vuln_info = plugin_attributes.get('vuln_information', {})
        ref_information = plugin_attributes.get('ref_information', {}).get('ref', {})
        cve = ""
        for ref in ref_information:
            if ref['name'] == "cve":
                cve = ",".join(ref['values']['value'])

        vuln_data = {
            "plugin_id": plugin_description["pluginid"],
            "plugin_name": plugin_attributes["fname"],
            "plugin_fname": plugin_description['pluginname'],
            "plugin_family": plugin_description["pluginfamily"],
            "severity": plugin_description['severity'],
            "risk_factor": plugin_attributes['risk_information']["risk_factor"],
            "plugin_version": plugin_attributes['plugin_information']["plugin_version"],
            "synopsis": plugin_attributes.get("synopsis", ""),
            "description": plugin_attributes['description'],
            "see_also": plugin_attributes.get('see_also',""),
            "solution": plugin_attributes['solution'],
            "plugin_output": plugin_output,
            "ports": ports,
            "protocols": protocols,
            "server_protocol": server_protocols,
            #
            "cwe": plugin_attributes.get('cwe', ""),
            "iavb": plugin_attributes.get('iavb', ""),
            "edb-id": plugin_attributes.get('edb-id', ""),
            "cve": cve,
            #
            "cvss_vector": plugin_attributes['risk_information'].get("cvss_vector", ""),
            "cvss_temporal_vector": plugin_attributes['risk_information'].get("cvss_temporal_vector", ""),
            "cvss_temporal_score": plugin_attributes['risk_information'].get("cvss_temporal_score", ""),
            "cvss_base_score": plugin_attributes['risk_information'].get("cvss_base_score", ""),
            #
            "exploitability_ease": vuln_info.get("exploitability_ease", ""),
            "cpe": vuln_info.get("cpe", ""),
            "exploit_available": vuln_info.get("exploitability_ease", "") in ["Exploits are available"],
            "vuln_publication_date": vuln_info.get("vuln_publication_date", ""),
            "patch_publication_date": vuln_info.get("patch_publication_date", "")
        }
        
        return vuln_data

    def get_results_event(self, scan_id, scan_uuid=None):
        results = self.get_results(scan_id, scan_uuid)
        data_events = []

        for host, host_data in results['hosts']:
            event_host_base = {
                'scan_id': results['scan_id'],
                'scan_uuid': results['scan_uuid'],
                'scan_name': results['scan_name'],
                'scan_start': results['scan_start'],
                'scan_end': results['scan_end'],
                'scan_policy': results['scan_policy'],
                'target': host,
            }
            if len(host_data['vulnerabilities']):
                for vulns in host_data['vulnerabilities']:
                    ports = vulns.pop('ports',[])
                    protocols = vulns.pop('protocols', [])
                    server_protocols = vulns.pop('server_protocols', [])
                    data_vuln = event_host_base + vulns
                    for i in range(0,len(ports)):
                        data_vuln_event = deepcopy(data_vuln)
                        data_vuln_event['port'] = ports[i]
                        data_vuln_event['protocols'] = protocols[i]
                        data_vuln_event['server_protocols'] = server_protocols[i]
                        data_events.append(data_vuln)
            else:
                data_events.append(event_host_base)

        return data_events

    def get_results_string(self, scan_id, uuid=None):
        results = self.get_results_event(scan_id, uuid)
        string_results = []
        for result in results:
            string_results.append(
                ", ".join([self._event_to_string(key,value) for key, value in result.items()])
            )
        return string_results


    def _event_to_string(self, key, value):
        if type(value) in [int, float]:
                return '{}={}'.format(key, value)
        elif type(value) in [str, bytes]:
            try:
                return "{}={}".format(key, int(value))
            except ValueError:
                return '{}="{}"'.format(key, value)
            

    def get_diff(self, scan_id, scan_uuid_orig=None, scan_uuid_target=None):
        """
        Compara el ultimo scaneo con el penultimo, y devuelve los resultados.
        Si se ha indicado scan_uuid_orig y scan_uuid_target, usará esos dos para compararlos
        """
        if scan_uuid_orig != None and scan_uuid_target == None:
            raise Exception("If you select the orig, you must give the target uuid")

        scan_history = self._get_scan_history(scan_id)
        
        if scan_uuid_orig == None:
            # Obtiene los uuid de origen y target
            scan_history_id_orig = scan_history[0]['history_id']
            scan_history_id_target = scan_history[1]['history_id']
        else:
            scan_history_id_orig = [scanner["history_id"] for scanner in scan_history if scanner['uuid'] == scan_uuid_orig][0]
            scan_history_id_target = [scanner["history_id"] for scanner in scan_history if scanner['uuid'] == scan_uuid_target][0]

        # obtiene el diff: 
        diff_uri = "scans/{}/diff?history_id_id={}".format(scan_id, scan_history_id_target)
        self.scan_api.action(action=diff_uri, method="POST", extra={
                             'diff_id': scan_history_id_orig})

        # Coge los resultados
        diff_uri = "scans/{}?diff_id={}&history_id={}".format(scan_id, scan_history_id_orig, scan_history_id_target)
        raise Exception(self.scan_api.res)
        results = self._extract_scan_results(scan_id)
        return results
        

    def _get_scan_history(self, scan_id):
        details_uri = "scans/{}".format(scan_id)
        self.scan_api.action(action=details_uri, method="GET")
        history = []
        for historic_data in self.scan_api.res['history']:
            if historic_data['alt_targets_used'] != False:
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
        """
        TODO:
        Returns a list with the scanners running right now
        """
        pass
