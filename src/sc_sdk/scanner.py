from sc_sdk.security_center import SecurityCenter
from sc_sdk.endpoints.scan import ScanStatus

class Scanner(object):
    """
    Esta clase es una encapsulación para comptabilizar el uso de la api del SC 
    con la de Nessus Pro, pero está deprecada y debería ir entrando en desuso
    """

    def __init__(self, host, username='', password='', unsecure=False, scheme="https", port=443, http_proxy=None):
        self.security_center = SecurityCenter(host, username, password, unsecure, scheme, port, http_proxy)
        

    ## SCANS
    def list_scan_results(self, fields=None, name=None, status:ScanStatus=None, start_time=None, end_time=None):
        """
        Return a list of the scanners filtered by the fields parameters
        """
        return self.security_center.scans.list(fields=fields, name=name, status=status, start_time=start_time, end_time=end_time)


    def get_scan_details(self, scan_id):
        """
        Get the details of a scan
        """
        return self.security_center.scans.details(scan_id)


    def scan_inspect(self, scan_id=None, scan_name=None):
        """
        Fetch the details of the requested scan
        """
        
        return self.security_center.scans.inspect(scan_id)

    

    def scan_status(self, scan_id):
        scan_info = self.get_scan_details(scan_id)
        return scan_info['info']['status']
        
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
        return self.security_center.scans.results(scan_id, *filters, **kw)


    def get_results(self, scan_id):
        raise NotImplementedError()
        # TODO: Adaptar al SC
        self.scan_id = scan_id
        self.scan_inspect(self.scan_id)

        if self.scan_api.res['info']['status'] != "completed":
            return None
        
        history_id = self._get_history_id(scan_id, self.scan_api.res['info']['uuid'])
        results = self._extract_scan_results(scan_id, history_id)
        return results


    def _extract_scan_results(self, scan_id, history_id, diff_id=None):
        # TODO: Adaptar al SC
        history_id_params = "?history_id={}".format(history_id)   
        if diff_id:
            history_id_params = history_id_params + "&diff_id={}".format(diff_id)
        #self.scan_api._scan_status() # No esperamos a que termine
        results = {
            "scan_id": self.scan_api.res["info"]["object_id"],
            "scan_uuid": self.scan_api.res["info"]["uuid"],
            "scan_name": self.scan_api.res["info"]["name"],
            "scan_start": self.scan_api.res["info"]["scan_start"],
            "scan_end": self.scan_api.res["info"]["scan_end"],
            "scan_policy": self.scan_api.res["info"].get("policy", ""),
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
            host_dict['os'] = self.scan_api.res['info'].get('operating-system')
            res_host_info = deepcopy(self.scan_api.res)
            for vulnerability in res_host_info['vulnerabilities']:
                plugin_id = vulnerability['plugin_id']
                vuln_index = vulnerability['vuln_index']

                self.scan_api.action("scans/{}/hosts/{}/plugins/{}{}".format(scan_id, host["host_id"], plugin_id, history_id_params), method="GET")
                vuln_data = self._extract_vulnerability_data(self.scan_api.res, host["hostname"])
                host_dict['vulnerabilities'].append(deepcopy(vuln_data))

            for compliance in res_host_info['compliance']:
                # TODO: Hacer cuando tengamos muestras con credenciales
                pass

            results['hosts'][host["hostname"]] = deepcopy(host_dict)

        return results

    def _extract_vulnerability_data(self, vuln_information, hostname):
        # TODO: Adaptar al SC

        vuln_data = {}

        port_data = ""
        occurences = []
        ports = []
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
            "occurences": occurences,
            "ports": ports,
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

    def get_results_events(self, scan_id):
        # TODO: Adaptar al SC
        results = self.get_results(scan_id)
        return self.parse_report_to_events(results)

    def parse_report_to_events(self, results):
        raise NotImplementedError()
        data_events = []
        for host, host_data in results['hosts'].items():
            event_host_base = {
                'scan_id': results['scan_id'],
                'scan_uuid': results.get('scan_uuid'),
                'scan_name': results['scan_name'],
                'scan_start': results['scan_start'],
                'scan_end': results['scan_end'],
                'scan_policy': results['scan_policy'],
                'os': host_data['os'],
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

    ## Scan Creation
    def create_scan(self):
        pass

    def delete_scan(self):
        pass

    def update_scan(self):
        pass

    def update_scan_targets(self, scan_id, targets=[]):
        pass

    def update_scan_schedule(self, scan_id, targets=[]):
        pass

    ### TODO: HASTA AQUÍ ###
    ## TODO: Scan Control
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
