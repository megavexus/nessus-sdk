# -*- coding: utf-8 -*-

from .nessrest import NessusScanner

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

    
    def scan_run(self, scan_id):
        """
        Start the scan and save the UUID to query the status
        """
        self.scan_api.action(action="scans/{}/launch".format(scan_id), method="POST")
        scan_info = self.scan_inspect(scan_id = scan_id)
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

    def scan_inspect(self, scan_id=None, scan_name=None):
        """
        Fetch the details of the requested scan
        """
        if scan_id != None:
            self.scan_api.action(action="scans/{}".format(scan_id), method="GET")
        elif scan_name != None:
            self.scan_api.scan_details(scan_name)
        else: 
            return None

        if 'error' in self.scan_api.res:
            raise KeyError(self.scan_api.res['error'])

        return self.scan_api.res

    
    def scan_status(self, scan_id=None, scan_name=None):
        scan_info = self.scan_inspect(scan_id, scan_name)
        return scan_info['info']['status']


    def get_running_scanners(self):
        """
        TODO:
        Returns a list with the scanners running right now
        """
        pass


    def get_results(self, scan_id):
        """
        self.scan_id = scan_id
        self.scan_inspect(self.scan_id)
        if self.scan_api.res['info']['status'] != "completed":
            return None
        
        self._scan_status()
        
        results = {}
        for host in self.scan_api.res["hosts"]:
            host_dict = {
                'target': host["hostname"]
            }
            if self.format_start:
                host_dict['format_start'] = self.format_start

            for plugin in self.plugins.keys():
                self.scan_api.action("scans/{}/hosts/{}/plugins/{}".format(self.scan_id, host["host_id"], plugin), method="GET")



        # Por cada host:
            # Coge los plugins
            # 
        pass
        """


