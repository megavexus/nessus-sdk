# -*- coding: utf-8 -*-

from nessrest.ness6rest import Scanner as NessusScanner, SSLException
import json
import requests
import atexit
import os


class Scanner(NessusScanner):

    def __init__(self, url, login='', password='', api_akey='', api_skey='',
                 insecure=False, ca_bundle='', bypass_proxy=False):
        self.bypass_proxy = bypass_proxy
        self.api_akey = None
        self.api_skey = None
        self.use_api = False
        self.name = ''
        self.policy_name = ''
        self.debug = False
        self.format = ''
        self.format_start = ''
        self.format_end = ''
        self.http_response = ''
        self.plugins = {}
        self.names = {}
        self.files = {}
        self.cisco_offline_configs = ''
        self.permissions = ''
        self.policy_id = ''
        self.policy_object = ''
        self.pref_cgi = ''
        self.pref_paranoid = ''
        self.pref_supplied = ''
        self.pref_thorough = ''
        self.pref_max_checks = ''
        self.pref_receive_timeout = ''
        self.set_safe_checks = ''
        self.pref_verbose = ''
        self.pref_silent_dependencies = ''
        self.res = {}
        self.scan_id = ''
        self.scan_name = ''
        self.scan_template_uuid = ''
        self.scan_uuid = ''
        self.tag_id = ''
        self.tag_name = ''
        self.targets = ''
        self.policy_template_uuid = ''
        self.token = ''
        self.url = url
        self.ver_feed = ''
        self.ver_gui = ''
        self.ver_plugins = ''
        self.ver_svr = ''
        self.ver_web = ''
        self.ca_bundle = ca_bundle
        self.insecure = insecure
        self.auth = []
        self.host_vulns = {}
        self.plugin_output = {}
        self.host_details = {}
        self.host_ids = {}

        if insecure and hasattr(requests, 'packages'):
            requests.packages.urllib3.disable_warnings()

        if (api_akey and api_skey):
            self.api_akey = api_akey
            self.api_skey = api_skey
            self.use_api = True
        else:
            # Initial login to get our token for all subsequent transactions
            self._login(login, password)

            # Register a call to the logout action automatically
            atexit.register(self.action, action="session",
                            method="DELETE", retry=False)

        self._get_permissions()
        self._get_scanner_id()


    def action(self, action, method, extra={}, files={}, json_req=True, download=False, private=False, retry=True):
        '''
        Generic actions for REST interface. The json_req may be unneeded, but
        the plugin searching functionality does not use a JSON-esque request.
        This is a backup setting to be able to change content types on the fly.
        '''
        payload = {}
        payload.update(extra)
        if self.use_api:
            headers = {'X-ApiKeys': 'accessKey=' + self.api_akey +
                       '; secretKey=' + self.api_skey}
        else:
            headers = {'X-Cookie': 'token=' + str(self.token)}

        if json_req:
            headers.update({'Content-type': 'application/json',
                            'Accept': 'text/plain'})
            payload = json.dumps(payload)

        url = "%s/%s" % (self.url, action)
        if self.debug:
            if private:
                print("JSON    : **JSON request hidden**")
            else:
                print("JSON    :")
                print(payload)

            print("HEADERS :")
            print(headers)
            print("URL     : %s " % url)
            print("METHOD  : %s" % method)
            print("\n")

        # Figure out if we should verify SSL connection (possibly with a user
        # supplied CA bundle). Default to true.
        if self.insecure:
            verify = False
        elif self.ca_bundle:
            verify = self.ca_bundle
        else:
            verify = True

        try:
            if self.bypass_proxy:
                session = requests.Session()
                session.trust_env = False
                req = session.request(method, url, data=payload, files=files,
                                    verify=verify, headers=headers)
            else:
                req = requests.request(method, url, data=payload, files=files,
                                      verify=verify, headers=headers)

            if not download and req.text:
                self.res = req.json()
            elif not req.text:
                self.res = {}

            if req.status_code != 200:
                print("*****************START ERROR*****************")
                if private:
                    print("JSON    : **JSON request hidden**")
                else:
                    print("JSON    :")
                    print(payload)
                    print(files)

                print("HEADERS :")
                print(headers)
                print("URL     : %s " % url)
                print("METHOD  : %s" % method)
                print("RESPONSE: %d" % req.status_code)
                print("\n")
                self.pretty_print()
                print("******************END ERROR******************")

            if self.debug:
                # This could also contain "pretty_print()" but it makes a lot of
                # noise if enabled for the entire scan.
                print("RESPONSE CODE: %d" % req.status_code)

            if download:
                return req.content
        except requests.exceptions.SSLError as ssl_error:
            raise SSLException('%s for %s.' % (ssl_error, url))
        except requests.exceptions.ConnectionError as e:
            raise Exception("{} {} {} {} {} {} {}".format(
                method, url, payload, files, verify, headers, str(e)
            ))
            raise Exception("Could not connect to %s.\nExiting!\n" % url)

        if self.res and "error" in self.res and retry:
            if self.res["error"] == "You need to log in to perform this request" or self.res["error"] == "Invalid Credentials":
                self._login()
                self.action(action=action, method=method, extra=extra, files=files,
                            json_req=json_req, download=download, private=private,
                            retry=False)

    def scan_stop(self, scan_id=None):
        '''
        Start the scan and save the UUID to query the status
        '''
        if scan_id == None:
            scan_id = self.scan_id
        self.action(action="scans/" + str(scan_id) + "/stop", method="POST")
        

    def scan_list_from_folder(self, folder_id):
        '''
        Fetch a list with scans from a specified folder
        '''
        self.scan_list()
        scans = self.res[u'scans']

        self.res = []
        for scan in scans:
            if str(scan[u'folder_id']) == str(folder_id):
                self.res.append(scan)

        return self.res


if __name__ == "__main__":
    import os
    os.environ['NO_PROXY'] = '127.0.0.1,localhost,10.139.90.81'
    #host = "https://10.139.90.81:8834"
    host = "https://127.0.0.1:8834"
    user = "admin"
    #password = "Disma$020"
    password = "1234"
    insecure = True
    scan_class = Scanner(url=host, login=user, password=password, insecure=insecure)
    
    #scan_list = scan.scan_list_from_folder("1089")
    scan_list = scan_class.scan_list_from_folder("5")
    for scan in scan_list:
        if str(scan[u'status']) == "running":
            print("[!] Running Scan [#{}] {}. Stopping...".format(
                scan[u'id'], scan[u'name']))
            scan_class.scan_stop(scan[u'id'])
            print("....SCAN STOPPED")
        else:
            print(" - Scan [#{}] {}: STATUS = {}".format(
                scan[u'status'], scan[u'id'], scan[u'name']))
    #for scan in scan_list[u'scans']:

    #    print("{}".format(scan))
