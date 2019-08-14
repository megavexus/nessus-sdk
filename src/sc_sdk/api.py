from tenable.sc import TenableSC
from tenable.errors import APIError
from .exceptions import *
import requests
import logging
import os


class SCApi(TenableSC):
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

        super().__init__(
            host=host, 
            scheme=scheme,
            ssl_verify=unsecure == False,
            session = session,
        )

        self._init_logger()
        self.login(username, password)

    def _init_logger(self):
        self.logger = logging.getLogger('sc_api')
        if not len(self.logger.handlers):
            logger_handler = logging.StreamHandler()
            logger_handler.setLevel(logging.DEBUG)

            logger_format_style = "%(asctime)s (%(name)s) [%(levelname)s]: %(message)s"
            logger_formatter = logging.Formatter(logger_format_style)
            logger_handler.setFormatter(logger_formatter)

            self.logger.addHandler(logger_handler)

    def login(self, user, password):
        try:
            super().login(user,password)
        except APIError as e:
            if "Invalid login credentials" in e.msg:
                raise BadLoginException
            else:
                raise

    def _check_kwargs(self, allowed_keys, **kwargs):
        invalid_args = []
        for key in kwargs.keys():
            if not key in allowed_keys:
                invalid_args.append(key)
        
        if len(invalid_args) > 0: 
            raise WrongParametersException(invalid_args)
"""
import urllib3
import json

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
                try:
                    self._login()
                    self.action(action=action, method=method, extra=extra, files=files,
                                json_req=json_req, download=download, private=private,
                                retry=False)
                except IndexError:
                    raise WrongCredentialsException("Bad Access Key Given")
"""
