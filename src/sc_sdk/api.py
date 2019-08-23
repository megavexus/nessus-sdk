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

    def parse_events_to_strings(self, result_events):
        string_results = []
        for result in result_events:
            string_results.append(
                ", ".join([self._key_value_to_string(key, value) for key,value in result.items()])
            )
        return string_results
