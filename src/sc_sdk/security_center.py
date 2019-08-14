from sc_sdk.endpoints.scan import Scan, ScanStatus
from sc_sdk.endpoints.repository import Repositories
from sc_sdk.api import SCApi


class SecurityCenter(object):
    def __init__(self, host, username='', password='', unsecure=False, scheme="https", port=443, http_proxy=None):
        self._version = "0.1"
        self.hostname = host
        self.username = username
        self.sc_api = SCApi(host, username, password, unsecure, scheme, port, http_proxy)

        self.scans = Scan(self.sc_api)
        self.repositories = Repositories(self.sc_api)
