import pytest
import configparser
import os
import time
from sc_sdk.scanner import Scanner
from sc_sdk.exceptions import WrongCredentialsException, BadLoginException

@pytest.fixture()
def sc_scanner(connection_data):
    scanner = Scanner(
        host=connection_data['host'],
        port=connection_data['port'],
        scheme=connection_data['scheme'],
        username=connection_data['username'],
        password=connection_data['password'],
        unsecure=connection_data['unsafe'],
    )
    return scanner


## Inspect Scans
@pytest.mark.skip()
def test_list_results(sc_scanner):
    list_instances = sc_scanner.scan_api.scan_instances.list()
    assert len(list_instances) > 0

@pytest.mark.skip()
def test_get_scan_result(sc_scanner):
    results = sc_scanner.get_scan_results(scan_id=2)
    assert len(results) > 0

@pytest.mark.skip()
def test_get_scan_info(sc_scanner):
    results = sc_scanner.scan_inspect(scan_id=2)
    assert len(results) > 0
    assert len(results['vulnerabilities']) > 0

@pytest.mark.skip()
def test_get_scan_status(sc_scanner):
    status = sc_scanner.scan_status(scan_id=2)
    assert status == "Complete"
