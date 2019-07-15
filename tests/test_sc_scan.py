import pytest
import configparser
import os
import time
from sc_sdk import Scanner
from sc_sdk.exceptions import WrongCredentialsException, BadLoginException


@pytest.fixture()
def connection_data():
    mypath = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(mypath, 'config', 'sc.conf')
    config = configparser.ConfigParser()
    config.read(config_file)

    data = {
        'host': config['sc'].get('host', '127.0.0.1'),
        'port': config['sc'].get('port', 443),
        'scheme': config['sc'].get('scheme', 'https'),
        'username': config['sc'].get('username', 'admin'),
        'password': config['sc'].get('password', '1234'),
        'unsafe': config['sc'].get('unsafe', 'false') == "true",
    }
    return data


def test_login_user_password(connection_data):
    scanner = Scanner(
        host=connection_data['host'],
        port=connection_data['port'],
        scheme=connection_data['scheme'],
        username=connection_data['username'],
        password=connection_data['password'],
        unsecure=connection_data['unsafe'],
    )
    assert len(scanner.scan_api._session.headers) > 0


def test_login_user_bad_password(connection_data):
    with pytest.raises(BadLoginException):
        scanner = Scanner(
            host=connection_data['host'],
            port=connection_data['port'],
            scheme=connection_data['scheme'],
            username=connection_data['username'],
            password="hola123",
            unsecure=connection_data['unsafe'],
        )


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
def test_list_results(sc_scanner):
    list_instances = sc_scanner.scan_api.scan_instances.list()
    assert len(list_instances) > 0


def test_get_scan_result(sc_scanner):
    results = sc_scanner.get_scan_results(scan_id=2)
    assert len(results) > 0


def test_get_scan_info(sc_scanner):
    results = sc_scanner.scan_inspect(scan_id=2)
    assert len(results) > 0
    assert len(results['vulnerabilities']) > 0


def test_get_scan_status(sc_scanner):
    status = sc_scanner.scan_status(scan_id=2)
    assert status == "Complete"


@pytest.mark.slow
def test_get_result_scan(sc_scanner):
    # espera a que acabe
    created_scanner_id = 9
    scan_results = sc_scanner.get_results(created_scanner_id)
    assert scan_results['scan_id'] == created_scanner_id
    assert len(scan_results['hosts']) >= 1
    for host, host_data in scan_results['hosts'].items():
        assert 'vulnerabilities' in host_data
        assert 'compliance' in host_data
        assert host == host_data['target']
## TODO: Create Scans
## TODO: Control Scans
