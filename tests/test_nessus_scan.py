import pytest
import configparser
import os
from nessus_sdk import Scanner
from nessus_sdk.api import WrongCredentialsException, BadLoginException


@pytest.fixture()
def connection_data():
    mypath = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(mypath, 'config', 'nessus.conf')
    config = configparser.ConfigParser()
    config.read(config_file)

    data = {
        'host': config['nessus'].get('host', 'https://127.0.0.1:8834'),
        'login': config['nessus'].get('login', 'admin'),
        'passwd': config['nessus'].get('password', '1234'),
        'akey': config['nessus'].get('access_key', ''),
        'skey': config['nessus'].get('secret_key', ''),
        'insecure': config['nessus'].get('insecure', 'true') == "true",
    }
    return data


def test_login_user_password(connection_data):
    scanner = Scanner(
        url=connection_data['host'],
        login=connection_data['login'],
        password=connection_data['passwd'],
        insecure=connection_data['insecure'],
        bypass_proxy=True
    )
    scan_list = scanner.scan_list()
    assert len(scan_list) > 0


def test_login_user_bad_password(connection_data):
    with pytest.raises(BadLoginException):
        scanner = Scanner(
            url=connection_data['host'],
            login=connection_data['login'],
            password="hola123",
            insecure=connection_data['insecure'],
            bypass_proxy=True
        )


def test_login_user_key(connection_data):
    scanner = Scanner(
        url=connection_data['host'],
        api_akey=connection_data['akey'],
        api_skey=connection_data['skey'],
        insecure=connection_data['insecure'],
        bypass_proxy=True
    )
    scan_list = scanner.scan_list()
    assert len(scan_list) > 0


def test_login_wrong_akey(connection_data):
    with pytest.raises(WrongCredentialsException):
        scanner = Scanner(
            url=connection_data['host'],
            api_akey="ASDFG",
            api_skey=connection_data['skey'],
            insecure=connection_data['insecure'],
            bypass_proxy=True
        )


def test_login_wrong_skey(connection_data):
    with pytest.raises(WrongCredentialsException):
        scanner = Scanner(
            url=connection_data['host'],
            api_akey=connection_data['akey'],
            api_skey="IMMA WRONG",
            insecure=connection_data['insecure'],
            bypass_proxy=True
        )


@pytest.fixture()
def nessus_scanner(connection_data):
    scanner = Scanner(
        url=connection_data['host'],
        api_akey=connection_data['akey'],
        api_skey=connection_data['skey'],
        insecure=connection_data['insecure'],
        bypass_proxy=True
    )
    return scanner


def test_start_scanner(nessus_scanner):
    targets = "127.0.0.1,10.228.84.74"
    policy = "basic network scan"
    folder_name = "Pruebas Pytest"
    name = "Pytest Prueba SDK"
    description = "Pytest Prueba SDK"

    scan_id = nessus_scanner.scan_create(
        targets, policy, folder_name, scan_name=name, description=description)
    assert type(scan_id) == int


@pytest.fixture()
def created_scanner_id(nessus_scanner):
    targets = "127.0.0.1,10.228.84.74"
    policy = "basic network scan"
    folder_name = "Pruebas Pytest"
    name = "Pytest Prueba SDK"
    description = "Pytest Prueba SDK"

    scan_id = nessus_scanner.scan_create(
        targets, policy, folder_name, scan_name=name, description=description)
    return scan_id


def test_inspect_scan(nessus_scanner, created_scanner_id):
    scan_info = nessus_scanner.scan_inspect(scan_id=created_scanner_id)
    assert type(scan_info) == dict
    assert len(scan_info) > 0


def test_get_scan_status(nessus_scanner, created_scanner_id):
    scan_status = nessus_scanner.scan_status(scan_id=created_scanner_id)
    assert type(scan_status) == str


def test_run_scanner(nessus_scanner, created_scanner_id):
    scan_info = nessus_scanner.scan_run(scan_id=created_scanner_id)
    assert scan_info['status'] == "running"


def test_delete_scanner(nessus_scanner):
    targets = "127.0.0.1,10.228.84.74"
    policy = "basic network scan"
    folder_name = "Pruebas Pytest"
    name = "Pytest Delete Test"
    description = "Pytest Delete test"

    scan_id = nessus_scanner.scan_create(
        targets, policy, folder_name, scan_name=name, description=description)

    nessus_scanner.scan_delete(scan_id=scan_id)
    with pytest.raises(KeyError) as ex:
        scan_info = nessus_scanner.scan_inspect(scan_id=scan_id)
        str(ex) == "The requested file was not found"


def test_stop_scanner():
    pass


def test_pause_scanner():
    pass

###


def test_get_result_scan():
    pass


def test_get_result_events_scan():
    pass
