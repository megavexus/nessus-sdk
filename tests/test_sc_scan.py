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
    scan_list = scanner.scan_list()
    assert len(scan_list) > 0


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


## Get Instances
def test_list_results(sc_scanner):
    list_instances = sc_scanner.scan_api.scan_instances.list()
    assert list_instances
    raise Exception(list_instances)

def test_get_scan_result(sc_scanner):
    results = sc_scanner.scan_inspect(scan_id=2)
    raise Exception(results)
### Obtiene las instancias de un escaneo
### Obtiene 
## Get Results