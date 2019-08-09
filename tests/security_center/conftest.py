import pytest
import configparser
import os
from sc_sdk.api import SCApi
from sc_sdk import SecurityCenter


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

@pytest.fixture()
def sc_api(connection_data):
    scanner = SCApi(
        host=connection_data['host'],
        port=connection_data['port'],
        scheme=connection_data['scheme'],
        username=connection_data['username'],
        password=connection_data['password'],
        unsecure=connection_data['unsafe'],
    )
    return scanner
@pytest.fixture()
def security_center(connection_data):
    scanner = SecurityCenter(
        host=connection_data['host'],
        port=connection_data['port'],
        scheme=connection_data['scheme'],
        username=connection_data['username'],
        password=connection_data['password'],
        unsecure=connection_data['unsafe'],
    )
    return scanner
