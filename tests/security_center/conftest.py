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
        'repository_id': config['sc'].get('repository_id', 7),
    }
    return data

@pytest.fixture()
def adm_connection_data():
    mypath = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(mypath, 'config', 'sc.conf')
    config = configparser.ConfigParser()
    config.read(config_file)

    data = {
        'host': config['sc_adm'].get('host', '127.0.0.1'),
        'port': config['sc_adm'].get('port', 443),
        'scheme': config['sc_adm'].get('scheme', 'https'),
        'username': config['sc_adm'].get('username', 'admin'),
        'password': config['sc_adm'].get('password', '1234'),
        'unsafe': config['sc_adm'].get('unsafe', 'false') == "true",
        'repository_id': config['sc_adm'].get('repository_id', 7),
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

@pytest.fixture()
def adm_sc(adm_connection_data):
    scanner = SecurityCenter(
        host=adm_connection_data['host'],
        port=adm_connection_data['port'],
        scheme=adm_connection_data['scheme'],
        username=adm_connection_data['username'],
        password=adm_connection_data['password'],
        unsecure=adm_connection_data['unsafe'],
    )
    return scanner

@pytest.fixture()
def repository_id(connection_data):
    return connection_data['repository_id']