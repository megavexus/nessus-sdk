import pytest
import configparser
import os
import time
from nessus_sdk import Scanner
from nessus_sdk.exceptions import WrongCredentialsException, BadLoginException


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
    targets = "127.0.0.1,10.229.214.132"
    policy = "basic network scan"
    folder_name = "Pruebas Pytest"
    name = "Pytest Prueba SDK"
    description = "Pytest Prueba SDK"

    scan_id = nessus_scanner.scan_create_from_name(name, targets, policy, folder_name, description=description)
    assert type(scan_id) == int


@pytest.fixture()
def created_scanner_id(nessus_scanner):
    targets = "10.229.214.132"
    policy = "basic network scan"
    folder_name = "Pruebas Pytest"
    name = "Pytest Prueba SDK"
    description = "Pytest Prueba SDK"

    scan_id = nessus_scanner.scan_create_from_name(name, targets, policy, folder_name, description=description)
    return scan_id


def test_inspect_scan(nessus_scanner, created_scanner_id):
    scan_info = nessus_scanner.scan_inspect(scan_id=created_scanner_id)
    assert type(scan_info) == dict
    assert len(scan_info) > 0


def test_get_scan_status(nessus_scanner, created_scanner_id):
    scan_status = nessus_scanner.scan_status(scan_id=created_scanner_id)
    assert type(scan_status) == str


def test_run_scanner(nessus_scanner, created_scanner_id):
    scan_uuid = nessus_scanner.scan_run(scan_id=created_scanner_id)
    assert type(scan_uuid) == str
    scan_info = nessus_scanner.scan_inspect(scan_id=created_scanner_id)
    assert scan_info['info']['status'] == "running"
    assert scan_info['info']['uuid'] == scan_uuid


def test_delete_scanner(nessus_scanner):
    targets = "127.0.0.1,10.229.214.132"
    policy = "bash shellshock detection"
    folder_name = "Pruebas Pytest"
    name = "Pytest Delete Test"
    description = "Pytest Delete test"

    scan_id = nessus_scanner.scan_create_from_name(name, targets, policy, folder_name, description=description)

    nessus_scanner.scan_delete(scan_id=scan_id)
    with pytest.raises(KeyError) as ex:
        scan_info = nessus_scanner.scan_inspect(scan_id=scan_id)
        str(ex) == "The requested file was not found"


def test_stop_scanner(nessus_scanner, created_scanner_id):
    scan_uuid = nessus_scanner.scan_run(created_scanner_id)
    scan_info = nessus_scanner.scan_inspect(created_scanner_id)
    assert scan_info['info']['status'] == "running"

    scan_uuid = nessus_scanner.scan_stop(created_scanner_id)
    scan_info = nessus_scanner.scan_inspect(created_scanner_id)
    assert scan_info['info']['status'] == "stopping"
    assert scan_info['info']['uuid'] == scan_uuid

    time.sleep(5)
    scan_info = nessus_scanner.scan_inspect(created_scanner_id)
    if scan_info == "stopping":
        # Si sigue parandose, le damos 5s mas...
        time.sleep(15)
        scan_info = nessus_scanner.scan_inspect(created_scanner_id)

    assert scan_info['info']['status'] == "canceled"


@pytest.mark.slow
def test_pause_scanner(nessus_scanner, created_scanner_id):
    scan_info = nessus_scanner.scan_inspect(created_scanner_id)
    targets = scan_info['info']['targets']
    # Le metemos mas hosts para que no se complete antes de pararse
    targets = targets + ",127.0.0.1,localhost,10.229.214.132/24"
    nessus_scanner.update_targets(created_scanner_id,targets)

    scan_uuid = nessus_scanner.scan_run(created_scanner_id)
    scan_info = nessus_scanner.scan_inspect(created_scanner_id)
    assert scan_info['info']['status'] == "running"
    
    scan_uuid = nessus_scanner.scan_pause(created_scanner_id)
    
    scan_info = nessus_scanner.scan_inspect(created_scanner_id)
    assert scan_info['info']['status'] in ["pausing", "paused"]
    assert scan_info['info']['uuid'] == scan_uuid
    
    time.sleep(10)
    scan_info = nessus_scanner.scan_inspect(created_scanner_id)
    assert scan_info['info']['status'] == "paused"

    #borra el scan antes de salir, para no bloquear
    nessus_scanner.scan_stop(scan_id=created_scanner_id)
    time.sleep(10)


@pytest.mark.slow
def test_get_result_scan(nessus_scanner, created_scanner_id):
    # espera a que acabe
    scan_uuid = nessus_scanner.scan_run(created_scanner_id, wait_to_finish=True)
    scan_results = nessus_scanner.get_results(created_scanner_id, scan_uuid=scan_uuid)
    assert scan_results['scan_id'] == created_scanner_id
    assert scan_results['scan_uuid'] == scan_uuid
    assert len(scan_results['hosts']) == 1
    for host, host_data in scan_results['hosts'].items():
        assert 'vulnerabilities' in host_data
        assert 'compliance' in host_data
        assert host == host_data['target']


@pytest.mark.slow
def test_get_result_scan_custom_hosts(nessus_scanner, created_scanner_id):
    # espera a que acabe
    custom_hosts = ["10.229.214.132","10.229.214.133","10.229.214.139"]
    scan_uuid = nessus_scanner.scan_run(
        created_scanner_id, 
        custom_targets=custom_hosts,
        wait_to_finish=True)
    scan_results = nessus_scanner.get_results(created_scanner_id, scan_uuid=scan_uuid)
    assert scan_results['scan_id'] == created_scanner_id
    assert scan_results['scan_uuid'] == scan_uuid
    assert len(scan_results['hosts']) == 3
    for host, host_data in scan_results['hosts'].items():
        assert 'vulnerabilities' in host_data
        assert 'compliance' in host_data
        assert host == host_data['target']


def test_get_result_custom_scan(nessus_scanner, created_scanner_id):
    created_scanner_id = 110
    uuid = "40215f76-5212-e45a-8621-0de1f8207ad4f7b464b4f2dd63fd"
    scan_results = nessus_scanner.get_results(created_scanner_id, scan_uuid=uuid)

    assert scan_results['scan_id'] == created_scanner_id
    assert scan_results['scan_uuid'] == uuid
    assert len(scan_results['hosts']) == 3
    for host, host_data in scan_results['hosts'].items():
        assert 'vulnerabilities' in host_data
        assert 'compliance' in host_data
        assert host == host_data['target']


def test_get_result_events_scan(nessus_scanner):
    created_scanner_id = 110
    uuid = "40215f76-5212-e45a-8621-0de1f8207ad4f7b464b4f2dd63fd"
    scan_results = nessus_scanner.get_results_events(created_scanner_id, scan_uuid=uuid)

    assert len(scan_results) > 0
    for data in scan_results:
        assert data['scan_id'] == created_scanner_id
        assert data['scan_uuid'] == uuid
        assert 'port' in data
        assert 'plugin_output' in data


def test_get_result_events_string_scan(nessus_scanner):
    created_scanner_id = 110
    uuid = "40215f76-5212-e45a-8621-0de1f8207ad4f7b464b4f2dd63fd"
    scan_results = nessus_scanner.get_results_string(created_scanner_id, scan_uuid=uuid)

    assert len(scan_results) > 0
    for data in scan_results:
        assert type(data) == str
        assert 'protocol=' in data
        assert 'server_protocol=' in data
        assert 'scan_id={}'.format(created_scanner_id) in data
        assert 'scan_uuid="{}"'.format(uuid) in data


def test_get_scan_diff_last_scan(nessus_scanner):
    created_scanner_id = 110
    scan_results = nessus_scanner.get_diff(created_scanner_id)
    assert scan_results['scan_id'] == created_scanner_id
    assert scan_results['scan_uuid'][0:5] == "diff-" 
    assert len(scan_results['hosts']) >= 0
    for host, host_data in scan_results['hosts'].items():
        assert 'vulnerabilities' in host_data
        assert 'compliance' in host_data
        assert host == host_data['target']



def test_get_scan_diff_one_scan(nessus_scanner):
    created_scanner_id = 110
    scaner_uuid = "05065a5d-4080-e352-c864-52689622a1fc8374b69eeb7a8782"
    scan_results = nessus_scanner.get_diff(created_scanner_id, scaner_uuid)
    assert scan_results['scan_id'] == created_scanner_id
    assert scan_results['scan_uuid'][0:5] == "diff-" 
    assert len(scan_results['hosts']) >= 3
    for host, host_data in scan_results['hosts'].items():
        assert 'vulnerabilities' in host_data
        assert 'compliance' in host_data
        assert host == host_data['target']


def test_get_scan_diff_two_targets(nessus_scanner):
    created_scanner_id = 110
    scaner_uuid = "05065a5d-4080-e352-c864-52689622a1fc8374b69eeb7a8782"
    scaner_last_uuid = "356aabec-3e66-1be3-feef-f7c5ff6b9f3fb323f4e389956493"
    scan_results = nessus_scanner.get_diff(created_scanner_id, scaner_uuid, scaner_last_uuid)
    raise Exception(scan_results)
    assert scan_results['scan_id'] >= created_scanner_id
    assert scan_results['scan_uuid'][0:5] == "diff-" 
    assert len(scan_results['hosts']) == 3
    for host, host_data in scan_results['hosts'].items():
        assert 'vulnerabilities' in host_data
        assert 'compliance' in host_data
        assert host == host_data['target']


def test_get_scan_history(nessus_scanner):
    scan_id = 110
    history = nessus_scanner._get_scan_history(scan_id)
    assert len(history) > 0


@pytest.mark.parametrize("targets, expected", [
    ("host1,host2", {"alt_targets": ["host1", "host2"]}),
    (" host1 , host2 ", {"alt_targets": ["host1", "host2"]}),
    (["host1","host2"], {"alt_targets": ["host1", "host2"]}),
    ([], {}),
    ("", {}),
    (None, {})
])
def test_get_custom_targets(nessus_scanner, targets, expected):
    custom_targets = nessus_scanner._get_custom_targets(targets)
    if len(expected) == 0:
        assert expected == custom_targets
    else:
        assert sorted(expected['alt_targets']) == sorted(custom_targets['alt_targets'])


def test_get_running_scanners(nessus_scanner):
    # start two scans
    created_scanner_id = 110
    nessus_scanner.scan_run(created_scanner_id)
    time.sleep(3)
    
    running_scanners = nessus_scanner.get_running_scanners()

    assert len(running_scanners) == 1
    assert running_scanners[0]['id'] == created_scanner_id

    nessus_scanner.scan_stop(created_scanner_id)
