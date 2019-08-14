import pytest
import time
import logging

## Inspect Scans
def test_list_results(security_center):
    list_instances = security_center.scans.list()
    assert len(list_instances) > 0


def test_get_scan_result(security_center):
    results = security_center.scans.results(scan_id=2, filters=[("severity", "=", "4,3")])
    assert len(results) > 0


def test_get_scan_info(security_center):
    results = security_center.scans.inspect(scan_id=2, filters=[("severity", "=", "4")])
    assert len(results) > 0
    assert len(results['vulnerabilities']) > 0


def test_get_scan_status(security_center):
    status = security_center.scans.status(scan_id=2)
    assert status == "Completed"

@pytest.mark.parametrize("name, targets, asset_lists, schedule", [
    ("TEST CREATE 1", ["127.0.0.1"], [], None)
])
def test_create(security_center, repository_id, name, targets, asset_lists, schedule):
    policy_id = 1
    scan = security_center.scans.create(name, repository_id, policy_id, targets=targets, asset_lists=asset_lists)
    existent_scans = security_center.scans.list_scans(name=name)
    assert existent_scans['id'] == scan['id']
    security_center.scans.delete(scan['id'])

def test_delete(security_center, repository_id):
    policy_id = 1
    targets = ['127.0.0.1']
    name = "BORRATE ESTA SC"
    scan = security_center.scans.create(name, repository_id, policy_id, targets=targets)
    security_center.scans.delete(scan['id'])
    existent_scans = security_center.scans.list_scans(name=name)
    assert existent_scans == []

@pytest.fixture(scope="function")
def sc_scan(security_center, repository_id):
    policy_id = 1
    targets = ['10.229.214.132']
    name = "TEST DE PRUEBAS API"
    scan = security_center.scans.create(name, repository_id, policy_id, targets=targets)
    yield scan
    security_center.scans.delete(scan['id'])

@pytest.fixture(scope="function")
def sc_scan_nd(security_center, repository_id):
    policy_id = 1
    targets = ['10.229.214.132']
    name = "TEST DE PRUEBAS API NONDELETE"
    scan = security_center.scans.create(name, repository_id, policy_id, targets=targets)
    yield scan


@pytest.mark.parametrize("kwargs, key_mapping", [
    ({"targets":["127.0.0.1","192.168.0.1"]}, {"targets": "ipList"}),
    ({"name":"PERRO ONE"},  {"name": "name"}),
])
def test_update(security_center, sc_scan, kwargs, key_mapping):
    scan_id = sc_scan['id']
    updated_scan = security_center.scans.update(scan_id, **kwargs)

    for key,value in kwargs.items():
        key_sc = key_mapping.get(key, key)
        if key_sc == "ipList":
            kwargs[key] = "\r".join(kwargs[key])
        assert updated_scan[key_sc] == kwargs[key]

@pytest.mark.parametrize("timestamp, locale, expected", [
    (1565598930, None, "TZID=Europe/Madrid:20190812T103530"), # 
    (1265916900, "America/New York", "TZID=America/New York:20100211T203500"),
])
def test_get_ical_time(security_center, timestamp, locale, expected):
    ical_dt = security_center.scans._get_ical_time(timestamp, locale)
    assert expected == ical_dt

@pytest.mark.parametrize("description, expected", [
    ("every month", "INTERVAL=1;FREQ=MONTHLY"),
    ("every two weeks", "INTERVAL=2;FREQ=WEEKLY"),
    ("every day at 2pm", "BYHOUR=14;BYMINUTE=0;INTERVAL=1;FREQ=DAILY"),
    #("in wednesdays of every two weeks", "BYDAY=WE;INTERVAL=2;FREQ=WEEKLY"), # ERROR. Esta sale mal
    ("each thurs", "BYDAY=TH;INTERVAL=1;FREQ=WEEKLY"),
])
def test_get_ical_rrule(security_center, description, expected):
    ical_rrule = security_center.scans._get_ical_rrule(description)
    assert expected == ical_rrule

@pytest.mark.parametrize("start_time, rrule_description, expected", [
    (None, None, {"type": "never"}),
    (1565598930, None, {"type": "ical", "start": "TZID=Europe/Madrid:20190812T103530"}),
    (None, "every month", {"type": "ical", "repeatRule": "INTERVAL=1;FREQ=MONTHLY"}),
    (None, "sdadsadsa", {"type": "never"}),
    (1565598930, "every day at 2pm", {"type": "ical", "start": "TZID=Europe/Madrid:20190812T103530", "repeatRule":"BYHOUR=14;BYMINUTE=0;INTERVAL=1;FREQ=DAILY"}),
])
def test_traduct_schedule(security_center, start_time, rrule_description, expected):
    scheduling = security_center.scans._traduct_scheduling(start_time, rrule_description)
    assert scheduling == expected


@pytest.mark.parametrize("start_time, rrule_description, expected", [
    # NOTA: Sólo funciona en ical si tiene rryle y start
    (None, None, {"type": "never"}),
    (1565598930, "every day at 2pm", {"type": "ical", "start": "TZID=Europe/Madrid:20190812T103530", "repeatRule":"BYHOUR=14;BYMINUTE=0;INTERVAL=1;FREQ=DAILY"}),
])
def test_update_schedule(security_center, sc_scan, start_time, rrule_description, expected):
    id_scan = sc_scan['id']
    scheduling = security_center.scans._traduct_scheduling(start_time, rrule_description)
    scan =  security_center.scans.update(id_scan, schedule=scheduling)
    assert scheduling['type'] == scan['schedule']['type']
    assert scheduling.get('start',"") == scan['schedule']['start']
    assert scheduling.get('repeatRule', "") == scan['schedule']['repeatRule']

@pytest.mark.slow
def test_run_scan(security_center, sc_scan):
    id_scan = sc_scan['id']
    scan_instance = security_center.scans.run(id_scan)
    
    assert scan_instance['status'] == "Queued"

    id_scan_instance = scan_instance['id']
    scan_status = scan_instance['status']
    current_time_step = 0
    time_steps = 5
    
    while scan_status != "Running":
        time.sleep(time_steps)
        current_time_step += time_steps

        details = security_center.scans.get(id_scan_instance)
        scan_status = details['status']
        logging.info("[{}s]: Status = {}".format(current_time_step, scan_status))

        assert current_time_step < 120
    
    security_center.scans.stop(scan_instance['id'])

@pytest.mark.slow
def test_run_scan_waiting(security_center, sc_scan):
    id_scan = sc_scan['id']
    scan_instance = security_center.scans.run(id_scan, wait=True)    
    assert scan_instance['status'] == "Running"
    security_center.scans.stop(scan_instance['id'])


@pytest.mark.slow
def test_stop_scan(security_center, sc_scan):
    id_scan = sc_scan['id']
    scan_instance = security_center.scans.run(id_scan, wait=True)
    assert scan_instance['status'] == "Running"
    id_scan_instance = scan_instance['id']

    scan_stopped = security_center.scans.stop(id_scan_instance)
    scan_status = scan_stopped['status']
    current_time_step = 0
    time_steps = 5
    timeout = 90

    while scan_status != "Stopping":
        assert current_time_step <= timeout

        time.sleep(time_steps)
        current_time_step += time_steps

        details = security_center.scans.get(id_scan_instance)
        scan_status = details['status']


@pytest.mark.slow
def test_pause_scan(security_center, sc_scan):
    id_scan = sc_scan['id']
    scan_instance = security_center.scans.run(id_scan, wait=True)
    assert scan_instance['status'] == "Running"
    id_scan_instance = scan_instance['id']

    scan_paused = security_center.scans.pause(id_scan_instance)
    scan_status = scan_paused['status']
    current_time_step = 0
    time_steps = 5
    timeout = 90

    while scan_status != "Paused":
        assert current_time_step <= timeout

        time.sleep(time_steps)
        current_time_step += time_steps

        details = security_center.scans.get(id_scan_instance)
        scan_status = details['status']

    security_center.scans.stop(scan_instance['id'], wait=True)

@pytest.mark.slow
def test_pause_scan_waiting(security_center, sc_scan):
    id_scan = sc_scan['id']
    scan_instance = security_center.scans.run(id_scan, wait=True)
    assert scan_instance['status'] == "Running"
    id_scan_instance = scan_instance['id']

    scan_paused = security_center.scans.pause(id_scan_instance, wait=True)
    scan_status = scan_paused['status']
    assert scan_status == "Paused"
    security_center.scans.stop(scan_instance['id'], wait=True)


@pytest.mark.slow
def test_resume_scan(security_center, sc_scan):
    id_scan = sc_scan['id']
    scan_instance = security_center.scans.run(id_scan, wait=True)
    assert scan_instance['status'] == "Running"
    id_scan_instance = scan_instance['id']

    scan_instance = security_center.scans.pause(id_scan_instance, wait=True)
    assert scan_instance['status'] == "Paused"
    time.sleep(2)

    scan_resumed = security_center.scans.resume(id_scan_instance)
    scan_status = scan_resumed['status']

    current_time_step = 0
    time_steps = 2
    timeout = 90

    while scan_status != "Running":
        assert current_time_step <= timeout

        time.sleep(time_steps)
        current_time_step += time_steps

        details = security_center.scans.get(id_scan_instance)
        scan_status = details['status']
    
    assert scan_status == "Running"
    time.sleep(5)

    security_center.scans.stop(id_scan_instance, wait=True)


@pytest.mark.slow
def test_resume_scan_waiting(security_center, sc_scan):
    id_scan = sc_scan['id']
    scan_instance = security_center.scans.run(id_scan, wait=True)
    assert scan_instance['status'] == "Running"
    id_scan_instance = scan_instance['id']

    scan_instance = security_center.scans.pause(id_scan_instance, wait=True)
    assert scan_instance['status'] == "Paused"
    time.sleep(2)

    scan_resumed = security_center.scans.resume(id_scan_instance, wait=True)
    scan_status = scan_resumed['status']
    assert scan_status == "Running"
    time.sleep(15)

    security_center.scans.stop(id_scan_instance, wait=True)
