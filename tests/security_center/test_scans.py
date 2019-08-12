import pytest

## Inspect Scans
def test_list_results(security_center):
    list_instances = security_center.scan.list()
    assert len(list_instances) > 0


def test_get_scan_result(security_center):
    results = security_center.scan.results(scan_id=2, filters=[("severity", "=", "4,3")])
    assert len(results) > 0


def test_get_scan_info(security_center):
    results = security_center.scan.inspect(scan_id=2, filters=[("severity", "=", "4")])
    assert len(results) > 0
    assert len(results['vulnerabilities']) > 0


def test_get_scan_status(security_center):
    status = security_center.scan.status(scan_id=2)
    assert status == "Completed"

@pytest.mark.parametrize("name, targets, asset_lists, schedule", [
    ("TEST CREATE 1", ["127.0.0.1"], [], None)
])
def test_create(security_center, name, targets, asset_lists, schedule):
    policy_id = 1
    repository_id = 7
    scan = security_center.scan.create(name, repository_id, policy_id, targets=targets, asset_lists=asset_lists)
    existent_scans = security_center.scan.list_scans(name=name)
    assert existent_scans['id'] == scan['id']
    security_center.scan.delete(scan['id'])

def test_delete(security_center):
    policy_id = 1
    repository_id = 7
    targets = ['127.0.0.1']
    name = "BORRATE ESTA SC"
    scan = security_center.scan.create(name, repository_id, policy_id, targets=targets)
    security_center.scan.delete(scan['id'])
    existent_scans = security_center.scan.list_scans(name=name)
    assert existent_scans == []

@pytest.fixture(scope="function")
def sc_scan(security_center):
    policy_id = 1
    repository_id = 7
    targets = ['127.0.0.1']
    name = "TEST DE PRUEBAS API"
    scan = security_center.scan.create(name, repository_id, policy_id, targets=targets)
    yield scan
    security_center.scan.delete(scan['id'])

@pytest.mark.parametrize("kwargs, key_mapping", [
    ({"targets":["127.0.0.1","192.168.0.1"]}, {"targets": "ipList"}),
    ({"name":"PERRO ONE"},  {"name": "name"}),
])
def test_update(security_center, sc_scan, kwargs, key_mapping):
    scan_id = sc_scan['id']
    updated_scan = security_center.scan.update(scan_id, **kwargs)

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
    ical_dt = security_center.scan._get_ical_time(timestamp, locale)
    assert expected == ical_dt

@pytest.mark.parametrize("description, expected", [
    ("every month", "INTERVAL=1;FREQ=MONTHLY"),
    ("every two weeks", "INTERVAL=2;FREQ=WEEKLY"),
    ("every day at 2pm", "BYHOUR=14;BYMINUTE=0;INTERVAL=1;FREQ=DAILY"),
    #("in wednesdays of every two weeks", "BYDAY=WE;INTERVAL=2;FREQ=WEEKLY"), # ERROR. Esta sale mal
    ("each thurs", "BYDAY=TH;INTERVAL=1;FREQ=WEEKLY"),
])
def test_get_ical_rrule(security_center, description, expected):
    ical_rrule = security_center.scan._get_ical_rrule(description)
    assert expected == ical_rrule

@pytest.mark.parametrize("start_time, rrule_description, expected", [
    (None, None, {"type": "never"}),
    (1565598930, None, {"type": "ical", "start": "TZID=Europe/Madrid:20190812T103530"}),
    (None, "every month", {"type": "ical", "repeatRule": "INTERVAL=1;FREQ=MONTHLY"}),
    (None, "sdadsadsa", {"type": "never"}),
    (1565598930, "every day at 2pm", {"type": "ical", "start": "TZID=Europe/Madrid:20190812T103530", "repeatRule":"BYHOUR=14;BYMINUTE=0;INTERVAL=1;FREQ=DAILY"}),
])
def test_traduct_schedule(security_center, start_time, rrule_description, expected):
    scheduling = security_center.scan._traduct_scheduling(start_time, rrule_description)
    assert scheduling == expected


@pytest.mark.parametrize("start_time, rrule_description, expected", [
    # NOTA: Sólo funciona en ical si tiene rryle y start
    (None, None, {"type": "never"}),
    (1565598930, "every day at 2pm", {"type": "ical", "start": "TZID=Europe/Madrid:20190812T103530", "repeatRule":"BYHOUR=14;BYMINUTE=0;INTERVAL=1;FREQ=DAILY"}),
])
def test_update_schedule(security_center, sc_scan, start_time, rrule_description, expected):
    id_scan = sc_scan['id']
    scheduling = security_center.scan._traduct_scheduling(start_time, rrule_description)
    scan =  security_center.scan.update(id_scan, schedule=scheduling)
    assert scheduling['type'] == scan['schedule']['type']
    assert scheduling.get('start',"") == scan['schedule']['start']
    assert scheduling.get('repeatRule', "") == scan['schedule']['repeatRule']

## TODO: Control Scans
# TODO: RUN SCAN
# TODO: STOP SCAN
# TODO: CANCEL SCAN
# TODO: RESTART SCAN

