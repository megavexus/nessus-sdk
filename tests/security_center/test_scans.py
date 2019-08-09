import pytest

## Inspect Scans
def test_list_results(security_center):
    list_instances = security_center.scan.list_results()
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

## TODO: Create Scans
# TODO: Search for a Scan
# TODO: Create Scan
# TODO: Edit Scan
# TODO: Edit Inventory Scan
# TODO: Edit Schedule Scan
# TODO: Delete Scan Scan


## TODO: Control Scans
# TODO: RUN SCAN
# TODO: STOP SCAN
# TODO: CANCEL SCAN SCAN

