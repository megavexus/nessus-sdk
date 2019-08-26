import pytest
import os
import time
import configparser

def test_list(security_center):
    list_repos = security_center.repositories.list()
    assert len(list_repos) > 0

def test_get(security_center, repository_id):
    ID_REPO = repository_id
    results = security_center.repositories.get(ID_REPO)
    assert int(results["id"]) == int(ID_REPO)

@pytest.mark.parametrize("name,format_ip,allowed_ips", [
    ("TEST_API_CREATE_1","IPv4",["127.0.0.1"]),
    ("TEST_API_CREATE_2","IPv4",["127.0.0.0/8"]),
    ("TEST_API_CREATE_3","IPv4",["127.0.0.0/8","10.229.214.0/24"]),
    ("TEST_API_CREATE_4","IPv6",["::1"]),
    ("TEST_API_CREATE_5","IPv6",["::1/128"]),
])
def test_create(adm_sc, name, format_ip, allowed_ips):
    repo = adm_sc.repositories.create(
        name=name, 
        format=format_ip, 
        allowed_ips=allowed_ips
    )
    time.sleep(2)
    adm_sc.repositories.delete(repo['id'])
    assert int(repo['id']) > 0
    assert repo['name'] == name

def test_delete(adm_sc):
    repo = adm_sc.repositories.create(
        name="TEST_API_DELETE", 
        format="IPv4", 
        allowed_ips=["127.0.0.1"]
    )
    adm_sc.repositories.delete(repo['id'])
    with pytest.raises(Exception) as e:
        adm_sc.repositories.get(repo['id'])
    assert 403 == e.value.code
    assert "Unable to get Repository" in e.value.msg


def test_update(adm_sc):
    repo = adm_sc.repositories.create(
        name="TEST_API_DELETE", 
        format="IPv4", 
        allowed_ips=["127.0.0.1"]
    )
    new_name = "TEST_API_UPDATE"
    repo_upd = adm_sc.repositories.update(id=repo['id'], name=new_name)
    adm_sc.repositories.delete(repo['id'])

    assert repo_upd['name'] == new_name

