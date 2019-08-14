from sc_sdk.api import SCApi


class Repositories(object):
    def __init__(self, sc_api:SCApi):
        self.api = sc_api

    def list(self, name=None, fields=None):
        params = dict()
        if fields:
            params['fields'] = ','.join([f for f in fields])
        else:
            params['fields'] = "name,description,type,dataFormat,vulnCount,remoteID,remoteIP,running,enableTrending,downloadFormat,lastSyncTime,lastVulnUpdate,createdTime,modifiedTime,organizations,correlation,nessusSchedule,ipRange,ipCount,runningNessus,lastGenerateNessusTime,running,transfer,deviceCount,typeFields"
        repos = self.api.get('repository', params=params).json()['response']
        return repos

    def get(self, id):
        return self.api.repositories.details(id)

    def create(self, name, **kwargs):
        allowed_params = [
            "allowed_ips", "description", "format", "fulltext_search", 
            "lce_correlation", "nessus_sched", "mobile_sched", "orgs", 
            "preferences", "remote_ip", "remote_repo", "remote_sched", 
            "repo_type", "scanner_id", "trending", 
        ]
        if "allowed_ips" in kwargs and type(kwargs['allowed_ips']) == str:
            kwargs['allowed_ips'] = kwargs['allowed_ips'].split(",")
            
        self.api._check_kwargs(allowed_params, **kwargs)

        repo = self.api.repositories.create(name=name, **kwargs)
        return repo

    def update(self, id, **kwargs):
        allowed_params = [
            "allowed_ips", "description", "lce_correlation", "name", 
            "nessus_sched", "mobile_sched", "orgs", "preferences", 
            "remote_ip", "remote_repo", "remote_sched", 
            "scanner_id", "trending", 
        ]
        self.api._check_kwargs(allowed_params, **kwargs)
        repo = self.api.repositories.edit(id, **kwargs)
        return repo
        
    def delete(self, id):
        return self.api.repositories.delete(id)


"""
name
description
type
dataFormat
vulnCount
remoteID
remoteIP
running
enableTrending
downloadFormat
lastSyncTime
lastVulnUpdate
createdTime
modifiedTime
organizations
correlation
nessusSchedule
ipRange
ipCount
runningNessus
lastGenerateNessusTime
running
transfer
deviceCount
typeFields
"""