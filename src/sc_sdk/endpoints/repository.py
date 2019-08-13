from sc_sdk.api import SCApi


class Repositories(object):
    def __init__(self, sc_api:SCApi):
        self.api = sc_api

    def list(self, name=None):
        params = dict()
        if fields:
            params['fields'] = ','.join([self._check('field', f, str) for f in fields])
        self._api.get('repository/', params=params).json()['response']
    # details
    # create
    # edit
    # delete


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