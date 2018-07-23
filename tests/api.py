#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import json
import urllib3

# uuid = 731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65 (basic network scan) -->r = requests.request('GET','https://10.139.90.81:8834/editor/scan/temp$
# uuid: se puede ver en: https://10.139.90.81:8834/api#/resources/editor/list
# policy_id = 4 (basic network scan) --> r = requests.request('GET','https://10.139.90.81:8834/policies',verify=False, headers=headers)
# folder_id = 1270 (Trigo_ARGOS) ------> r = requests.request('GET','https://10.139.90.81:8834/folders',verify=False, headers=headers)
# scanner_id = 1 ----------------------> r = requests.request('GET','https://10.139.90.81:8834/scanners',verify=False, headers=headers)

# 0. Eliminamos los mensajes de warning por utilizar el verify a False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 1. Gestion de claves:

api_akey = '398c4425241ac5ff00355294e6b7183d2a65f506617cd7f865e77cfea9dbf0e2'
api_skey = '5f75e1c29c422d25aceade6ea0197e7ebaa81cb89f1ba67c77143aa2bc083025'

headers = {'X-ApiKeys': 'accessKey=' + api_akey + '; secretKey=' + api_skey}
headers.update({'Content-type': 'application/json; charset=utf-8','Accept': 'text/plain'})

# 2. Creamos el scan:

try:
        payload = {"uuid": "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65", "settings":
        {"name":"Prueba_ARGOS",
        "description":"Esto es una pruebita",
        "policy_id":4,
        "folder_id":1270,
        "scanner_id":1,
        "enabled":"true",
        "launch":"ON_DEMAND",
        "text_targets":"10.228.84.74",
        "emails":"atrigom@mapfre.com"}}
        r = requests.post('https://10.139.90.81:8834/scans', data=json.dumps(payload), verify=False, headers=headers)
        if r.status_code != 200:
                print ('[-] Invalid credentials or problems with Nessus server connection.')
                print('[-] ' + str(r.status_code), str(r.reason))
        else:

# 3. Recuperamos el ID del nuevo scan:
                json_data = json.loads(r.text)
                # El id del scan esta en un diccionario metido dentro de otro diccionario:
                id_scan = json_data['scan']
                id_scan = id_scan['id']
                print('[+] Scan created with ID ' + str(id_scan) + '. Lauching scan...')

# 4. Lanzamos el escaneo:
                url = 'https://10.139.90.81:8834/scans/' + str(id_scan) + '/launch'
                r = requests.post(url, verify=False, headers=headers)
                #r = requests.post('https://10.139.90.81:8834/1321312312312/launch', verify=False, headers=headers)
                if r.status_code != 200:
                        print('[-] Error: ' + str(r.status_code), str(r.reason))
                        print('[-] Trying to deleting scan configured...')
                        # Borramos el escaner:
                        r = requests.delete('https://10.139.90.81:8834/scans/' + str(id_scan), verify=False, headers=headers)
                        if r.status_code != 200:
                                print('[-] Delete process failed. Manually deletion required for the scan with ID ' + str(id_scan))
                        else:
                                print('[+] Scan deleted.')
                else:
                        print('[+] Scan launched successfully!!')

except requests.exceptions.SSLError as ssl_error:
        print('%s for %s.' % (ssl_error, 'https://10.139.90.81:8834/'))