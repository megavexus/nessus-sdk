import click
import configparser
import codecs
import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
from time import gmtime, strftime
from NessusSDK import NessusSDK


@click.command()
@click.option('--folder_id', '-f', help="Id of the folder to stop")
#@click.option('--config_file', '-c', default="", type=(str), help="Config file with the nessus info")
def stop_scan(folder_id):
    scanner = getScanner()

    scan_list = scanner.scan_list_from_folder(folder_id)
    actual_time = strftime("%d/%m/%Y %H:%M:%S", gmtime())
    print("[{}] Checking the folder {} with #{} scans:".format(
        actual_time, folder_id, len(scan_list)))

    for scan in scan_list:
        if str(scan[u'status']) == "running":
            print("  - [!] Running Scan [#{}] {}. Pausing...".format(
                scan[u'id'], scan[u'name']))
            scanner.scan_pause(scan[u'id'])
            print("  ....SCAN PAUSED")
        else:
            print("  - Scan [#{}] {}: STATUS = {} {}".format(
                scan[u'status'], scan[u'id'], scan[u'name'], scan))

    print("-----")

def setProxy(host):
    no_proxy = os.environ.get('NO_PROXY', '')

    if no_proxy == '':
        no_proxy = "127.0.0.1,localhost,%s" % host
    elif host not in no_proxy:
        no_proxy += ",%s" % host

    os.environ['NO_PROXY'] = no_proxy
    os.environ['HTTP_PROXY'] = ''
    os.environ['HTTPS_PROXY'] = ''

def getScanner(config_file=""):
    if config_file == '':
        config_file = os.path.join(myPath, 'config', 'nessus.ini')

    config = configparser.ConfigParser()
    config.readfp(codecs.open(config_file, "r"))

    setProxy("10.139.90.81")
    host = config['nessus'].get('url', 'https://127.0.0.1:8834')
    login = config['nessus'].get('login', 'admin')
    password = config['nessus'].get('password', '1234')
    insecure = config['nessus'].get('insecure', 'true') in ['true', 'TRUE', 1, '1']
    scanner = NessusSDK(
        url=host, 
        login=login, 
        password=password,
        insecure=insecure, 
        bypass_proxy=True
    )
    return scanner


if __name__ == "__main__":
    stop_scan()
