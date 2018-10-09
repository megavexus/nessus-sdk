# Nessus Python SDK

Nessus sdk for creating scans, launching, stopping them and retrieving results.

It can also get the diffs betwen two scanners.

## Instalation

To install, we can make it with pip:
```sh
pip install git+https://github.com/megavexus/nessus-sdk.git
```

Or we can clone it, and install manually:
```sh
git clone https://github.com/megavexus/nessus-sdk.git
cd nessus-sdk
pip install .
```

## Manual

### Authentication

- To connect with basic authentication (user and password)
```python
scanner = Scanner(
    url="https://localhost:8834",
    login="admin",
    password="1234"
)
```

- To connect with the nessus api tokens:
```python
scanner = Scanner(
    url="https://localhost:8834",
    api_akey=connection_data['akey'],
    api_skey=connection_data['skey'],
)
```

- Extra options;
    - To connect to a unsecure ssl connection, you have to set to true the parameter `insecure`
```python 
insecure:True
```
    - To connect with a proxy to bypass, you have to set to true the parameter `bypass_proxy` 
```python 
bypass_proxy:True
```

### Creating a new scanner
- By name
```python
targets = "host1,host2"
policy = "basic network scan"
folder_name = "SDK Testing"
name = "Nessus Test SDK"
description = "Nessus Test SDK description"

scan_id = nessus_scanner.scan_create_from_name(name, targets, policy, folder_name, description=description)
```

### Launching a scan
```python
scan_uuid = nessus_scanner.scan_run(scan_id=110)
```

We have also the option to set custom targets:

```python
custom_targets = "host2, host3, host4"
scan_uuid = nessus_scanner.scan_run(scan_id=110, custom_targets=custom_targets)
```


### Getting the metainformation of a scan


```python
scan_info = nessus_scanner.scan_inspect(scan_id=110)
```

We can also use the parameters `scan_uuid` and `scan_name` to select out scan.

- If we only want the status, we can use the function scan_status


```python
scan_status = nessus_scanner.scan_status(scan_id=110)
```

### Stopping and Pausing a scan
- Stopping a Scan:

```python
scan_uuid = nessus_scanner.scan_stop(scan_id=110)
```

- Pausing a scan
```python
scan_uuid = nessus_scanner.scan_stop(scan_id=110)
```

### Retrieving the results

```python
scan_results = nessus_scanner.get_results(scan_id=110)
```

We can also specify the `history_id` or `scan_uuid` of the historic version of the scan to retrieve results

### Getting the diff between two scans


```python
scan_results = nessus_scanner.get_diff(scan_id=110)
```

We can also specify the `diff_uuid` and `history_id` to get the comparative between that two scans, being the `diff_uuid` the primary
