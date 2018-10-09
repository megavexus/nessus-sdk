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

```python
scanner = Scanner(
    url="https://localhost:8834",
    login="admin",
    password="1234"
)
```

```python
scanner = Scanner(
    url="https://localhost:8834",
    api_akey=connection_data['akey'],
    api_skey=connection_data['skey'],
)
```


- To connect to a unsecure ssl connection:

You have to pass the parameter 
```python 
insecure:True
```
- To connect with a proxy to bypass

You have to pass the parameter 
```python 
bypass_proxy:True
```

### Creating a new scanner

### Launching a scan

### Launching a scan with custom targets

### Stopping and Pausing a scan

### Retrieving the results

#### In the events format

### Getting the diff between two scans
