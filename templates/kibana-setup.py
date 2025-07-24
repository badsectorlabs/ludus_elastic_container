import requests
import json
import os
import urllib3
import socket

# Quiet the noise
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load .env file and extract some variables
with open('.env', 'r') as file:
    for line in file:
        if 'ELASTIC_PASSWORD' in line:
            ELASTIC_PASSWORD = line.split('=')[1].strip()
        if 'STACK_VERSION' in line:
            STACK_VERSION = line.split('=')[1].strip()

ELASTIC_USER = 'elastic'
KIBANA_URL = 'https://localhost:5601'
ELASTIC_SERVER = "{{ elastic_host }}"
FLEET_SERVER_URL = "https://" + ELASTIC_SERVER + ":8220"
ELASTISEARCH_URL = "https://" + ELASTIC_SERVER + ":9200"

ELASTIC_ENDPOINT_VERSION = '8.12.0'
ELASTIC_WINDOWS_VERSION = '1.44.4'

def get_enrollment_token():
    # Define the URL for the Fleet's enrollment API
    url = f"{KIBANA_URL}{{ kibana_enrollment_endpoint }}"

    # Define the headers for the request
    headers = {
        "Content-Type": "application/json",
        'kbn-xsrf': 'true'
    }

    # Send the GET request
    try:
        response = requests.get(url, headers=headers, auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        print("Http Error:",errh)
        return None
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:",errc)
        return None
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:",errt)
        return None
    except requests.exceptions.RequestException as err:
        print("Something went wrong",err)
        return None

    # Check the response
    if response.status_code == 200:
        print("Enrollment token retrieved successfully.")
        data = response.json()
        # Assuming the first key is the one we want
        if data and 'items' in data and len(data['items']) > 0:
            return data['items'][0]['api_key']
        else:
            print("No enrollment token found.")
            return None
    else:
        print(f"Failed to retrieve enrollment token. Status code: {response.status_code}, Response: {response.text}")
        return None

def get_fleet_server_hosts():
    # Define the URL for the Fleet Server API
    url = f"{KIBANA_URL}/api/fleet/fleet_server_hosts"

    # Send the GET request
    try:
        response = requests.get(url, verify=False, auth=(ELASTIC_USER, ELASTIC_PASSWORD))
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
        return None
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
        return None
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
        return None
    except requests.exceptions.RequestException as err:
        print ("Something went wrong",err)
        return None

    # Check the response
    if response.status_code == 200:
        print("Fleet Server hosts retrieved successfully.")
        return response.json()
    else:
        print(f"Failed to retrieve Fleet Server hosts. Status code: {response.status_code}, Response: {response.text}")
        return None

def create_fleet_server_host():
    # Define the URL for the Fleet Server API
    url = f"{KIBANA_URL}/api/fleet/fleet_server_hosts"

    # Define the headers for the request
    headers = {
        "Content-Type": "application/json",
        'kbn-xsrf': 'true'
    }

    # Define the body of the request
    data = {
            "name": "fleet-server-1",
            "host_urls": [f"{FLEET_SERVER_URL}"],
            "is_default": True,
    }

    # Send the POST request
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        print("Http Error:",errh)
        print("Response content:", response.content)
        return None
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:",errc)
        return None
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:",errt)
        return None
    except requests.exceptions.RequestException as err:
        print("Something went wrong",err)
        return None

    # Check the response
    if response.status_code == 200:
        print("Fleet Server host created successfully.")
        return response.json()
    else:
        print(f"Failed to create Fleet Server host. Status code: {response.status_code}, Response: {response.text}")
        return None

def add_fleet_output(new_host):
    # Define the URL for the Fleet Server API
    url = f"{KIBANA_URL}/api/fleet/outputs"

    # Define the headers for the request
    headers = {
        "Content-Type": "application/json",
        'kbn-xsrf': 'true'
    }

    # Get the current output
    try:
        response = requests.get(url, headers=headers, auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("Something went wrong",err)
        return None

    # Check the response
    if response.status_code != 200:
        print(f"Failed to get the output. Status code: {response.status_code}, Response: {response.text}")
        return None

    output = response.json()

    # Add the new host to the hosts field
    output['items'][0]['hosts'] = new_host

    # Define the URL for the PUT request, including the output ID
    url = f"{KIBANA_URL}/api/fleet/outputs/{output['items'][0]['id']}"

    # Prepare the data for the PUT request
    data = {
        "name": output['items'][0]['name'],
        "type": output['items'][0]['type'],
        "hosts": output['items'][0]['hosts']
    }

    # Send the PUT request to update the output
    try:
        response = requests.put(url, headers=headers, data=json.dumps(data), auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("Something went wrong",err)
        return None

    # Check the response
    if response.status_code == 200:
        print("Default output modified successfully.")
        return response.json()
    else:
        print(f"Failed to modify default output. Status code: {response.status_code}, Response: {response.text}")
        return None

def get_policy_by_integration_id():
    url = f'{KIBANA_URL}/api/fleet/package_policies'
    headers = {
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'kbn-xsrf': 'true',
    }

    try:
        response = requests.get(url, headers=headers, auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
        response.raise_for_status()  # Raises a HTTPError if the response status is 4xx, 5xx
        return response.json()

    except requests.exceptions.HTTPError as errh:
        print("Http Error:", errh)
        print("Response content:", response.content)
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print("Something went wrong", err)
        print("Request details:", err.request)

def post_agent_policy():
    url = f'{KIBANA_URL}/api/fleet/agent_policies?sys_monitoring=true'
    headers = {
        'Accept': '*/*',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'kbn-xsrf': 'true', # Required for POST requests
    }
    data = {
        "name": "Ludus-Agent-Policy",
        "description": "",
        "namespace": "default",
        "monitoring_enabled": ["logs", "metrics"],
        "inactivity_timeout": 172800,
        "is_protected": False,
    }

    try:
        response = requests.post(url, headers=headers, json=data, auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as err:
        print(f"Error posting agent policy: {err}")
        if hasattr(err, 'response'):
            print(f"Response content: {err.response.content}")
        return None

def add_windows_integration(policy_id, package_version):
    url = f'{KIBANA_URL}/api/fleet/package_policies'
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'kbn-xsrf': 'true',
    }
    data = {
        "package": {
            "name": "windows",
            "version": package_version
        },
        "name": "windows-1",
        "namespace": "default",
        "description": "",
        "policy_id": policy_id,
        "vars": {},
        "inputs": {
            "windows-winlog": {
            "enabled": True,
            "streams": {
                "windows.applocker_exe_and_dll": {
                "enabled": True,
                "vars": {
                    "preserve_original_event": False,
                    "event_id": None,
                    "ignore_older": "72h",
                    "language": 0,
                    "tags": [],
                    "custom": "# Winlog configuration example\n#batch_read_size: 100"
                }
                },
                "windows.applocker_msi_and_script": {
                "enabled": True,
                "vars": {
                    "preserve_original_event": False,
                    "event_id": None,
                    "ignore_older": "72h",
                    "language": 0,
                    "tags": [],
                    "custom": "# Winlog configuration example\n#batch_read_size: 100"
                }
                },
                "windows.applocker_packaged_app_deployment": {
                "enabled": True,
                "vars": {
                    "preserve_original_event": False,
                    "event_id": None,
                    "ignore_older": "72h",
                    "language": 0,
                    "tags": [],
                    "custom": "# Winlog configuration example\n#batch_read_size: 100"
                }
                },
                "windows.applocker_packaged_app_execution": {
                "enabled": True,
                "vars": {
                    "preserve_original_event": False,
                    "event_id": None,
                    "ignore_older": "72h",
                    "language": 0,
                    "tags": [],
                    "custom": "# Winlog configuration example\n#batch_read_size: 100"
                }
                },
                "windows.forwarded": {
                "enabled": True,
                "vars": {
                    "preserve_original_event": False,
                    "ignore_older": "72h",
                    "language": 0,
                    "tags": [
                    "forwarded"
                    ],
                    "custom": "# Winlog configuration example\n#batch_read_size: 100"
                }
                },
                "windows.powershell": {
                "enabled": True,
                "vars": {
                    "preserve_original_event": False,
                    "event_id": "400, 403, 600, 800",
                    "ignore_older": "72h",
                    "language": 0,
                    "tags": [],
                    "custom": "# Winlog configuration example\n#batch_read_size: 100"
                }
                },
                "windows.powershell_operational": {
                "enabled": True,
                "vars": {
                    "preserve_original_event": False,
                    "event_id": "4103, 4104, 4105, 4106",
                    "ignore_older": "72h",
                    "language": 0,
                    "tags": [],
                    "custom": "# Winlog configuration example\n#batch_read_size: 100"
                }
                },
                "windows.sysmon_operational": {
                "enabled": True,
                "vars": {
                    "preserve_original_event": False,
                    "ignore_older": "72h",
                    "language": 0,
                    "tags": [],
                    "custom": "# Winlog configuration example\n#batch_read_size: 100"
                }
                }
            }
            },
            "windows-windows/metrics": {
            "enabled": True,
            "streams": {
                "windows.perfmon": {
                "enabled": True,
                "vars": {
                    "perfmon.group_measurements_by_instance": True,
                    "perfmon.ignore_non_existent_counters": True,
                    "perfmon.refresh_wildcard_counters": True,
                    "perfmon.queries": "- object: 'Process'\n  instance: [\"*\"]\n  counters:\n   - name: '% Processor Time'\n     field: cpu_perc\n     format: \"float\"\n   - name: \"Working Set\"\n",
                    "period": "10s"
                }
                },
                "windows.service": {
                "enabled": True,
                "vars": {
                    "period": "60s"
                }
                }
            }
            },
        }
}

    response = requests.post(url, headers=headers, data=json.dumps(data), auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
    return response

def add_defend_integration(policy_id, package_version):
    url = f'{KIBANA_URL}/api/fleet/package_policies'
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'kbn-xsrf': 'true',
    }
    data = {
        "name": "elastic-defend-1",
        "description": "",
        "namespace": "default",
        "policy_id": policy_id,
        "enabled": True,
        "inputs": [
            {
                "enabled": True,
                "streams": [],
                "type": "ENDPOINT_INTEGRATION_CONFIG",
                "config": {
                    "_config": {
                        "value": {
                            "type": "endpoint",
                            "endpointConfig": {
                                "preset": "EDRComplete"
                            }
                        }
                    }
                }
            }
        ],
        "package": {
            "name": "endpoint",
            "title": "Elastic Defend",
            "version": package_version
        }
    }

    try:
        response = requests.post(url, headers=headers, json=data, auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as err:
        print(f"Error adding Defend integration: {err}")
        return None

def update_defend_integration(integration_id, manifest_data, policy_id, package_version):
    url = f'{KIBANA_URL}/api/fleet/package_policies/{integration_id}'
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'kbn-xsrf': 'true',
    }
    data = {
        "name": "elastic-defend-1",
        "namespace": "default",
        "description": "",
        "policy_id": policy_id,
        "enabled": True,
        "inputs": [
            {
                "type": "endpoint",
                "enabled": True,
                "streams": [],
                "config": {
                    "integration_config": {
                        "value": {
                            "type": "endpoint",
                            "endpointConfig": {
                                "preset": "EDRComplete"
                            }
                        }
                    },
                    "artifact_manifest": manifest_data ,
                    "policy": {
                        "value": {
                            "windows": {
                                "events": {
                                    "credential_access": True,
                                    "dll_and_driver_load": True,
                                    "dns": True,
                                    "file": True,
                                    "network": True,
                                    "process": True,
                                    "registry": True,
                                    "security": True
                                },
                                "malware": {
                                    "mode": "detect",
                                    "blocklist": False
                                },
                                "ransomware": {
                                    "mode": "detect",
                                    "supported": True
                                },
                                "memory_protection": {
                                    "mode": "detect",
                                    "supported": True
                                },
                                "behavior_protection": {
                                    "mode": "detect",
                                    "reputation_service": True,
                                    "supported": True
                                },
                                "popup": {
                                    "malware": {
                                        "message": "Ludus - malware protection",
                                        "enabled": True
                                    },
                                    "ransomware": {
                                        "message": "Ludus - ransomware protection",
                                        "enabled": True
                                    },
                                    "memory_protection": {
                                        "message": "Ludus - memory protection",
                                        "enabled": True
                                    },
                                    "behavior_protection": {
                                        "message": "Ludus - behavior protection",
                                        "enabled": True
                                    }
                                },
                                "logging": {
                                    "file": "info"
                                },
                                "antivirus_registration": {
                                    "enabled": True
                                },
                                "attack_surface_reduction": {
                                    "credential_hardening": {
                                        "enabled": False
                                    }
                                }
                            },
                            "mac": {
                                "events": {
                                    "process": True,
                                    "file": True,
                                    "network": True
                                },
                                "malware": {
                                    "mode": "detect",
                                    "blocklist": True
                                },
                                "behavior_protection": {
                                    "mode": "detect",
                                    "reputation_service": False,
                                    "supported": True
                                },
                                "memory_protection": {
                                    "mode": "detect",
                                    "supported": True
                                },
                                "popup": {
                                    "malware": {
                                        "message": "Ludus - Malware protection",
                                        "enabled": True
                                    },
                                    "behavior_protection": {
                                        "message": "Ludus - Behavior protection",
                                        "enabled": True
                                    },
                                    "memory_protection": {
                                        "message": "Ludus - Memory protection",
                                        "enabled": True
                                    }
                                },
                                "logging": {
                                    "file": "info"
                                },
                                "advanced": {
                                    "capture_env_vars": "DYLD_INSERT_LIBRARIES,DYLD_FRAMEWORK_PATH,DYLD_LIBRARY_PATH,LD_PRELOAD"
                                }
                            },
                            "linux": {
                                "events": {
                                    "process": True,
                                    "file": True,
                                    "network": True,
                                    "session_data": True,
                                    "tty_io": False
                                },
                                "malware": {
                                    "mode": "detect",
                                    "blocklist": True
                                },
                                "behavior_protection": {
                                    "mode": "detect",
                                    "reputation_service": False,
                                    "supported": True
                                },
                                "memory_protection": {
                                    "mode": "detect",
                                    "supported": True
                                },
                                "popup": {
                                    "malware": {
                                        "message": "Ludus - Malware protection",
                                        "enabled": False
                                    },
                                    "behavior_protection": {
                                        "message": "Ludus - Behavior protection",
                                        "enabled": False
                                    },
                                    "memory_protection": {
                                        "message": "Ludus - Memory protection",
                                        "enabled": False
                                    }
                                },
                                "logging": {
                                    "file": "info"
                                },
                                "advanced": {
                                    "capture_env_vars": "LD_PRELOAD,LD_LIBRARY_PATH"
                                }
                            }
                        }
                    }
                }
            }
        ],
        "package": {
            "name": "endpoint",
            "title": "Elastic Defend",
            "version": package_version
        }
    }

    try:
        response = requests.put(url, headers=headers, json=data, auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as err:
        print(f"Error adding Defend integration: {err}")
        return None

def load_prebuilt_rules():
    url = f'{KIBANA_URL}/api/detection_engine/rules/prepackaged'
    headers = {
        'kbn-xsrf': 'true',  # Required for PUT requests
    }

    try:
        response = requests.put(url, headers=headers, auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify=False)
        response.raise_for_status()  # Raises a HTTPError if the response status is 4xx, 5xx
        return response.json()

    except requests.exceptions.HTTPError as errh:
        print("Http Error:", errh)
        print("Response content:", response.content)
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print("Something went wrong", err)
        print("Request details:", err.request)

if __name__ == "__main__":
    agent_policy_res = post_agent_policy()
    if agent_policy_res is None:
        print("Failed to create agent policy.")
        exit(1)

    print("Agent Policy Response:", json.dumps(agent_policy_res, indent=2))

    if 'item' not in agent_policy_res:
        print("Unexpected response structure from post_agent_policy()")
        exit(1)

    policy_name = agent_policy_res['item']['name']
    print(f'Agent Policy Created: {policy_name}')
    
    agent_policy_id = agent_policy_res['item']['id']
    
    integration_res = add_defend_integration(agent_policy_id, ELASTIC_ENDPOINT_VERSION)
    if integration_res is None:
        print("Failed to add Defend integration.")
        exit(1)
    print(f'Defend Integration Created: {integration_res.status_code}')

    integration_res = integration_res.json()
    defend_id = integration_res['item']['id']
    manifest_data = integration_res['item']['inputs'][0]['config']['artifact_manifest']
    update_defend = update_defend_integration(defend_id, manifest_data, agent_policy_id, ELASTIC_ENDPOINT_VERSION)
    if update_defend is None:
        print("Failed to update Defend integration.")
        exit(1)
    print(f'Defend Integration Updated: {update_defend.status_code}')
    
    windows_response = add_windows_integration(agent_policy_id, ELASTIC_WINDOWS_VERSION)
    if windows_response is None:
        print("Failed to add Windows integration.")
        exit(1)
    print(f'Windows Integration Created: {windows_response.status_code}')

    fleet_server_host = create_fleet_server_host()
    if fleet_server_host is None:
        print("Failed to create Fleet Server host.")
        exit(1)
    print(f'Fleet Server Host Created: {fleet_server_host}')

    enrollment_token = get_enrollment_token()
    if enrollment_token is None:
        print("Failed to get enrollment token.")
        exit(1)
    print(f'Enrollment Token: {enrollment_token}')

    with open('enrollment_token.txt', 'w') as f:
        f.write(enrollment_token)

    

    
