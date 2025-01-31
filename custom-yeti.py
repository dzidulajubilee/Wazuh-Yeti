#!/usr/bin/env python3
import sys
import json
import requests
import logging

# Set up logging
logging.basicConfig(filename='/var/ossec/logs/custom-yeti.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s: %(message)s')

# Hardcoded Yeti API key and host details
YETI_API_KEY = "b177--------a10c----------------54248f9--3a75"
YETI_HOST = "http://192.168.10.131:8000"
YETI_AUTH_URL = f"{YETI_HOST}/api/v2/auth/api-token"
YETI_IMPORT_URL = f"{YETI_HOST}/api/v2/observables/import/text"

try:
    # Log the arguments passed to the script
    logging.debug(f"Arguments received: {sys.argv}")

    # Check if the alert file path is provided
    if len(sys.argv) < 2:
        logging.error("Missing alert file path argument.")
        sys.exit(1)

    # Read the alert file
    alert_file_path = sys.argv[1]
    logging.debug(f"Reading alert file: {alert_file_path}")
    with open(alert_file_path) as alert_file:
        alert_json = json.load(alert_file)

    # Log the alert JSON
    logging.debug(f"Alert JSON: {json.dumps(alert_json, indent=2)}")

    # Extract relevant fields from the alert
    alert_level = alert_json['rule']['level']
    rule_id = alert_json['rule']['id']
    description = alert_json['rule']['description']
    agent_id = alert_json['agent']['id']
    agent_name = alert_json['agent']['name']

    # Extract observables (e.g., IPs, hashes, etc.) from the alert
    observables = []
    if 'data' in alert_json:
        observables.append(alert_json['data'])  # Add relevant data as observables

    # Prepare the payload for Yeti
    payload = {
        "text": "\n".join(observables),  # One observable per line
        "tags": ["wazuh", f"rule_{rule_id}", f"level_{alert_level}"]
    }

    # Log the payload
    logging.debug(f"Payload: {json.dumps(payload, indent=2)}")

    # Authenticate with Yeti and get an access token
    auth_response = requests.post(
        YETI_AUTH_URL,
        headers={"x-yeti-apikey": YETI_API_KEY},
    )
    if auth_response.status_code != 200:
        logging.error(f"Failed to authenticate with Yeti: {auth_response.status_code} - {auth_response.text}")
        sys.exit(1)

    access_token = auth_response.json().get("access_token")
    if not access_token:
        logging.error("Failed to retrieve access token from Yeti.")
        sys.exit(1)

    # Send observables to Yeti
    response = requests.post(
        YETI_IMPORT_URL,
        json=payload,
        headers={"authorization": f"Bearer {access_token}"}
    )

    # Log the response from Yeti
    logging.debug(f"Yeti API Response: {response.status_code} - {response.text}")

    if response.status_code != 200:
        logging.error(f"Failed to send observables to Yeti: {response.status_code} - {response.text}")
        sys.exit(1)

    logging.info("Observables successfully sent to Yeti.")
    sys.exit(0)

except Exception as e:
    logging.error(f"An error occurred: {str(e)}", exc_info=True)
    sys.exit(1)
