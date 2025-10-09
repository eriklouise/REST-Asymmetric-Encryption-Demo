#*********************************************************************************
#                                                                                *
# This file is part of the "CTM REST Asymmetric key demo" project.               *
# Use it at your own risk                                                        *
# Distributed under Apache 2.0 license                                           *
#                                                                                *
# Written by Erik LOUISE                                                         *
# Copyright © 2025 Thales Group                                                  *
#                                                                                *
#*********************************************************************************

# OBJECTIVE :
# - Create an RSA-4096 asymmetric key in CipherTrust Manager via REST API

import requests
import json
import os
import sys
import config
import urllib3

# --- Configuration (see config.py) ---

# The hostname or IP address of your CipherTrust Manager appliance
CM_HOST = config.CTM_HOST
CM_USERNAME = config.CTM_USER
CM_PASSWORD = config.CTM_PASSWORD

# The ID of the Key Vault (Key Store) where the key will be created
# The name you want to assign to the new key
KEY_NAME = config.ASYM_KEY_NAME
KEY_LENGTH = config.ASYM_KEY_LENGTH
KEY_ALGO = config.ASYM_ALGO

# Directory to store secrets (make sure this directory exists or the script can create it)
SECRETS_DIR = config.SECRETS_DIR
RSA_PUBKEY_ID_FILE = config.RSA_PUBKEY_ID_FILE
RSA_PRIVKEY_ID_FILE = config.RSA_PRIVKEY_ID_FILE

# Cryptographic Usage Mask Calculation (Decimal Value)
USAGE_MASK = config.ASYM_KEY_USAGE_MASK

# --- API Details ---

# Base path for key creation (Standard API endpoint)
AUTH_ENDPOINT = config.CTM_AUTH_ENDPOINT
API_ENDPOINT = config.CTM_API_ENDPOINT

# --- Function get bearer token ---
def authenticate_and_get_token(username, password):
    """
    Authenticates with CipherTrust Manager using username/password to get a Bearer Token.
    Returns the token string or None on failure.
    """
    print("Step 1: Authenticating to get API Token...")
    
    auth_payload = {
        "name": username,
        "password": password
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    try:
        # Disable warnings for self-signed certificates (for demo purposes only)
        urllib3.disable_warnings()

        # NOTE: Use verify=False only for testing with self-signed certificates.
        # In production, use the path to your CA bundle (e.g., verify="/path/to/ca.pem").
        response = requests.post(AUTH_ENDPOINT, headers=headers, json=auth_payload, verify=False)
        response.raise_for_status()

        token_data = response.json()
        token = token_data.get('jwt')
        
        if token:
            print("Authentication successful. Bearer token retrieved.")
            return token
        else:
            print("Authentication failed: Token not found in response.")
            return None

    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error during authentication: {errh}")
        print(f"Response: {response.text}")
        return None
    except requests.exceptions.ConnectionError as errc:
        print(f"Connection Error: Could not reach {CM_HOST}. {errc}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during authentication: {e}")
        return None

# --- Function to Create Key ---
def generate_asymmetric_key(bearer_token):
    """
    Generates an RSA-4096 asymmetric key in CipherTrust Manager via REST API.
    """
    if len(bearer_token) < 1:
        print("ERROR: Please set the CM_API_TOKEN environment variable or update the script.")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "algorithm": KEY_ALGO,
        "size": KEY_LENGTH,
        "format": "raw",
        "name": KEY_NAME,
        "unexportable": False, # This setting is for both public & private keys. For security reasons you should manually set the private key as unexportable via the CM UI after creation.
        "undeletable": False,
        "usageMask": USAGE_MASK
    }
    
    try:
        # Disable warnings for self-signed certificates (for demo purposes only)
        urllib3.disable_warnings()

        # Use verify=False if you are using a self-signed cert, otherwise, use a path to your CA bundle
        response = requests.post(API_ENDPOINT, headers=headers, json=payload, verify=False) 
        response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)

        # Successful response (usually 201 Created or 200 OK)
        key_data = response.json()
        PubKeyId = key_data.get('links')[0].get('targetID')
        PrivKeyId = key_data.get('links')[0].get('sourceID')

        if PubKeyId:
            print(f"Public Key ID: {PubKeyId}")
            # Store the Public Key ID in a file for later use
            store_in_opensecrets(RSA_PUBKEY_ID_FILE, PubKeyId)
        else:
            print("Warning: Public Key ID not found in the response.")

        if PrivKeyId:
            print(f"Private Key ID: {PrivKeyId}")
            # Store the Private Key ID in a file for later use
            store_in_opensecrets(RSA_PRIVKEY_ID_FILE, PrivKeyId)
        else:
            print("Warning: Private Key ID not found in the response.")
        
    except requests.exceptions.HTTPError as errh:
        print(f"\nHTTP Error occurred: {errh}")
        try:
            # Attempt to print error message from CM response body
            error_details = response.json()
            print("Server Error Details:")
            print(json.dumps(error_details, indent=4))
        except json.JSONDecodeError:
            # Handle cases where the response body is not JSON
            print(f"Raw Response Text: {response.text}")
            
    except requests.exceptions.ConnectionError as errc:
        print(f"\nConnection Error: Could not connect to {CM_HOST}. Check hostname and port.")
        print(errc)
        
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

    return True

# --- Function to store data in file ---
def store_in_opensecrets(filename, filecontent):
    if not os.path.exists(SECRETS_DIR):
        os.makedirs(SECRETS_DIR)

    with open(filename, 'w') as file:
        file.write(filecontent)
    print(f"Content successfully written to {filename}")

# --- Execution ---
if __name__ == "__main__":
    # Step 1: Get the token
    print("Step 1: Authentication to CipherTrust Manager")
    bearer_token = authenticate_and_get_token(CM_USERNAME, CM_PASSWORD)
    if not bearer_token:
        print("Failed to obtain bearer token. Exiting.")
        sys.exit(1)
    
    print("Bearer token obtained.")

    # Step 2: Create the key
    print(f"Step 2: Create {KEY_ALGO}-{KEY_LENGTH} Asymmetric Key in CipherTrust Manager")
    result = generate_asymmetric_key(bearer_token)
    if not result:
        print("Key creation failed.")
        sys.exit(1)

    print(f"Key creation process completed. For security reasons you should manually set the private key ({KEY_NAME}) as unexportable via the CM UI after creation.")