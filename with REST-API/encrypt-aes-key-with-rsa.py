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
# - Retrieve the public RSA key from CipherTrust Manager using REST API
# - Encrypt the AES key and IV files created in previous step with this RSA public key
# - Store the encrypted AES key and IV files in the 'secrets' directory

import os
import requests
import urllib3
import config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# --- Configuration (see config.py) ---
SECRETS_DIR = config.SECRETS_DIR
RSA_KEY_ID_FILE = config.RSA_KEY_ID_FILE
AES_KEY_FILE = config.AES_KEY_FILE
IV_FILE = config.IV_FILE
ENC_AES_KEY_FILE = config.ENC_AES_KEY_FILE
ENC_IV_FILE = config.ENC_IV_FILE

CM_HOST = config.CTM_HOST
CM_USERNAME = config.CTM_USER
CM_PASSWORD = config.CTM_PASSWORD
AUTH_ENDPOINT = config.CTM_AUTH_ENDPOINT
KEY_EXPORT_ENDPOINT = config.CTM_KEY_EXPORT_ENDPOINT

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

# --- Function to get RSA public key ---
def get_rsa_public_key(bearer_token, key_id):
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json"
    }
    url = KEY_EXPORT_ENDPOINT.format(key_id=key_id)

    urllib3.disable_warnings()
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    pubkey_pem = response.json().get('publickey')

    if not pubkey_pem:
        raise Exception("Public key not found in response.")
    return pubkey_pem.encode()

def load_file(filename):
    if not os.path.exists(SECRETS_DIR):
        os.makedirs(SECRETS_DIR)

    with open(os.path.join(SECRETS_DIR, filename), 'rb') as f:
        return f.read()

def save_file(filename, data):
    if not os.path.exists(SECRETS_DIR):
        os.makedirs(SECRETS_DIR)

    with open(os.path.join(SECRETS_DIR, filename), 'wb') as f:
        f.write(data)
    print(f"Saved {filename} in {SECRETS_DIR}")

def main():
    # Step 1: Get the token
    bearer_token = authenticate_and_get_token(CM_USERNAME, CM_PASSWORD)
    if not bearer_token:
        print("Failed to obtain bearer token. Exiting.")
        return

    # Step 2: Read RSA key ID
    with open(os.path.join(SECRETS_DIR, RSA_KEY_ID_FILE), 'r') as f:
        rsa_key_id = f.read().strip()

    print(f"Using RSA Key ID: {rsa_key_id}")
    if not rsa_key_id:
        print("RSA Key ID is empty. Exiting.")
        return 

    # Step 3: Get public RSA key
    pubkey_pem = get_rsa_public_key(bearer_token, rsa_key_id)
    public_key = serialization.load_pem_public_key(pubkey_pem)

    # Step 4: Load AES key and IV
    aes_key = load_file(AES_KEY_FILE)
    iv = load_file(IV_FILE)

    # Step 5: Encrypt AES key and IV
    enc_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    enc_iv = public_key.encrypt(
        iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Step 6: Store encrypted files
    save_file(ENC_AES_KEY_FILE, enc_aes_key)
    save_file(ENC_IV_FILE, enc_iv)

if __name__ == "__main__":
    main()