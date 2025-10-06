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
# - Decrypt the ./payload/encrypted_base64_payload.txt content with CipherTrust Manager using the private key of an RSA keypair stored in CTM
# - Store the decrypted content in ./payload/unencrypted_payload.txt

import os
import requests
import urllib3
import config
import base64
import json

# Load configuration from config.py
SECRETS_DIR = config.SECRETS_DIR
PAYLOAD_DIR = config.PAYLOAD_DIR
RSA_PRIVKEY_ID_FILE = config.RSA_PRIVKEY_ID_FILE
ENCRYPTED_PAYLOAD_FILE = config.ENCRYPTED_PAYLOAD_FILE
UNENCRYPTED_PAYLOAD_FILE = config.UNENCRYPTED_PAYLOAD_FILE
CM_HOST = config.CTM_HOST
CM_USERNAME = config.CTM_USER
CM_PASSWORD = config.CTM_PASSWORD
AUTH_ENDPOINT = config.CTM_AUTH_ENDPOINT
DECRYPT_ENDPOINT = config.CTM_DECRYPT_ENDPOINT

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

# --- Function to decrypt with CTM ---
def decrypt_with_ctm(bearer_token, key_id, ciphertext):
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = {
        "id": key_id,
        "ciphertext": ciphertext,
        "type": "id",
        "version": 0,
        "pad": "OAEP256" #Valid values for asymmetric algorithms, the valid values are PKCS1, OAEP, OAEP256, OAEP384, and OAEP512. The default is OAEP. See https://thalesdocs.com/ctp/cm/latest/reference/cckmapi/ora-ext-apis/ora-ext-invoked-apis/ora-ext-encrypt-data/index.html
    }

    urllib3.disable_warnings()
    response = requests.post(DECRYPT_ENDPOINT, headers=headers, json=payload, verify=False)
    response.raise_for_status()

    plaintext = response.json().get('plaintext')
    if not plaintext:
        raise Exception("Plaintext not found in response.")
    return plaintext

# --- File operations ---
def load_file(filename):
    with open(filename, 'r') as f:
        return f.read()

def save_file(filename, data):
    if not os.path.exists(SECRETS_DIR):
        os.makedirs(SECRETS_DIR)

    with open(filename, 'w') as f:
        f.write(data)
    print(f"Saved {filename}")

# --- Main process ---
def main():
    # Step 1: Get the token
    print("Step 1: Authentication to CipherTrust Manager")
    bearer_token = authenticate_and_get_token(CM_USERNAME, CM_PASSWORD)
    if not bearer_token:
        print("Failed to obtain bearer token. Exiting.")
        return
    
    print("Bearer token obtained.")

    # Step 2: Read RSA key ID
    print("Step 2: Reading RSA private key ID...")
    rsa_key_id = load_file(RSA_PRIVKEY_ID_FILE)
    if not rsa_key_id:
        print(f"Error: RSA private key ID file '{RSA_PRIVKEY_ID_FILE}' is empty or not found.")
        return
    
    print(f"Using RSA Private Key ID: {rsa_key_id}")

    # Step 3: Load encrypted payload
    print("Step 3: Loading encrypted payload...")
    encrypted_payload = load_file(ENCRYPTED_PAYLOAD_FILE)
    if not encrypted_payload:
        print(f"Error: Encrypted payload file '{ENCRYPTED_PAYLOAD_FILE}' is empty or not found.")
        return
    
    print("Encrypted payload loaded.")

    # Step 4: Decrypt using CipherTrust Manager
    print("Step 4: Decrypting payload with CipherTrust Manager")
    decrypted_base64_payload = decrypt_with_ctm(bearer_token, rsa_key_id, encrypted_payload)
    if not decrypted_base64_payload:
        print("Decryption failed. Exiting.")
        return
    
    print("Payload decrypted.")

    # Step 5: Decode base64 to get original payload
    print("Step 5: Decoding base64 decrypted payload...")
    decrypted_payload = base64.b64decode(decrypted_base64_payload)
    if not decrypted_payload:
        print("Base64 decoding failed. Exiting.")
        return
    
    print("Base64 decoding successful.")

    # Step 6: Store decrypted files
    print("Step 6: Storing decrypted payload...")
    if not os.path.exists(PAYLOAD_DIR):
        os.makedirs(PAYLOAD_DIR)
    
    with open(UNENCRYPTED_PAYLOAD_FILE, 'wb') as f:
        f.write(decrypted_payload)
    print(f"Saved {UNENCRYPTED_PAYLOAD_FILE}")

    print(f"Decrypted payload stored successfully in {UNENCRYPTED_PAYLOAD_FILE}")

# --- Main process ---
if __name__ == "__main__":
    main()