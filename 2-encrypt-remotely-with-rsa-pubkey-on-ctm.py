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
# - Encrypt the content of the ./payload/clear_payload.txt content remotely on CipherTrust Manager using public RSA key ID (Key material is stored in CTM)
# - Store the encrypted content in ./payload/encrypted_base64_payload.txt

import os
import requests
import urllib3
import config
import base64

# --- Configuration (see config.py) ---
SECRETS_DIR = config.SECRETS_DIR
PAYLOAD_DIR = config.PAYLOAD_DIR
RSA_PUBKEY_ID_FILE = config.RSA_PUBKEY_ID_FILE
CLEAR_PAYLOAD_FILE = config.CLEAR_PAYLOAD_FILE
ENCRYPTED_PAYLOAD_FILE = config.ENCRYPTED_PAYLOAD_FILE

CM_HOST = config.CTM_HOST
CM_USERNAME = config.CTM_USER
CM_PASSWORD = config.CTM_PASSWORD
AUTH_ENDPOINT = config.CTM_AUTH_ENDPOINT
KEY_EXPORT_ENDPOINT = config.CTM_KEY_EXPORT_ENDPOINT
ENCRYPT_ENDPOINT = config.CTM_ENCRYPT_ENDPOINT

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

# --- Function to encrypt data using CipherTrust Manager ---
def encrypt_with_ctm(bearer_token, cleartext, rsa_key_id):
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Accept": "application/json"
    }

    # Create JSON structure
    plaintext_b64 = base64.b64encode(cleartext).decode('utf-8')
    # Be sure to use a consistent padding scheme between encrypt and decrypt
    full_query = {
        "id": rsa_key_id,
        "plaintext": plaintext_b64,
        "pad": "OAEP256" #Valid values for asymmetric algorithms, the valid values are PKCS1, OAEP, OAEP256, OAEP384, and OAEP512. The default is OAEP. See https://thalesdocs.com/ctp/cm/latest/reference/cckmapi/ora-ext-apis/ora-ext-invoked-apis/ora-ext-encrypt-data/index.html
    }

    urllib3.disable_warnings()
    response = requests.post(ENCRYPT_ENDPOINT, headers=headers, json=full_query, verify=False)
    response.raise_for_status()

    if not response.json().get("ciphertext"):
        raise Exception("Ciphertext not found in response.")

    return response.json().get("ciphertext")

# --- File operations ---
def load_file(filename):
    with open(filename, 'r') as f:
        return f.read()

def save_file(filename, data):
    if not os.path.exists(SECRETS_DIR):
        os.makedirs(SECRETS_DIR)
    
    if not os.path.exists(PAYLOAD_DIR):
        os.makedirs(PAYLOAD_DIR)

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
    print("Step 2: Reading RSA Key ID...")
    rsa_key_id = load_file(RSA_PUBKEY_ID_FILE)
    if not rsa_key_id:
        print("RSA Key ID is empty. Exiting.")
        return
    
    print(f"Using RSA Key ID: {rsa_key_id}")

    # Step 3: Load the clear payload content
    print("Step 4: Loading clear payload...")
    clear_payload = load_file(CLEAR_PAYLOAD_FILE).encode("utf-8")
    if not clear_payload:
        print("Payload empty. Exiting.")
        return
    
    print("Clear payload loaded.")

    # Step 4: Encrypt using CipherTrust Manager
    print("Step 5: Encrypting payload with RSA public key on CipherTrust Manager...")
    encrypted_payload_response = encrypt_with_ctm(bearer_token, clear_payload, rsa_key_id)
    if not encrypted_payload_response:
        print("Encryption failed. Exiting.")
        return
    
    print("Payload encrypted.")

    # Step 5: Store encrypted files
    print("Step 5: Storing encrypted payload...")
    save_file(ENCRYPTED_PAYLOAD_FILE, encrypted_payload_response)
    print(f"Encrypted payload stored successfully in {ENCRYPTED_PAYLOAD_FILE}")

# --- Main execution ---
if __name__ == "__main__":
    main()