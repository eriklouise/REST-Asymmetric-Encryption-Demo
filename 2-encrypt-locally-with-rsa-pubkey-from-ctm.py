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
# - Encrypt the content of the ./payload/clear_payload.txt content locally using the retrieved RSA public key
# - Store the encrypted content in ./payload/encrypted_base64_payload.txt

import os
import requests
import urllib3
import config
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256 #, SHA1
from cryptography.hazmat.primitives import serialization

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

# --- Function to get RSA public key material ---
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

# --- Function to encrypt locally with RSA public key ---
def encrypt_locally_with_rsa_public_key(public_pem, plaintext):
    key = RSA.importKey(public_pem)
    # Be sure to use a consistent padding scheme between encrypt and decrypt
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256, randfunc=None)
    encrypted_payload_response = cipher.encrypt(plaintext)
    return encrypted_payload_response

# --- Functions to load and save files ---
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
    print(f"Saved {filename} in {SECRETS_DIR}")

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
    with open(RSA_PUBKEY_ID_FILE, 'r') as f:
        rsa_key_id = f.read().strip()

    if not rsa_key_id:
        print("RSA Key ID is empty. Exiting.")
        return 
    
    print(f"Using RSA Key ID: {rsa_key_id}")

    # Step 3: Get public RSA key material from Ciphertrust Manager
    print("Step 3: Retrieving RSA public key from CipherTrust Manager")
    pubkey_pem = get_rsa_public_key(bearer_token, rsa_key_id)
    public_key = serialization.load_pem_public_key(pubkey_pem)

    if not public_key:
        print("Failed to load RSA public key. Exiting.")
        return
    
    print("RSA public key material loaded.")

    # Step 4: Load the clear payload content
    print("Step 4: Loading clear payload...")
    clear_payload = load_file(CLEAR_PAYLOAD_FILE).encode("utf-8")
    if not clear_payload:
        print("Payload empty. Exiting.")
        return
    
    print("Clear payload loaded.")

    # Step 5: Encrypt payload using the RSA public key
    print("Step 5: Encrypting locally the payload with RSA public key...")
    encrypted_payload_response = encrypt_locally_with_rsa_public_key(pubkey_pem, clear_payload)

    if not encrypted_payload_response:
        print("Encryption failed. Exiting.")
        return
    
    print("Payload encrypted.")

    # Step 6: Converting encrypted payload to base64 for storage
    encrypted_payload_b64 = base64.b64encode(encrypted_payload_response).decode('utf-8')
    if not encrypted_payload_b64:
        print("Base64 encoding of encrypted payload failed. Exiting.")
        return
    
    print("Encrypted payload converted to base64.")

    # Step 7: Store encrypted files
    print("Step 7: Storing encrypted payload...")
    save_file(ENCRYPTED_PAYLOAD_FILE, encrypted_payload_b64)
    print(f"Encrypted payload stored successfully in {ENCRYPTED_PAYLOAD_FILE}")

if __name__ == "__main__":
    main()