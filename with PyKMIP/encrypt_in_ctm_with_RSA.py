#*********************************************************************************
#                                                                                *
# This file is part of the "KMIP Asymmetric key demo" project.                   *
# Use it at your own risk                                                        *
# Distributed under Apache 2.0 license                                           *
#                                                                                *
# Written by Erik LOUISE                                                         *
# Copyright © 2025 Thales Group                                                  *
#                                                                                *
#*********************************************************************************

# OBJECTIVE :
# - This code demonstrates how to query the public key of the asymmetric key pair using KMIP & encrypt a payload with it.

import base64
from kmip.pie import client, objects
from kmip import enums
import PyKMIP.config as config
import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Configuration
WRAPPING_KEY_ID = open(config.PUBLIC_KEYID_FILE, 'r').read().rstrip("\n")   # The ID of the public key in CTM that will be used to encrypt (wrap) the AES key, as the file may contain a newline at the end we remove it
PLAINTEXT_AESGCM_KEY_FILE = config.AES_KEY_FILE                             # The local plaintext AES key file to be encrypted (wrapped)     
WRAPPED_AESGCM_KEY_FILE = config.AES_WRAPPED_KEY_FILE                       # The output file that will contain the encrypted (wrapped) AES key
 
def main():

    # Validate wrapping key id early
    if not WRAPPING_KEY_ID:
        print("Error: wrapping key id is empty. Check PUBLIC_KEYID_FILE contents, you may have to run the create_keypair.py script first.")
        return
    print(f"Using wrapping key id: {repr(WRAPPING_KEY_ID)}")

    # Read the local plaintext key file
    if not os.path.exists(PLAINTEXT_AESGCM_KEY_FILE):
        print(f"Error: Plaintext key file not found at '{PLAINTEXT_AESGCM_KEY_FILE}'.")
        print("Please ensure you have generated this file (e.g., a 32-byte AES key).")
        return
    
    with open(PLAINTEXT_AESGCM_KEY_FILE, 'rb') as f:
        PLAINTEXT_AESGCM_KEY_BYTES = f.read()

    print(f"Read {len(PLAINTEXT_AESGCM_KEY_BYTES)} bytes from '{PLAINTEXT_AESGCM_KEY_FILE}'")

    # Initialize the KMIP client
    print(f"\nConnecting to CTM and fetching wrapping key ID: {WRAPPING_KEY_ID}...")
    kmip_client = None
    try:
        kmip_client = client.ProxyKmipClient(
            hostname=config.KMIP_HOST,
            port=config.KMIP_PORT,
            cert=config.CLIENT_CERT,
            key=config.CLIENT_KEY,
            ca=config.CA_CERT
        )

        with kmip_client:
            #public_key = kmip_client.get(
            #    uid=WRAPPING_KEY_ID,
            #    key_wrapping_specification={
            #        'wrapping_method': enums.WrappingMethod.ENCRYPT,
            #        'encryption_key_information': {
            #            'key_format_type': enums.KeyFormatType.PKCS_1
            #        }
            #    }
            #)
            public_key = kmip_client.get(
                uid=WRAPPING_KEY_ID
            )

            print (public_key.value)
            
    finally:
        kmip_client.close()
    #except Exception as e:
    #    print(f"Error connecting to CTM or fetching the public key: {e}")
    #    return
 
if __name__ == "__main__":
    main()