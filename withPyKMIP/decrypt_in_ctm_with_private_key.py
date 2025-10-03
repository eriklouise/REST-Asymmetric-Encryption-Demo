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
# - This code demonstrates how to perform a ddecrypt operation of the payload using the private key of the asymmetric key pair on Ciphertrust Manager using KMIP.

# decrypt_with_kmip.py
import base64
from kmip.pie import client
from kmip import enums
from kmip.core import objects as kmip_objects
 
KMIP_HOST = "ciphertrust-manager.example.com"
KMIP_PORT = 5696
CLIENT_CERT = "/path/to/client.crt"
CLIENT_KEY = "/path/to/client.key"
CA_CERT = "/path/to/ca.crt"
 
# Replace with the private key ID from create_keypair.py
PRIVATE_KEY_ID = "replace-with-private-key-id"
 
# Paste the base64 ciphertext printed by encrypt_with_public.py
CIPHERTEXT_B64 = "replace-with-base64-ciphertext"
 
def main():
    ciphertext = base64.b64decode(CIPHERTEXT_B64)
 
    kmip_client = client.ProxyKmipClient(
        hostname=KMIP_HOST,
        port=KMIP_PORT,
        cert=CLIENT_CERT,
        key=CLIENT_KEY,
        ca=CA_CERT
    )
    try:
        kmip_client.open()
 
        # The OAEP/SHA-256 parameters must match the client-side encryption.
        crypto_params = kmip_objects.CryptographicParameters(
            padding_method=enums.PaddingMethod.OAEP,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        )
 
        # Perform server-side decrypt with the private key object.
        # The private key bytes never leave CipherTrust Manager.
        plaintext = kmip_client.decrypt(
            data=ciphertext,
            unique_identifier=PRIVATE_KEY_ID,
            cryptographic_parameters=crypto_params
        )
 
        # plaintext is bytes
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print(plaintext)
 
    finally:
        kmip_client.close()
 
if __name__ == "__main__":
    main()