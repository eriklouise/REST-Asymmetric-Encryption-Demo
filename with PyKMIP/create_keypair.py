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
# - This code demonstrates how to create an Asymmetric key pair in Ciphertrust Manager using KMIP.
# - RSA key pairs are more suitable for small payload due to ppadding/size limits. For large data encryption use hybrid encryption (AES-GCM for data & RSA to wrap the AES key)

# create_keypair.py
from kmip.pie import client
from kmip import enums
import config
import sys

def main():
    kmip_client = client.ProxyKmipClient(
        hostname=config.KMIP_HOST,
        port=config.KMIP_PORT,
        cert=config.CLIENT_CERT,
        key=config.CLIENT_KEY,
        ca=config.CA_CERT,
        
    )
    try:
        kmip_client.open()

        # Create an RSA key pair of the length of the config.KEY_LENGTH parameter. Set usage masks so that the public key can ENCRYPT
        # and the private key can DECRYPT. You can add SIGN/VERIFY if needed. 
        public_id, private_id = kmip_client.create_key_pair(
            algorithm=enums.CryptographicAlgorithm.RSA,
            length=config.KEY_LENGTH,
            public_usage_mask=[
                enums.CryptographicUsageMask.ENCRYPT,
                enums.CryptographicUsageMask.VERIFY
            ],
            private_usage_mask=[
                enums.CryptographicUsageMask.DECRYPT,
                enums.CryptographicUsageMask.SIGN
            ],
            public_name=f'{config.PUBLIC_KEY_NAME}',
            private_name=f'{config.PRIVATE_KEY_NAME}'
        )

        # By default the keys are created in a pre-active state. Activate them so that they can be used.
        kmip_client.activate(public_id)
        kmip_client.activate(private_id)

        # The keys are now active and can be used for encryption/decryption.
        print("Public Key ID :", public_id)
        print("Private Key ID:", private_id)

        # Store the key IDs in files for later use
        sys.stdout=open(f'{config.PUBLIC_KEYID_FILE}','w')
        print (public_id)
        sys.stdout.close()

        sys.stdout=open(f'{config.PRIVATE_KEYID_FILE}','w')
        print (private_id)
        sys.stdout.close()
 
    finally:
        kmip_client.close()
 
if __name__ == "__main__":
    main()