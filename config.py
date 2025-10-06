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
# - Store common configuration for create_keypair.py, decrypt_in_ctm_with_private_key.py & encrypt_locally_with_public_key_from_ctm.py files

# Ciphertrust Manager Configuration                                                                        
CTM_HOST = "kmip.ciphertrustmanager.local"             
CTM_USER = "REST_USER"                                          
CTM_PASSWORD = "RestPassword123*"                               
CTM_AUTH_ENDPOINT = f"https://{CTM_HOST}/api/v1/auth/tokens/"    
CTM_API_ENDPOINT = f"https://{CTM_HOST}/api/v1/vault/keys2/"     
CTM_KEY_EXPORT_ENDPOINT = f"https://{CTM_HOST}/api//v1/vault/keys2/{{key_id}}/"
CTM_ENCRYPT_ENDPOINT = f"https://{CTM_HOST}/api/v1/crypto/encrypt/"
CTM_DECRYPT_ENDPOINT = f"https://{CTM_HOST}/api/v1/crypto/decrypt/"

# Local secret storage configuration
SECRETS_DIR = './secrets'
PAYLOAD_DIR = './payload'

# Asymmetric Key Configuration
ASYM_ALGO = "RSA"
ASYM_KEY_LENGTH = 4096
ASYM_KEY_NAME = "DemoREST"
ASYM_KEY_USAGE_MASK = 124  # Sign + Verify + Wrap Key + Unwrap Key
RSA_PUBKEY_ID_FILE = f"{SECRETS_DIR}/{ASYM_KEY_NAME}_PubKeyID.txt"
RSA_PRIVKEY_ID_FILE = f"{SECRETS_DIR}/{ASYM_KEY_NAME}_PrivKeyID.txt"

# Payload files configuration
CLEAR_PAYLOAD_FILE = f"{PAYLOAD_DIR}/clear_payload.txt"
ENCRYPTED_PAYLOAD_FILE = f"{PAYLOAD_DIR}/encrypted_base64_payload.txt"
UNENCRYPTED_PAYLOAD_FILE = f"{PAYLOAD_DIR}/unencrypted_payload.txt"