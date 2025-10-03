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

# Asymmetric Key Configuration
ASYM_ALGO = "RSA"
ASYM_KEY_LENGTH = 4096
ASYM_KEY_NAME = "DemoREST"
ASYM_KEY_USAGE_MASK = 124  # Sign + Verify + Wrap Key + Unwrap Key
RSA_KEY_ID_FILE = f"{ASYM_KEY_NAME}_KeyID.txt"

# Local secret storage configuration
SECRETS_DIR = './secrets'

# AES-GCM Key Configuration
AES_KEY_FILE = "AES_GCM_Key.bin"
IV_FILE = "AES_GCM_IV.bin"
ENC_AES_KEY_FILE = "AES_GCM_Key_encrypted.bin"
ENC_IV_FILE = "AES_GCM_IV_encrypted.bin"
KEY_SIZE = 32  # 256 bits for AES-256-GCM
IV_SIZE = 12   # 12 bytes for GCM