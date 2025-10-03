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
# - Create a local AES-GCM key and IV and store them in files
# - The key and IV are generated using a cryptographically secure random number generator
# - The key and IV are stored in the ./secrets directory    

import os
import config
from secrets import token_bytes

KEY_SIZE = config.KEY_SIZE
IV_SIZE = config.IV_SIZE

SECRETS_DIR = config.SECRETS_DIR
KEY_FILE = config.AES_KEY_FILE
IV_FILE = config.IV_FILE

def ensure_secrets_dir():
    if not os.path.exists(SECRETS_DIR):
        os.makedirs(SECRETS_DIR)

def save_secret(filename, data):
    if not os.path.exists(SECRETS_DIR):
        os.makedirs(SECRETS_DIR)

    with open(os.path.join(SECRETS_DIR, filename), 'wb') as f:
        f.write(data)
    print(f"Saved {filename} in {SECRETS_DIR}")

def main():
    ensure_secrets_dir()
    key = token_bytes(KEY_SIZE)
    iv = token_bytes(IV_SIZE)
    save_secret(KEY_FILE, key)
    save_secret(IV_FILE, iv)

if __name__ == "__main__":
    main()