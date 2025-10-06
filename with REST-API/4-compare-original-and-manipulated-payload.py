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
# - compare the original clear payload with the decrypted payload
# - The original clear payload is stored in ./payload/clear_payload.txt
# - The decrypted payload is stored in ./payload/unencrypted_payload.txt

import config

CLEAR_PAYLOAD_FILE = config.CLEAR_PAYLOAD_FILE
UNENCRYPTED_PAYLOAD_FILE = config.UNENCRYPTED_PAYLOAD_FILE

def files_are_identical(file1, file2):
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        return f1.read() == f2.read()

def main():
    if files_are_identical(CLEAR_PAYLOAD_FILE, UNENCRYPTED_PAYLOAD_FILE):
        print(f"'{CLEAR_PAYLOAD_FILE}' and '{UNENCRYPTED_PAYLOAD_FILE}' are identical.")
    else:
        print(f"'{CLEAR_PAYLOAD_FILE}' and '{UNENCRYPTED_PAYLOAD_FILE}' are different.")

# --- Main process ---
if __name__ == "__main__":
    main()