#!/bin/bash

# --- Configuration ---
# AES-256 requires a 32-byte key (256 bits)
KEY_SIZE_BYTES=32
# GCM standard IV/Nonce size is 12 bytes (96 bits)
IV_SIZE_BYTES=12
# GCM standard Authentication Tag size is 16 bytes (128 bits)
TAG_SIZE_BYTES=16

# --- Output Files (will be overwritten if they exist) ---
KEY_FILE="./secrets/aes_gcm_key.bin"
IV_FILE="./secrets/aes_gcm_iv.bin"

echo "--- Generating Random AES-GCM Assets (256-bit Key) ---"
echo "Key size: ${KEY_SIZE_BYTES} bytes, IV size: ${IV_SIZE_BYTES} bytes, Tag size: ${TAG_SIZE_BYTES} bytes"
echo "--------------------------------------------------------"

# 1. Generate the random key
# Use /dev/urandom for good randomness
RANDOM_KEY=$(openssl rand -base64 ${KEY_SIZE_BYTES})
echo "Key (Base64): ${RANDOM_KEY}"
# Save the key in raw binary format for encryption tools
echo "${RANDOM_KEY}" | base64 -d > "${KEY_FILE}"
echo "Key saved to: ${KEY_FILE} (Binary)"

# 2. Generate a unique Initialization Vector (IV/Nonce)
RANDOM_IV=$(openssl rand -base64 ${IV_SIZE_BYTES})
echo "IV (Base64):  ${RANDOM_IV}"

# Save the IV in raw binary format
echo "${RANDOM_IV}" | base64 -d > "${IV_FILE}"
echo "IV saved to: ${IV_FILE} (Binary)"

# 3. Informational output for the Tag size
echo "Authentication Tag size required for GCM is ${TAG_SIZE_BYTES} bytes."
echo "--------------------------------------------------------"
echo "NOTE: The IV should be unique for every encryption operation with the same key."

# Clean up variables
unset RANDOM_KEY
unset RANDOM_IV