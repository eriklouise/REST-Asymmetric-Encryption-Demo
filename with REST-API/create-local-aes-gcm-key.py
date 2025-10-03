import os
from secrets import token_bytes

KEY_SIZE = 32  # 256 bits for AES-256-GCM
IV_SIZE = 12   # 12 bytes for GCM

SECRETS_DIR = './secrets'
KEY_FILE = 'AES_GCM_Key.bin'
IV_FILE = 'AES_GCM_IV.bin'

def ensure_secrets_dir():
    if not os.path.exists(SECRETS_DIR):
        os.makedirs(SECRETS_DIR)

def save_secret(filename, data):
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