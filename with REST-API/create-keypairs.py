import requests
import json
import os
import sys
import config
import urllib3

# --- Configuration (UPDATE THESE VALUES) ---

# The hostname or IP address of your CipherTrust Manager appliance
CM_HOST = config.CTM_HOST
CM_USERNAME = config.CTM_USER
CM_PASSWORD = config.CTM_PASSWORD

# The ID of the Key Vault (Key Store) where the key will be created
# The name you want to assign to the new key
KEY_NAME = config.ASYM_KEY_NAME
KEY_LENGTH = config.ASYM_KEY_LENGTH
KEY_ALGO = config.ASYM_ALGO

# Your CipherTrust Manager API token (Bearer token)
# NOTE: In a real application, you'd get this from a separate authentication call.
API_TOKEN = os.getenv("CM_API_TOKEN", "YOUR_ACTUAL_API_TOKEN_HERE") 

# Cryptographic Usage Mask Calculation (Decimal Value)
USAGE_MASK = config.ASYM_KEY_USAGE_MASK

# --- API Details ---

# Base path for key creation (Standard API endpoint)
AUTH_ENDPOINT = f"https://{CM_HOST}/api/v1/auth/tokens/"
API_ENDPOINT = f"https://{CM_HOST}/api/v1/vault/keys2/" 

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

# --- Function to Create Key ---
def generate_asymmetric_key(bearer_token):
    """
    Generates an RSA-4096 asymmetric key in CipherTrust Manager via REST API.
    """
    if len(bearer_token) < 1:
        print("ERROR: Please set the CM_API_TOKEN environment variable or update the script.")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    payload = {
        "algorithm": KEY_ALGO,
        "size": KEY_LENGTH,
        "format": "raw",
        "name": KEY_NAME,
        "unexportable": False,
        "undeletable": False,
        "usageMask": USAGE_MASK
    }
    
    print(f"Attempting to create key '{KEY_NAME}' with size {KEY_LENGTH} and usageMask {USAGE_MASK}...")

    try:
        # Disable warnings for self-signed certificates (for demo purposes only)
        urllib3.disable_warnings()

        # Use verify=False if you are using a self-signed cert, otherwise, use a path to your CA bundle
        response = requests.post(API_ENDPOINT, headers=headers, json=payload, verify=False) 
        response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)

        # Successful response (usually 201 Created or 200 OK)
        key_data = response.json()

        print(f"Key created successfully: {key_data}")

        privateKeyId = token_data.get('jwt')
        
    except requests.exceptions.HTTPError as errh:
        print(f"\nHTTP Error occurred: {errh}")
        try:
            # Attempt to print error message from CM response body
            error_details = response.json()
            print("Server Error Details:")
            print(json.dumps(error_details, indent=4))
        except json.JSONDecodeError:
            # Handle cases where the response body is not JSON
            print(f"Raw Response Text: {response.text}")
            
    except requests.exceptions.ConnectionError as errc:
        print(f"\nConnection Error: Could not connect to {CM_HOST}. Check hostname and port.")
        print(errc)
        
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

# --- Function to store data in file ---
def store_in_file(filename, filecontent):
    with open(filename, 'w') as file:
        file.write(filecontent)
    print(f"Content successfully written to {filename}")

# --- Execution ---
if __name__ == "__main__":
    # Step 1: Get the token
    bearer_token = authenticate_and_get_token(CM_USERNAME, CM_PASSWORD)

    if bearer_token:
        # Step 2: Create the key
        generate_asymmetric_key(bearer_token)