#!/bin/bash

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
# - This code demonstrates how to generate required KMIP Users, Roles, Client Profiles, Clients and certificattes in Ciphertrust Manager using ksctl.
 
# ===== MODIFY THESE VARIABLES... =====
KMIP_PROFILE="kmip-profile.json"
KSCTL_CONFIGFILE="./ksctl/ksctl-config.yaml"

# ===== ...BUT NOT THOSE (unless you know what you do) =====
CTM_GROUPS=("Key Admins" "Key Users")
KMIP_CTM_CLIENTPROFILE="$(jq -r '.csr_org_name' """$KMIP_PROFILE""")_KMIPClientProfile"
KMIP_CTM_CLIENT="$(jq -r '.csr_org_name' """$KMIP_PROFILE""")_KMIPClient"
KMIP_USER_PWD_OUTFILE="./secrets/${KMIP_CTM_CLIENT}_pwd.txt" 
CLIENT_CERT="./secrets/${KMIP_CTM_CLIENT}_client_cert.pem"
CLIENT_KEY="./secrets/${KMIP_CTM_CLIENT}_client_key.pem"
CA_CERT="./secrets/${KMIP_CTM_CLIENT}_ca_cert.pem"

# ===== FOLDER secrets =====
if [ ! -d "./secrets" ]; then
    echo "Creating secrets folder"
    mkdir -p ./secrets
fi

# ===== Random Password Generator (that meets CTM default policies) =====
generate_password() {
    PWD_LENGTH=$(( 8 + RANDOM % (30 - 8 + 1) ))
    while true; do
        password=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+=-' </dev/urandom | head -c"$PWD_LENGTH")
 
        # Check if the password meets requirements
        [[ "$password" =~ [a-z] ]] || continue
        [[ "$password" =~ [A-Z] ]] || continue
        [[ "$password" =~ [0-9] ]] || continue
        [[ "$password" =~ [\!\@\#\$\%\^\&\*\(\)_\+\=\-] ]] || continue
 
        echo "$password"
        break
    done
}

# ===== STEP 1: Create a KMIP user in CTM if not exists =====
KMIP_USER=$(jq -r '.csr_cn' "$KMIP_PROFILE")
if ./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" users list --username $KMIP_USER | grep -q '"total": 1,'; then
    echo "User ${KMIP_USER} already exists, going next step..."
else
    echo "User ${KMIP_USER} doesn't already exists, creating it..."
    KMIP_USER=$(jq -r '.csr_cn' "$KMIP_PROFILE")
    KMIP_PWD=$(generate_password)
    echo $KMIP_PWD > $KMIP_USER_PWD_OUTFILE
    KMIP_EMAIL=$(jq -r '.csr_email' "$KMIP_PROFILE")
    KMIP_USERID=$(./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" users create -n ${KMIP_USER} -p ${KMIP_PWD} -e ${KMIP_EMAIL} | jq -r '.user_id')
    echo "User ${KMIP_USER} created, assigning it to required groups..."
    for iCTMgroup in "${CTM_GROUPS[@]}"; do
        ./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" groups adduser -n "$iCTMgroup" -u "$KMIP_USERID" > /dev/null
    done
    echo "Done user & groups management"
fi

# ===== STEP 2: Create a KMIP client profile in CTM if not exists =====
KMIP_PROFILE_EXISTS=""
KMIP_PROFILE_EXISTS=$(./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" kmip listprofiles --profilename $KMIP_CTM_CLIENTPROFILE 2> /dev/null | jq -r '.name')
if [ $KMIP_PROFILE_EXISTS == $KMIP_CTM_CLIENTPROFILE ]; then
    echo "KMIP Client Profile ${KMIP_CTM_CLIENTPROFILE} already exists"
else
    echo "KMIP Client Profile ${KMIP_CTM_CLIENTPROFILE} doesn't already exists, creating it..."
    ./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" kmip createprofile -p $KMIP_CTM_CLIENTPROFILE -c $KMIP_PROFILE > /dev/null
    echo "Done KMIP Client Profile management"
fi

# ===== STEP 3: Create KMIP Client Tokens in CTM if not already created =====
if $(./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" clientmgmt tokens list | jq -e '.resources[].label.KmipClientProfile == "'$KMIP_CTM_CLIENTPROFILE'"' 2> /dev/null); then
    echo "KMIP Registration Tokens attached to profile ${KMIP_CTM_CLIENTPROFILE} already exists, retrieving token info"
    KMIP_REGISTRATION_TOKEN=$(./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" clientmgmt tokens list | jq -r '.resources[] | select(.label.KmipClientProfile == "'$KMIP_CTM_CLIENTPROFILE'") | .token' 2> /dev/null)
    echo "Found KMIP Registration Token ${KMIP_REGISTRATION_TOKEN}"
else
    echo "KMIP Registration Tokens attached to profile ${KMIP_CTM_CLIENTPROFILE} doesn't already exists, creating it..."
    KMIP_REGISTRATION_TOKEN=$(./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" kmip createkmipregtoken -p $KMIP_CTM_CLIENTPROFILE | jq -r '.token')
    echo "Done KMIP Registration Tokens management"
fi

# ===== STEP 4: Register KMIP Client in CTM if not already registered =====
if $(./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" clientmgmt clients list | jq -e '.resources[].name == "'$KMIP_CTM_CLIENT'"' 2> /dev/null); then
    echo "KMIP Client ${KMIP_CTM_CLIENT} attached to profile ${KMIP_CTM_CLIENTPROFILE} already exists, retrieving client info"
    KMIP_CLIENT_ID=$(./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" clientmgmt clients list | jq -r '.resources[] | select(.name == "'$KMIP_CTM_CLIENT'") | .id' 2> /dev/null)
    echo "Found KMIP Client Id ${KMIP_CLIENT_ID}"
else
    echo "KMIP Client ${KMIP_CTM_CLIENT} doesn't already exists, creating it..."
    KMIP_CLIENT_ID=$(./ksctl/ksctl --configfile "${KSCTL_CONFIGFILE}" kmip register -n $KMIP_CTM_CLIENT -t $KMIP_REGISTRATION_TOKEN --kmipCertOutFile $CLIENT_CERT --kmipKeyOutFile $CLIENT_KEY | jq -r '.token')
    echo "Done KMIP Client management"
fi

# Clean up variables
unset KMIP_CLIENT_ID
unset KSCTL_CONFIGFILE
unset KMIP_CTM_CLIENT
unset KMIP_REGISTRATION_TOKEN
unset CLIENT_CERT
unset CLIENT_KEY
unset KMIP_CTM_CLIENTPROFILE
unset KMIP_PROFILE
unset KMIP_PROFILE_EXISTS
unset iCTMgroup
unset KMIP_USERID
unset KMIP_EMAIL
unset KMIP_PWD
unset KMIP_USER_PWD_OUTFILE
unset password
unset CTM_GROUPS
unset CA_CERT

echo "Done KMIP Certificate Generation. Certificates & randomized passwords are stored in the ./secrets/ folder."