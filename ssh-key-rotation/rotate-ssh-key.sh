#!/bin/bash

# SSH Key Rotation Script
# Usage: ./rotate-ssh-key.sh <remote_user> <remote_host>

REMOTE_USER=$1
REMOTE_HOST=$2
KEY_NAME="id_rsa_rotated_$(date +%Y-%m-%d_%H-%M-%S)"
LOG_FILE="example-output/rotation-log.txt"

if [[ -z "$REMOTE_USER" || -z "$REMOTE_HOST" ]]; then
    echo "Usage: $0 <remote_user> <remote_host>"
    exit 1
fi

echo "[INFO] Starting SSH key rotation for $REMOTE_USER@$REMOTE_HOST" | tee -a "$LOG_FILE"

# 1. Generate new SSH keypair
ssh-keygen -t rsa -b 4096 -f "$KEY_NAME" -N "" || { echo "[ERROR] Key generation failed"; exit 1; }
echo "[INFO] New keypair generated: $KEY_NAME" | tee -a "$LOG_FILE"

# 2. Copy the new public key to the remote server
ssh-copy-id -i "${KEY_NAME}.pub" "${REMOTE_USER}@${REMOTE_HOST}" || { echo "[ERROR] Failed to copy new public key"; exit 1; }
echo "[INFO] Public key copied to $REMOTE_HOST" | tee -a "$LOG_FILE"

# 3. Test login with the new key
ssh -i "$KEY_NAME" "${REMOTE_USER}@${REMOTE_HOST}" "echo '[SUCCESS] Login test successful with new key.'" || { echo "[ERROR] Login test failed"; exit 1; }

# 4. Notify user to manually remove the old key
echo "[WARNING] Manual step: review and remove the old public key from ~/.ssh/authorized_keys on the remote server."
echo "[INFO] SSH key rotation script completed at $(date)" | tee -a "$LOG_FILE"
