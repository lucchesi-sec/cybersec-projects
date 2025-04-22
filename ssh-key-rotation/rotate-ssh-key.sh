#!/bin/bash

# SSH Key Rotation Script with Fingerprint Matching and Safe Removal
# Usage: ./rotate-ssh-key.sh <remote_user> <remote_host>

REMOTE_USER=$1
REMOTE_HOST=$2
OLD_KEY_PATH="$HOME/.ssh/id_rsa.pub"
NEW_KEY_NAME="id_rsa_rotated_$(date +%Y-%m-%d_%H-%M-%S)"
LOG_FILE="example-output/rotation-log.txt"
BACKUP_DATE=$(date +%Y-%m-%d_%H-%M-%S)

if [[ -z "$REMOTE_USER" || -z "$REMOTE_HOST" ]]; then
    echo "Usage: $0 <remote_user> <remote_host>"
    exit 1
fi

if [[ ! -f "$OLD_KEY_PATH" ]]; then
    echo "[ERROR] Old public key not found at $OLD_KEY_PATH"
    exit 1
fi

# Get fingerprint of the old key
OLD_FINGERPRINT=$(ssh-keygen -lf "$OLD_KEY_PATH" | awk '{print $2}')
echo "[INFO] Old key fingerprint detected: $OLD_FINGERPRINT" | tee -a "$LOG_FILE"

# Generate new SSH keypair
echo "[INFO] Generating new SSH keypair: $NEW_KEY_NAME" | tee -a "$LOG_FILE"
ssh-keygen -t rsa -b 4096 -f "$NEW_KEY_NAME" -N "" || { echo "[ERROR] Key generation failed"; exit 1; }

# Copy new public key to remote server
echo "[INFO] Copying new public key to $REMOTE_HOST" | tee -a "$LOG_FILE"
ssh-copy-id -i "${NEW_KEY_NAME}.pub" "${REMOTE_USER}@${REMOTE_HOST}" || { echo "[ERROR] Failed to copy new key"; exit 1; }

# Test login with new key
echo "[INFO] Testing login with new key..." | tee -a "$LOG_FILE"
ssh -i "$NEW_KEY_NAME" "${REMOTE_USER}@${REMOTE_HOST}" "echo '[SUCCESS] Login test successful with new key.'" || { echo "[ERROR] Login test failed"; exit 1; }

# Backup existing authorized_keys on remote
BACKUP_FILE="~/.ssh/authorized_keys.backup-${BACKUP_DATE}"
echo "[INFO] Backing up authorized_keys on remote server to $BACKUP_FILE" | tee -a "$LOG_FILE"
ssh -i "$NEW_KEY_NAME" "${REMOTE_USER}@${REMOTE_HOST}" "cp ~/.ssh/authorized_keys $BACKUP_FILE"

# Check and remove the old key by fingerprint
echo "[INFO] Checking for old key in authorized_keys..." | tee -a "$LOG_FILE"

OLD_KEY_FOUND=$(ssh -i "$NEW_KEY_NAME" "${REMOTE_USER}@${REMOTE_HOST}" "awk '{print \$0}' ~/.ssh/authorized_keys | while read line; do echo \"\$line\" | ssh-keygen -lf /dev/stdin 2>/dev/null | grep '$OLD_FINGERPRINT'; done")

if [[ -n "$OLD_KEY_FOUND" ]]; then
    echo "[WARNING] Old key detected in authorized_keys." | tee -a "$LOG_FILE"
    read -p "Do you want to remove the old key? [y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "[INFO] Removing old key..." | tee -a "$LOG_FILE"
        ssh -i "$NEW_KEY_NAME" "${REMOTE_USER}@${REMOTE_HOST}" "grep -v '$OLD_FINGERPRINT' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.new && mv ~/.ssh/authorized_keys.new ~/.ssh/authorized_keys"
        echo "[SUCCESS] Old key removed." | tee -a "$LOG_FILE"
    else
        echo "[INFO] Old key not removed. Exiting safely." | tee -a "$LOG_FILE"
    fi
else
    echo "[INFO] Old key fingerprint not found. No action taken." | tee -a "$LOG_FILE"
fi

echo "[INFO] SSH key rotation completed at $(date)" | tee -a "$LOG_FILE"
