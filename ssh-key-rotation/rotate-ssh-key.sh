#!/bin/bash

# SSH Key Rotation Script (Safe Version)
# Usage: ./rotate-ssh-key.sh <remote_user> <remote_host>

# Log levels
LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_SUCCESS=2
LOG_LEVEL_WARNING=3
LOG_LEVEL_ERROR=4

# Default to INFO level
CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO

# Logging function with levels
log() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local prefix=""
    
    # Only log if level is >= current log level
    if [[ $level -ge $CURRENT_LOG_LEVEL ]]; then
        case $level in
            $LOG_LEVEL_DEBUG)   prefix="[DEBUG]"   ;;
            $LOG_LEVEL_INFO)    prefix="[INFO]"    ;;
            $LOG_LEVEL_SUCCESS) prefix="[SUCCESS]" ;;
            $LOG_LEVEL_WARNING) prefix="[WARNING]" ;;
            $LOG_LEVEL_ERROR)   prefix="[ERROR]"   ;;
            *)                  prefix="[UNKNOWN]" ;;
        esac
        
        echo "$timestamp $prefix $message" | tee -a "$LOG_FILE"
    fi
}

# Error function with logging and exit
error_exit() {
    log $LOG_LEVEL_ERROR "$1"
    exit 1
}

REMOTE_USER=$1
REMOTE_HOST=$2
OLD_KEY_PATH="$HOME/.ssh/id_rsa.pub"
KEY_DIR="$HOME/.ssh/rotated-keys"
NEW_KEY_NAME="id_rsa_rotated_$(date +%Y-%m-%d_%H-%M-%S)"
NEW_KEY_PATH="$KEY_DIR/$NEW_KEY_NAME"
LOG_FILE="example-output/rotation-log.txt"
BACKUP_DATE=$(date +%Y-%m-%d_%H-%M-%S)

# Set log level from environment variable if present
if [[ -n "$SSH_KEY_ROTATION_LOG_LEVEL" ]]; then
    case "$SSH_KEY_ROTATION_LOG_LEVEL" in
        "DEBUG")   CURRENT_LOG_LEVEL=$LOG_LEVEL_DEBUG   ;;
        "INFO")    CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO    ;;
        "SUCCESS") CURRENT_LOG_LEVEL=$LOG_LEVEL_SUCCESS ;;
        "WARNING") CURRENT_LOG_LEVEL=$LOG_LEVEL_WARNING ;;
        "ERROR")   CURRENT_LOG_LEVEL=$LOG_LEVEL_ERROR   ;;
        *)         log $LOG_LEVEL_WARNING "Unknown log level: $SSH_KEY_ROTATION_LOG_LEVEL, using INFO" ;;
    esac
fi

if [[ -z "$REMOTE_USER" || -z "$REMOTE_HOST" ]]; then
    error_exit "Usage: $0 <remote_user> <remote_host>"
fi

# Verify old key exists
if [[ ! -f "$OLD_KEY_PATH" ]]; then
    error_exit "Old public key not found at $OLD_KEY_PATH"
fi

mkdir -p "$KEY_DIR"
mkdir -p "example-output"

# Get fingerprint of the old key
OLD_FINGERPRINT=$(ssh-keygen -lf "$OLD_KEY_PATH" | awk '{print $2}')
log $LOG_LEVEL_INFO "Old key fingerprint detected: $OLD_FINGERPRINT"

# Generate new SSH keypair
log $LOG_LEVEL_INFO "Generating new SSH keypair in $KEY_DIR: $NEW_KEY_NAME"
ssh-keygen -t rsa -b 4096 -f "$NEW_KEY_PATH" -N "" || error_exit "Key generation failed"

# Debug log for key details
if [[ $CURRENT_LOG_LEVEL -le $LOG_LEVEL_DEBUG ]]; then
    NEW_FINGERPRINT=$(ssh-keygen -lf "${NEW_KEY_PATH}.pub" | awk '{print $2}')
    log $LOG_LEVEL_DEBUG "New key fingerprint: $NEW_FINGERPRINT"
    log $LOG_LEVEL_DEBUG "New key permissions: $(ls -la $NEW_KEY_PATH)"
fi

# Copy new public key to remote server
log $LOG_LEVEL_INFO "Copying new public key to $REMOTE_HOST"
ssh-copy-id -i "${NEW_KEY_PATH}.pub" "${REMOTE_USER}@${REMOTE_HOST}" || error_exit "Failed to copy new key"

# Test login with new key
log $LOG_LEVEL_INFO "Testing login with new key..."
ssh -i "$NEW_KEY_PATH" "${REMOTE_USER}@${REMOTE_HOST}" "echo 'Login test successful with new key.'" || error_exit "Login test failed"
log $LOG_LEVEL_SUCCESS "Login test successful with new key"

# Backup authorized_keys
BACKUP_FILE="~/.ssh/authorized_keys.backup-${BACKUP_DATE}"
log $LOG_LEVEL_INFO "Backing up authorized_keys on remote server to $BACKUP_FILE"
ssh -i "$NEW_KEY_PATH" "${REMOTE_USER}@${REMOTE_HOST}" "cp ~/.ssh/authorized_keys $BACKUP_FILE" || \
    log $LOG_LEVEL_WARNING "Failed to backup authorized_keys file"

# Find matching fingerprint remotely
log $LOG_LEVEL_INFO "Checking for old key in authorized_keys..."
OLD_KEY_FOUND=$(ssh -i "$NEW_KEY_PATH" "${REMOTE_USER}@${REMOTE_HOST}" "
  while read line; do
    echo \"\$line\" | ssh-keygen -lf /dev/stdin 2>/dev/null | grep '$OLD_FINGERPRINT' && echo \"FOUND:\$line\" && break
  done < ~/.ssh/authorized_keys
")

if [[ "$OLD_KEY_FOUND" == *"FOUND:"* ]]; then
    log $LOG_LEVEL_WARNING "Old key detected in authorized_keys."
    read -p "Do you want to remove the old key? [y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        log $LOG_LEVEL_INFO "Removing old key..."
        ssh -i "$NEW_KEY_PATH" "${REMOTE_USER}@${REMOTE_HOST}" "
          grep -v '$OLD_FINGERPRINT' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.new && mv ~/.ssh/authorized_keys.new ~/.ssh/authorized_keys" || \
          log $LOG_LEVEL_ERROR "Failed to remove old key"
        log $LOG_LEVEL_SUCCESS "Old key removed"
    else
        log $LOG_LEVEL_INFO "Old key not removed. Exiting safely."
    fi
else
    log $LOG_LEVEL_INFO "Old key fingerprint not found. No action taken."
fi

log $LOG_LEVEL_SUCCESS "SSH key rotation completed at $(date)"

# Print usage instructions
if [[ $CURRENT_LOG_LEVEL -le $LOG_LEVEL_INFO ]]; then
    echo ""
    echo "New key generated: $NEW_KEY_PATH"
    echo "To use this key for SSH connections:"
    echo "ssh -i $NEW_KEY_PATH ${REMOTE_USER}@${REMOTE_HOST}"
fi
