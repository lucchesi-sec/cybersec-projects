#!/bin/bash

set -e -u -o pipefail

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
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local prefix=""
    
    # Only log if level is >= current log level
    if [[ $level -ge $CURRENT_LOG_LEVEL ]]; then
        case $level in
            "$LOG_LEVEL_DEBUG")   prefix="[DEBUG]"   ;;
            "$LOG_LEVEL_INFO")    prefix="[INFO]"    ;;
            "$LOG_LEVEL_SUCCESS") prefix="[SUCCESS]" ;;
            "$LOG_LEVEL_WARNING") prefix="[WARNING]" ;;
            "$LOG_LEVEL_ERROR")   prefix="[ERROR]"   ;;
            *)                    prefix="[UNKNOWN]" ;;
        esac
        
        echo "$timestamp $prefix $message" | tee -a "$LOG_FILE"
    fi
}

# Error function with logging and exit
error_exit() {
    log $LOG_LEVEL_ERROR "$1"
    # set -e handles exit on error for most commands, but explicit exit here is fine.
    exit 1
}

# Function to find and offer removal of a specific key fingerprint on the remote server
# Takes two arguments:
# $1: Fingerprint of the key to find and remove
# $2: Description of the key (e.g., "primary old key" or "key from old-keys.txt: path/to/key.pub")
find_and_remove_key_on_remote() {
    local fingerprint_to_find="$1"
    local key_description="$2"

    log $LOG_LEVEL_INFO "Checking for $key_description (fingerprint: $fingerprint_to_find) in remote authorized_keys..."
    
    # Note: This method of reading line-by-line and piping to 'ssh-keygen -lf /dev/stdin'
    # works well for standard authorized_key entries. For lines with complex prefixed options
    # (e.g., from="...", command="..."), its accuracy might vary.
    # A more robust solution would involve parsing each line to extract only the key-type and key-blob.
    local remote_key_line_found
    remote_key_line_found=$(ssh -i "$NEW_KEY_PATH" "${REMOTE_USER}@${REMOTE_HOST}" "
      while read line; do
        # Ensure 'line' is not empty before piping
        if [[ -n \"\$line\" ]]; then
            echo \"\$line\" | ssh-keygen -lf /dev/stdin 2>/dev/null | grep -qF \"$fingerprint_to_find\" && echo \"FOUND:\$line\" && break
        fi
      done < ~/.ssh/authorized_keys
    ")

    if [[ "$remote_key_line_found" == *"FOUND:"* ]]; then
        local actual_key_line="${remote_key_line_found#FOUND:}" # Remove "FOUND:" prefix
        log $LOG_LEVEL_WARNING "$key_description (fingerprint: $fingerprint_to_find) detected in remote authorized_keys: $actual_key_line"
        
        read -p "Do you want to remove this key ($key_description)? [y/N]: " CONFIRM_REMOVE
        if [[ "$CONFIRM_REMOVE" =~ ^[Yy]$ ]]; then
            log $LOG_LEVEL_INFO "Attempting to remove $key_description line from remote authorized_keys..."
            
            local remote_command_remove
            remote_command_remove="grep -vF -- \"${actual_key_line}\" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.new && mv ~/.ssh/authorized_keys.new ~/.ssh/authorized_keys"
            
            log $LOG_LEVEL_DEBUG "Remote command for key removal: $remote_command_remove"

            if ssh -i "$NEW_KEY_PATH" "${REMOTE_USER}@${REMOTE_HOST}" "$remote_command_remove"; then
                log $LOG_LEVEL_SUCCESS "$key_description removed successfully from remote authorized_keys."
            else
                log $LOG_LEVEL_ERROR "Failed to remove $key_description from remote authorized_keys. Check backup: $BACKUP_FILE"
            fi
        else
            log $LOG_LEVEL_INFO "$key_description not removed."
        fi
    else
        log $LOG_LEVEL_INFO "$key_description (fingerprint: $fingerprint_to_find) not found in remote authorized_keys."
    fi
}

REMOTE_USER="${1:-}" # Default to empty if not set, check later
REMOTE_HOST="${2:-}" # Default to empty if not set, check later
# Optional third argument for the old public key path
SPECIFIED_OLD_KEY_PATH="${3:-}" 

OLD_KEY_PATH="" # Initialize
KEY_DIR="$HOME/.ssh/rotated-keys"
NEW_KEY_NAME="id_rsa_rotated_$(date +%Y-%m-%d_%H-%M-%S)"
NEW_KEY_PATH="$KEY_DIR/$NEW_KEY_NAME"
LOG_FILE="example-output/rotation-log.txt" # Consider making this path more robust or configurable
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )" # Get script's own directory
OLD_KEYS_FILE_PATH="${SCRIPT_DIR}/old-keys.txt" # Assumes old-keys.txt is in the same dir as the script
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
    error_exit "Usage: $0 <remote_user> <remote_host> [path_to_old_public_key]"
fi

# Determine and verify old key path
if [[ -n "$SPECIFIED_OLD_KEY_PATH" ]]; then
    OLD_KEY_PATH="$SPECIFIED_OLD_KEY_PATH"
    log $LOG_LEVEL_INFO "Using specified old public key path: $OLD_KEY_PATH"
else
    OLD_KEY_PATH="$HOME/.ssh/id_rsa.pub"
    log $LOG_LEVEL_INFO "No old public key path specified, defaulting to: $OLD_KEY_PATH"
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
BACKUP_FILE="$HOME/.ssh/authorized_keys.backup-${BACKUP_DATE}"
log $LOG_LEVEL_INFO "Backing up authorized_keys on remote server to $BACKUP_FILE"
ssh -i "$NEW_KEY_PATH" "${REMOTE_USER}@${REMOTE_HOST}" "cp ~/.ssh/authorized_keys $BACKUP_FILE" || \
    log $LOG_LEVEL_WARNING "Failed to backup authorized_keys file"

# --- Remove primary old key ---
find_and_remove_key_on_remote "$OLD_FINGERPRINT" "primary old key ($OLD_KEY_PATH)"

# --- Scan for and remove other specified old keys ---
if [[ -f "$OLD_KEYS_FILE_PATH" ]]; then
    log $LOG_LEVEL_INFO "Found $OLD_KEYS_FILE_PATH. Scanning for additional old keys to remove."
    
    # Read file line by line, even if last line doesn't have a newline
    while IFS= read -r old_key_pub_path || [[ -n "$old_key_pub_path" ]]; do
        # Skip empty lines or comments
        if [[ -z "$old_key_pub_path" || "$old_key_pub_path" == \#* ]]; then
            continue
        fi

        # Expand tilde to home directory
        local expanded_path
        eval expanded_path="$old_key_pub_path"

        if [[ -f "$expanded_path" ]]; then
            local_fingerprint=$(ssh-keygen -lf "$expanded_path" | awk '{print $2}')
            if [[ -n "$local_fingerprint" ]]; then
                log $LOG_LEVEL_DEBUG "Processing key $expanded_path with fingerprint $local_fingerprint"
                find_and_remove_key_on_remote "$local_fingerprint" "key from old-keys.txt: $old_key_pub_path"
            else
                log $LOG_LEVEL_WARNING "Could not get fingerprint for key file: $expanded_path"
            fi
        else
            log $LOG_LEVEL_WARNING "Key file specified in $OLD_KEYS_FILE_PATH not found locally: $old_key_pub_path"
        fi
    done < "$OLD_KEYS_FILE_PATH"
else
    log $LOG_LEVEL_DEBUG "$OLD_KEYS_FILE_PATH not found, skipping scan for additional old keys."
fi


log $LOG_LEVEL_SUCCESS "SSH key rotation and cleanup completed at $(date)"

# Print usage instructions
if [[ $CURRENT_LOG_LEVEL -le $LOG_LEVEL_INFO ]]; then
    echo ""
    echo "New key generated: $NEW_KEY_PATH"
    echo "To use this key for SSH connections:"
    echo "ssh -i $NEW_KEY_PATH ${REMOTE_USER}@${REMOTE_HOST}"
fi
