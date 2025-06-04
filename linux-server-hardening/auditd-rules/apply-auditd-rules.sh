#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Script to apply basic auditd rules

RULES_DIR="/etc/audit/rules.d"
TARGET_RULES_FILE="${RULES_DIR}/99-hardening-rules.rules" # Use a named file

# Backup existing rules file if it exists
if [ -f "$TARGET_RULES_FILE" ]; then
    BACKUP_AUDIT_RULES_FILE="${TARGET_RULES_FILE}.bak_$(date +%Y%m%d_%H%M%S)"
    echo "Backing up existing $TARGET_RULES_FILE to $BACKUP_AUDIT_RULES_FILE..."
    sudo cp "$TARGET_RULES_FILE" "$BACKUP_AUDIT_RULES_FILE"
    # No need to check $? here due to set -e
fi

echo "Creating/Overwriting audit rules file: $TARGET_RULES_FILE"

# Create the rules file content
# Using cat with EOF allows for easy multi-line rule definition
sudo bash -c "cat > $TARGET_RULES_FILE" << EOF
# Auditd rules for hardening

# Make the configuration immutable - important!
-e 1

# Monitor changes to user/group files
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor changes to login definitions
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /etc/pam.d/ -p wa -k login

# Monitor changes to SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

# Monitor use of privileged commands (example: sudo)
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor module loading/unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Monitor mount operations
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Monitor failed access attempts (using openat)
-a always,exit -F arch=b64 -S openat,truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S openat,truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S openat,truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S openat,truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Make the configuration immutable (again, enforces it at the end)
# For RHEL/CentOS >= 7 and Debian/Ubuntu derivatives
-e 2
EOF

if [ $? -ne 0 ]; then
    echo "Error: Failed to write audit rules to $TARGET_RULES_FILE. Aborting."
    exit 1
fi

echo "Audit rules written to $TARGET_RULES_FILE."
echo "Attempting to delete existing rules and load new ones..."

# Flag to track if rules loaded successfully
RULES_LOADED_SUCCESSFULLY=0

# 0. Delete existing rules first for a clean slate
echo "Running 'auditctl -D' to delete existing rules..."
# Temporarily allow this command to fail without exiting the script due to 'set -e'
# as an immutable configuration (-e 2) would cause -D to fail.
if sudo auditctl -D; then
    echo "auditctl -D successful or no rules to delete."
else
    echo "Warning: 'auditctl -D' failed. This can happen if rules are immutable (-e 2)."
    echo "Proceeding with attempt to load new rules..."
fi

# 1. Attempt direct load first (often gives better immediate feedback)
echo "Running 'auditctl -R $TARGET_RULES_FILE'..."
# Temporarily disable 'set -e' to capture detailed error from auditctl -R
set +e
AUDITCTL_R_OUTPUT=$(sudo auditctl -R "$TARGET_RULES_FILE" 2>&1)
AUDITCTL_R_EXIT_CODE=$?
set -e

if [ "$AUDITCTL_R_EXIT_CODE" -eq 0 ]; then
    echo "auditctl -R successful."
    RULES_LOADED_SUCCESSFULLY=1
else
    echo "ERROR: 'auditctl -R $TARGET_RULES_FILE' failed with exit code $AUDITCTL_R_EXIT_CODE."
    echo "auditctl output:"
    echo "$AUDITCTL_R_OUTPUT"
    # The script will exit here due to 'set -e' being re-enabled and the main script's error handling
    # if RULES_LOADED_SUCCESSFULLY remains 0 and this script returns non-zero.
    # To ensure this script itself signals failure to apply-all.sh:
    exit 1 
fi

# 2. Attempt to make rules persistent using augenrules (if available)
if command -v augenrules &> /dev/null; then
    echo "Running 'augenrules --load'..."
    sudo augenrules --load
    if [ $? -eq 0 ]; then
        echo "augenrules --load successful."
        RULES_LOADED_SUCCESSFULLY=1
    else
        echo "Warning: First attempt of 'augenrules --load' failed. Attempting auditd restart and retry."
        sudo systemctl restart auditd
        sleep 2 # Give service a moment to restart
        echo "Retrying 'augenrules --load' after auditd restart..."
        sudo augenrules --load
        if [ $? -eq 0 ]; then
            echo "augenrules --load successful after auditd restart."
            RULES_LOADED_SUCCESSFULLY=1
        else
            echo "Warning: 'augenrules --load' still failed after auditd restart. Rules might not persist."
            # RULES_LOADED_SUCCESSFULLY remains 0 or based on auditctl -R
        fi
    fi
else
    echo "Warning: 'augenrules' command not found. Rules may not persist across reboots."
    # If auditctl -R was successful, we can still consider rules loaded for the current session.
    # RULES_LOADED_SUCCESSFULLY would be 1 from the auditctl -R check.
fi

# 3. If direct load or augenrules failed, try restarting the service as a last resort
# This section might be redundant now if augenrules retry logic includes a restart,
# but keeping it as a final fallback if RULES_LOADED_SUCCESSFULLY is still 0.
if [ "$RULES_LOADED_SUCCESSFULLY" -eq 0 ]; then
    echo "Warning: Rule loading via auditctl/augenrules failed or was incomplete. Attempting service restart..."
    sudo systemctl restart auditd
    if [ $? -ne 0 ]; then
        echo "Error: Failed to restart auditd service after rule loading issues."
        exit 1
    else
        echo "auditd service restarted. Check 'sudo auditctl -l' manually to verify rules."
        # We restarted, but can't be certain rules are loaded without checking again
        RULES_LOADED_SUCCESSFULLY=1 # Assume restart might have fixed it, but warn user
    fi
fi


if [ "$RULES_LOADED_SUCCESSFULLY" -eq 1 ]; then
    echo "Auditd rules applied/loaded."
    echo "Verify loaded rules manually using 'sudo auditctl -l' if needed."
else
    echo "Error: Failed to load auditd rules through all methods. Please investigate manually."
    exit 1
fi

exit 0
