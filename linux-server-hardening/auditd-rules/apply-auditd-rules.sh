#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Script to apply basic auditd rules with a more aggressive reset

RULES_DIR="/etc/audit/rules.d"
OUR_RULES_FILE_BASENAME="99-hardening-rules.rules"
TARGET_RULES_FILE_SRC="${RULES_DIR}/${OUR_RULES_FILE_BASENAME}"
COMPILED_RULES_FILE="/etc/audit/audit.rules"
RULES_BACKUP_DIR="/etc/audit/rules.d.bak_$(date +%Y%m%d_%H%M%S)"

echo "Attempting to apply auditd rules with aggressive reset and cleanup..."

# --- Stop auditd and prepare for clean slate ---
echo "Stopping auditd service..."
sudo systemctl stop auditd || echo "Warning: auditd stop failed, it might not have been running."

echo "Removing old compiled rules file $COMPILED_RULES_FILE (if it exists)..."
sudo rm -f "$COMPILED_RULES_FILE"

echo "Backing up existing rules from $RULES_DIR to $RULES_BACKUP_DIR..."
sudo mkdir -p "$RULES_BACKUP_DIR"
# Move all existing .rules files, then we'll write ours fresh
sudo find "$RULES_DIR" -maxdepth 1 -name '*.rules' -exec mv {} "$RULES_BACKUP_DIR/" \; || echo "No existing .rules files to backup, or error during backup."

# --- Write our new rules file ---
echo "Creating/Overwriting audit rules source file: $TARGET_RULES_FILE_SRC"
sudo bash -c "cat > $TARGET_RULES_FILE_SRC" << EOF
# Auditd rules for hardening (Lucchesi-Sec)

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

# Make the configuration immutable - THIS MUST BE THE LAST RULE LOADED.
-e 2
EOF

if [ $? -ne 0 ]; then
    echo "Error: Failed to write audit rules to $TARGET_RULES_FILE_SRC. Aborting."
    # Attempt to restore backed up rules before exiting if any were moved
    if [ -d "$RULES_BACKUP_DIR" ]; then
        sudo find "$RULES_BACKUP_DIR" -name '*.rules' -exec mv {} "$RULES_DIR/" \; || echo "Warning: Failed to restore rules from $RULES_BACKUP_DIR"
    fi
    exit 1
fi
echo "Audit rules source file written to $TARGET_RULES_FILE_SRC."

# --- Compile and Load Rules ---
RULES_APPLIED_CORRECTLY=0
if command -v augenrules &> /dev/null; then
    echo "Running 'augenrules' to compile rules from $RULES_DIR into $COMPILED_RULES_FILE..."
    if sudo augenrules; then
        echo "augenrules compilation successful."
        # At this point, /etc/audit/audit.rules should contain ONLY our rules.
        # The systemd service unit for auditd will run 'augenrules --load' on start,
        # which effectively loads /etc/audit/audit.rules.
        RULES_APPLIED_CORRECTLY=1
    else
        echo "ERROR: 'augenrules' compilation failed. Rules will not be persistent or correctly loaded."
    fi
else
    echo "Warning: 'augenrules' command not found. Attempting direct load of $TARGET_RULES_FILE_SRC for current session."
    # This is a fallback if augenrules isn't there, less ideal for persistence.
    set +e
    AUDITCTL_R_OUTPUT=$(sudo auditctl -R "$TARGET_RULES_FILE_SRC" 2>&1)
    AUDITCTL_R_EXIT_CODE=$?
    set -e
    if [ "$AUDITCTL_R_EXIT_CODE" -eq 0 ]; then
        echo "auditctl -R $TARGET_RULES_FILE_SRC successful for current session."
        RULES_APPLIED_CORRECTLY=1
    else
        echo "ERROR: 'auditctl -R $TARGET_RULES_FILE_SRC' failed with exit code $AUDITCTL_R_EXIT_CODE."
        echo "auditctl output:"
        echo "$AUDITCTL_R_OUTPUT"
    fi
fi

# --- Start auditd and Verify ---
echo "Attempting to start auditd service..."
if sudo systemctl start auditd; then
    echo "auditd service started successfully."
    if [ "$RULES_APPLIED_CORRECTLY" -eq 1 ]; then
        echo "Auditd rules should be active. Verifying with 'auditctl -l'..."
        sleep 2 # Give a moment for service to fully start and load rules
        sudo auditctl -l
        # Check if immutable flag is set
        if sudo auditctl -s | grep -q "enabled 2"; then
            echo "Audit rules are IMMUTABLE (enabled 2)."
        else
            echo "Warning: Audit rules are NOT immutable (enabled != 2). Check 'auditctl -s'."
            RULES_APPLIED_CORRECTLY=0 # Consider this a failure if not immutable
        fi
    else
        echo "Warning: auditd started, but rule compilation/loading encountered issues. Check 'auditctl -l'."
    fi
else
    echo "ERROR: Failed to start auditd service."
    RULES_APPLIED_CORRECTLY=0
fi

if [ "$RULES_APPLIED_CORRECTLY" -eq 1 ]; then
    echo "Auditd rules applied, auditd service started, and rules confirmed immutable."
else
    echo "Error: Auditd rule application failed or rules not immutable. Please review messages above."
    # Attempt to restore backed up rules if any were moved
    if [ -d "$RULES_BACKUP_DIR" ]; then
        echo "Attempting to restore original rules from $RULES_BACKUP_DIR..."
        sudo find "$RULES_BACKUP_DIR" -name '*.rules' -exec mv -f {} "$RULES_DIR/" \; || echo "Warning: Failed to restore rules from $RULES_BACKUP_DIR"
        echo "Restoring $COMPILED_RULES_FILE if backup exists..."
        # This part is tricky as we don't have a direct backup of compiled file in this script version
        # Best effort: re-run augenrules if original files are back
        sudo augenrules || echo "Warning: augenrules failed after attempting to restore original .rules.d files."
        sudo systemctl restart auditd || echo "Warning: auditd restart failed after attempting to restore."
    fi
    exit 1
fi

echo "apply-auditd-rules.sh completed successfully."
exit 0
