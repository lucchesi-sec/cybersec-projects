#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Script to apply basic auditd rules

RULES_DIR="/etc/audit/rules.d"
TARGET_RULES_FILE_SRC="${RULES_DIR}/99-hardening-rules.rules" # Source rules file name
COMPILED_RULES_FILE="/etc/audit/audit.rules" # Standard compiled rules file

# Backup existing source rules file if it exists
if [ -f "$TARGET_RULES_FILE_SRC" ]; then
    BACKUP_AUDIT_RULES_FILE="${TARGET_RULES_FILE_SRC}.bak_$(date +%Y%m%d_%H%M%S)"
    echo "Backing up existing $TARGET_RULES_FILE_SRC to $BACKUP_AUDIT_RULES_FILE..."
    sudo cp "$TARGET_RULES_FILE_SRC" "$BACKUP_AUDIT_RULES_FILE"
fi

echo "Creating/Overwriting audit rules source file: $TARGET_RULES_FILE_SRC"

# Create the rules file content
sudo bash -c "cat > $TARGET_RULES_FILE_SRC" << EOF
# Auditd rules for hardening

# Note: auditctl -R will enable auditing if rules are loaded.
# The -e 2 rule at the end will make the configuration immutable.

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
    echo "Error: Failed to write audit rules to $TARGET_RULES_FILE_SRC. Aborting."
    exit 1
fi
echo "Audit rules source file written to $TARGET_RULES_FILE_SRC."

echo "Attempting to apply auditd rules with aggressive reset..."

# --- Aggressive Reset of Auditd State ---
echo "Stopping auditd service..."
sudo systemctl stop auditd || echo "Warning: auditd stop failed, it might not have been running."

echo "Removing old compiled rules file $COMPILED_RULES_FILE to prevent reload of potentially immutable config..."
sudo rm -f "$COMPILED_RULES_FILE"

echo "Running 'auditctl -D' to delete any loaded kernel rules..."
if sudo auditctl -D; then
    echo "auditctl -D successful or no rules to delete."
else
    echo "Warning: 'auditctl -D' failed. This can happen if rules were immutable and kernel retained the flag."
    echo "Proceeding with attempt to load new rules..."
fi
# --- End Aggressive Reset ---

RULES_LOADED_SUCCESSFULLY=0

# 1. Syntax check rules from source file
echo "Performing syntax check by attempting to load rules from $TARGET_RULES_FILE_SRC..."
set +e
AUDITCTL_SYNTAX_CHECK_OUTPUT=$(sudo auditctl -R "$TARGET_RULES_FILE_SRC" 2>&1)
AUDITCTL_SYNTAX_CHECK_EXIT_CODE=$?
set -e

if [ "$AUDITCTL_SYNTAX_CHECK_EXIT_CODE" -eq 0 ]; then
    echo "Syntax check (auditctl -R $TARGET_RULES_FILE_SRC) successful."
    # Rules are now in the kernel, but auditd is stopped.
    # We still need augenrules for persistence and for auditd to use them on start.
else
    echo "ERROR: Syntax check (auditctl -R $TARGET_RULES_FILE_SRC) failed with exit code $AUDITCTL_SYNTAX_CHECK_EXIT_CODE."
    echo "auditctl output:"
    echo "$AUDITCTL_SYNTAX_CHECK_OUTPUT"
    echo "Aborting due to rule syntax errors."
    # Attempt to start auditd so system is not without it, though it may have no/default rules
    sudo systemctl start auditd || echo "Warning: Failed to start auditd after syntax check failure."
    exit 1
fi

# 2. Compile rules using augenrules for persistence
if command -v augenrules &> /dev/null; then
    echo "Running 'augenrules' to compile rules into $COMPILED_RULES_FILE..."
    if sudo augenrules; then
        echo "augenrules compilation successful."
        # Verify the compiled file can be loaded (redundant if previous -R passed, but good check)
        echo "Verifying compiled rules file $COMPILED_RULES_FILE with auditctl -R..."
        set +e
        AUDITCTL_COMPILED_LOAD_OUTPUT=$(sudo auditctl -R "$COMPILED_RULES_FILE" 2>&1)
        AUDITCTL_COMPILED_LOAD_EXIT_CODE=$?
        set -e
        if [ "$AUDITCTL_COMPILED_LOAD_EXIT_CODE" -eq 0 ]; then
            echo "Successfully loaded/verified compiled rules from $COMPILED_RULES_FILE."
            RULES_LOADED_SUCCESSFULLY=1
        else
            echo "ERROR: Failed to load/verify compiled rules from $COMPILED_RULES_FILE with auditctl. Exit code: $AUDITCTL_COMPILED_LOAD_EXIT_CODE."
            echo "auditctl output:"
            echo "$AUDITCTL_COMPILED_LOAD_OUTPUT"
            # RULES_LOADED_SUCCESSFULLY remains 0
        fi
    else
        echo "ERROR: 'augenrules' compilation failed. Rules will not be persistent."
        # RULES_LOADED_SUCCESSFULLY remains 0
    fi
else
    echo "Warning: 'augenrules' command not found. Rules may not persist across reboots."
    # If syntax check passed, rules are in kernel for current session.
    if [ "$AUDITCTL_SYNTAX_CHECK_EXIT_CODE" -eq 0 ]; then
        RULES_LOADED_SUCCESSFULLY=1 
        echo "Rules loaded for current session via auditctl -R $TARGET_RULES_FILE_SRC."
    fi
fi

# 3. Start auditd service
echo "Attempting to start auditd service..."
if sudo systemctl start auditd; then
    echo "auditd service started successfully."
    if [ "$RULES_LOADED_SUCCESSFULLY" -eq 1 ]; then
        echo "Auditd rules should be active."
        echo "Final check of loaded rules with 'auditctl -l':"
        sleep 1 # Give a moment
        sudo auditctl -l
    else
        echo "Warning: auditd started, but rule loading encountered issues. Check 'auditctl -l'."
    fi
else
    echo "ERROR: Failed to start auditd service."
    RULES_LOADED_SUCCESSFULLY=0 # Mark as failed if service doesn't start
fi

if [ "$RULES_LOADED_SUCCESSFULLY" -eq 1 ]; then
    echo "Auditd rules applied and auditd service started successfully."
else
    echo "Error: Auditd rule application failed. Please review messages above."
    exit 1
fi

exit 0
