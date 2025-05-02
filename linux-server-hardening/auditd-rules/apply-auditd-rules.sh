#!/bin/bash

# Script to apply basic auditd rules

RULES_DIR="/etc/audit/rules.d"
TARGET_RULES_FILE="${RULES_DIR}/99-hardening-rules.rules" # Use a named file

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

# Monitor failed access attempts
-a always,exit -F arch=b64 -S open,creat,truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,creat,truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,creat,truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open,creat,truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Make the configuration immutable (again, enforces it at the end)
# For RHEL/CentOS >= 7 and Debian/Ubuntu derivatives
-e 2
EOF

if [ $? -ne 0 ]; then
    echo "Error: Failed to write audit rules to $TARGET_RULES_FILE. Aborting."
    exit 1
fi

echo "Audit rules written to $TARGET_RULES_FILE."
echo "You may want to consolidate rules using 'augenrules --load'."
echo "Restarting auditd service to load rules (or use augenrules)..."

# Option 1: Restart auditd (simpler, potentially disruptive)
# sudo systemctl restart auditd

# Option 2: Use augenrules (preferred method)
if command -v augenrules &> /dev/null; then
    echo "Running 'augenrules --load'..."
    sudo augenrules --load
    if [ $? -ne 0 ]; then
        echo "Warning: 'augenrules --load' failed. Check auditd configuration."
        # Attempt restart as fallback? Or just warn? Let's just warn for now.
        # sudo systemctl restart auditd
    fi
else
    echo "Warning: 'augenrules' command not found. Restarting auditd service..."
    sudo systemctl restart auditd
fi

if [ $? -ne 0 ]; then
    echo "Warning: Failed to reload auditd rules. Please check manually."
    # Consider adding logic to remove the rules file if restart/reload fails?
    exit 1
fi

echo "Auditd rules applied/loaded successfully."
