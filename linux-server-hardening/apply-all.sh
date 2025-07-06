#!/bin/bash

# Master script to apply all hardening configurations

# Function to check sudo privileges
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run with sudo privileges."
        exit 1
    fi
}

# Function to execute a script
run_script() {
    local script_path="$1"
    local script_name
    script_name=$(basename "$script_path")

    echo "----------------------------------------"
    echo "Running $script_name..."
    echo "----------------------------------------"

    if [ ! -f "$script_path" ]; then
        echo "Error: Script not found: $script_path"
        return 1
    fi

    # Ensure script is executable (optional, but good practice)
    # chmod +x "$script_path"

    # Execute the script
    if bash "$script_path"; then # Run with bash explicitly
        echo "$script_name completed successfully."
    else
        echo "Error: $script_name failed. Aborting."
        return 1 # Indicate failure
    fi
    echo "" # Add a newline for spacing
    return 0 # Indicate success
}

# --- Main Execution ---

check_sudo

# Define script paths
INSTALL_SCRIPT="install-packages.sh"
PW_POLICY_SCRIPT="password-policy/apply-pam-pwquality.sh"
SSH_CONFIG_SCRIPT="ssh-config/apply-ssh-config.sh"
FAIL2BAN_SCRIPT="fail2ban/apply-fail2ban-config.sh"
AUDITD_SCRIPT="auditd-rules/apply-auditd-rules.sh"
BANNER_SCRIPT="banner/apply-banner.sh"
SYSCTL_SCRIPT="sysctl/apply-sysctl-config.sh"

# Execute scripts in order, stopping if any fail
run_script "$INSTALL_SCRIPT" && \
run_script "$PW_POLICY_SCRIPT" && \
run_script "$SSH_CONFIG_SCRIPT" && \
run_script "$FAIL2BAN_SCRIPT" && \
run_script "$AUDITD_SCRIPT" && \
run_script "$BANNER_SCRIPT" && \
run_script "$SYSCTL_SCRIPT"

if [ $? -eq 0 ]; then
    echo "----------------------------------------"
    echo "All hardening scripts executed successfully."
    echo "----------------------------------------"
    echo "It's recommended to reboot the server or at least manually verify all services."
    echo "Run './check-hardening.sh' (after enhancements) to verify the applied settings."
else
    echo "----------------------------------------"
    echo "One or more hardening scripts failed. Please check the output above."
    echo "----------------------------------------"
    exit 1
fi

exit 0
