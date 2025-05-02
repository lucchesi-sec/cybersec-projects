#!/bin/bash

# Script to apply security-related sysctl settings

SYSCTL_CONFIG_FILE="/etc/sysctl.d/99-hardening.conf" # Use a dedicated file

echo "Applying security-related sysctl settings to $SYSCTL_CONFIG_FILE..."

# Backup existing file if it exists
if [ -f "$SYSCTL_CONFIG_FILE" ]; then
    BACKUP_FILE="${SYSCTL_CONFIG_FILE}.bak_$(date +%Y%m%d_%H%M%S)"
    echo "Backing up existing $SYSCTL_CONFIG_FILE to $BACKUP_FILE..."
    sudo cp "$SYSCTL_CONFIG_FILE" "$BACKUP_FILE"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to backup existing sysctl config. Aborting."
        exit 1
    fi
fi

# Create/Overwrite the sysctl configuration file
# Using cat with EOF for multi-line content
sudo bash -c "cat > $SYSCTL_CONFIG_FILE" << EOF
# Hardening sysctl settings

# --- Network Settings ---

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0 # Also disable secure redirects
net.ipv4.conf.default.secure_redirects = 0

# Enable SYN cookies to handle SYN floods
net.ipv4.tcp_syncookies = 1

# Log Martians (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- Memory/Process Settings ---

# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Restrict access to kernel logs/pointers (dmesg)
kernel.dmesg_restrict = 1
# kernel.kptr_restrict = 2 # Uncomment for stricter pointer hiding if needed

# --- Filesystem Settings ---

# Restrict ptrace scope (prevents non-root processes attaching to others)
# Note: This can break debugging tools (like gdb) for non-root users
# kernel.yama.ptrace_scope = 1

# Prevent creation of file links/FIFOs in world-writable sticky directories by non-owners
# (e.g., /tmp)
fs.protected_fifos = 1
fs.protected_hardlinks = 1
fs.protected_regular = 1
fs.protected_symlinks = 1

EOF

if [ $? -ne 0 ]; then
    echo "Error: Failed to write sysctl settings to $SYSCTL_CONFIG_FILE. Aborting."
    exit 1
fi

echo "Applying sysctl settings..."
# Use -p with the specific file to load only these settings,
# or use --system to reload all files from /etc/sysctl.d/, /run/sysctl.d/, /usr/lib/sysctl.d/, /etc/sysctl.conf
# Using --system is generally safer and recommended.
sudo sysctl --system
if [ $? -ne 0 ]; then
    echo "Warning: Failed to apply sysctl settings using 'sysctl --system'. Check configuration."
    # Attempting with -p as a fallback
    # sudo sysctl -p "$SYSCTL_CONFIG_FILE"
    # if [ $? -ne 0 ]; then
    #    echo "Error: Failed to apply sysctl settings using 'sysctl -p' as well."
    #    exit 1
    # fi
    exit 1 # Exit if --system fails, as it indicates a broader issue.
fi

echo "Sysctl settings applied successfully."
echo "Note: Some settings may require a reboot to take full effect."
