#!/bin/bash

# Script to apply secure SSH configurations

SSH_CONFIG_FILE="/etc/ssh/sshd_config"
BACKUP_FILE="/etc/ssh/sshd_config.bak_$(date +%Y%m%d_%H%M%S)"

echo "Backing up current SSH configuration to $BACKUP_FILE..."
sudo cp "$SSH_CONFIG_FILE" "$BACKUP_FILE"
if [ $? -ne 0 ]; then
    echo "Error: Failed to backup SSH configuration. Aborting."
    exit 1
fi

echo "Applying secure SSH settings..."

# Disable Password Authentication (use key-based auth)
echo "Disabling PasswordAuthentication..."
sudo sed -i 's/^#*PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONFIG_FILE"
sudo sed -i 's/^#*ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' "$SSH_CONFIG_FILE" # Also disable challenge-response

# Disable Root Login
echo "Disabling root login..."
sudo sed -i 's/^#*PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONFIG_FILE"
sudo sed -i 's/^#*PermitRootLogin prohibit-password/PermitRootLogin no/' "$SSH_CONFIG_FILE" # Handle other PermitRootLogin variants

# Set LoginGraceTime (time allowed to authenticate)
echo "Setting LoginGraceTime to 60 seconds..."
sudo sed -i 's/^#*LoginGraceTime .*/LoginGraceTime 60/' "$SSH_CONFIG_FILE"
# If LoginGraceTime doesn't exist, add it
if ! grep -q "^LoginGraceTime" "$SSH_CONFIG_FILE"; then
    echo "LoginGraceTime 60" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null
fi

# Limit Max Authentication Attempts
echo "Setting MaxAuthTries to 3..."
sudo sed -i 's/^#*MaxAuthTries .*/MaxAuthTries 3/' "$SSH_CONFIG_FILE"
# If MaxAuthTries doesn't exist, add it
if ! grep -q "^MaxAuthTries" "$SSH_CONFIG_FILE"; then
    echo "MaxAuthTries 3" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null
fi

# --- Optional Recommended Settings ---
# Uncomment and modify as needed

# Change Default Port (e.g., to 2222) - Requires firewall adjustment!
# PORT=2222
# echo "Changing SSH port to $PORT..."
# sudo sed -i "s/^#*Port .*/Port $PORT/" "$SSH_CONFIG_FILE"
# if ! grep -q "^Port" "$SSH_CONFIG_FILE"; then
#     echo "Port $PORT" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null
# fi
# echo "Remember to allow port $PORT in your firewall (e.g., sudo ufw allow $PORT/tcp)"


# Allow only specific users/groups
# echo "Restricting SSH access (example: only allow user 'adminuser')..."
# echo "AllowUsers adminuser" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null
# OR restrict by group:
# echo "AllowGroups sshusers" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null
# Make sure the group 'sshusers' exists and users are added to it.

# Stronger Crypto (Modern Recommendations - May break compatibility with older clients)
# echo "Applying stronger cryptographic settings..."
# echo "" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null
# echo "# Stronger Crypto Settings" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null
# echo "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null
# echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null
# echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" | sudo tee -a "$SSH_CONFIG_FILE" > /dev/null

# --- End Optional Settings ---


echo "Validating SSH configuration..."
sudo sshd -t
if [ $? -ne 0 ]; then
    echo "Error: SSH configuration validation failed. Check $SSH_CONFIG_FILE."
    echo "Restoring backup from $BACKUP_FILE..."
    sudo cp "$BACKUP_FILE" "$SSH_CONFIG_FILE"
    exit 1
fi

echo "Restarting SSH service to apply changes..."
sudo systemctl restart sshd
if [ $? -ne 0 ]; then
    echo "Warning: Failed to restart sshd service. Please check manually."
    exit 1
fi

echo "SSH configuration applied successfully."
echo "IMPORTANT: Ensure you have SSH key-based authentication set up BEFORE disabling password authentication if you haven't already."
