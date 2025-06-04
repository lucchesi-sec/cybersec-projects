#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

# Script to install essential hardening packages

echo "Updating package lists..."
sudo apt update

echo "Installing ufw (firewall)..."
sudo apt install -y ufw

echo "Installing fail2ban (intrusion prevention)..."
sudo apt install -y fail2ban

echo "Installing auditd (auditing daemon)..."
sudo apt install -y auditd

echo "Installing unattended-upgrades (automatic updates)..."
sudo apt install -y unattended-upgrades

echo "Installation complete."

echo "Configuring basic UFW rules..."
# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH connections (OpenSSH is the service name)
sudo ufw allow OpenSSH

# Enable UFW - use --force to avoid interactive prompt in script
sudo ufw --force enable

echo "UFW has been configured with basic rules and enabled."
echo "Remember to further configure services like Fail2Ban and Auditd as needed."
