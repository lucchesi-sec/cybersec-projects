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

# Optional: Enable basic UFW rules (allow SSH, deny incoming)
# Uncomment the following lines if you want to enable UFW immediately
# echo "Configuring basic UFW rules..."
# sudo ufw allow OpenSSH
# sudo ufw --force enable # Use --force to avoid interactive prompt in script

echo "Remember to configure the installed services (UFW, Fail2Ban, Auditd) appropriately."
