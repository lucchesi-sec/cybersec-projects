#!/bin/bash

##############################################
# Collect Configs and Sample Output from VM #
##############################################

# -------- CONFIGURE THESE --------
VM_USER="enzo"
VM_IP="192.168.64.2"
PROJECT_DIR="$HOME/Documents/github/cybersec-projects/linux-server-hardening"
####################################

echo "🚀 Starting config and output collection from $VM_USER@$VM_IP"

# -------- PULL CONFIG FILES --------
echo "📂 Pulling SSH config..."
scp $VM_USER@$VM_IP:/etc/ssh/sshd_config $PROJECT_DIR/ssh-config/sshd_config

echo "📂 Pulling Fail2ban config..."
scp $VM_USER@$VM_IP:/etc/fail2ban/jail.local $PROJECT_DIR/fail2ban/jail.local

echo "📂 Pulling Auditd rules..."
scp $VM_USER@$VM_IP:/etc/audit/rules.d/audit.rules $PROJECT_DIR/auditd-rules/audit.rules

echo "📂 Pulling Legal Banner..."
scp $VM_USER@$VM_IP:/etc/issue.net $PROJECT_DIR/banner/issue.net

# -------- GENERATE SAMPLE OUTPUT ON VM --------
echo "🛠️ Generating output files on VM..."
ssh $VM_USER@$VM_IP "sudo fail2ban-client status sshd > ~/fail2ban-status.txt"
ssh $VM_USER@$VM_IP "sudo auditctl -l > ~/auditctl-list.txt"
ssh $VM_USER@$VM_IP "sudo aureport -x --summary > ~/aureport-exec-summary.txt"

# -------- PULL OUTPUT FILES BACK TO LOCAL --------
echo "📂 Pulling sample output files..."
scp $VM_USER@$VM_IP:~/fail2ban-status.txt $PROJECT_DIR/sample-output/fail2ban-status.txt
scp $VM_USER@$VM_IP:~/auditctl-list.txt $PROJECT_DIR/sample-output/auditctl-list.txt
scp $VM_USER@$VM_IP:~/aureport-exec-summary.txt $PROJECT_DIR/sample-output/aureport-exec-summary.txt

echo "✅ Collection complete!"
