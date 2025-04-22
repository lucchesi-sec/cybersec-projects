#!/bin/bash

# Linux Server Hardening Checker Script
# Colored output and scoring included

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0

check() {
    if $1; then
        echo -e "${GREEN}✅ $2${NC}"
        ((PASS_COUNT++))
    else
        echo -e "${RED}❌ WARNING: $3${NC}"
        ((FAIL_COUNT++))
    fi
}

echo "============================"
echo " Linux Server Hardening Check "
echo "============================"

# 1. SSH password login disabled
echo -e "\n[SSH CONFIG]"
check "[[ \$(grep -E '^PasswordAuthentication[[:space:]]+no' /etc/ssh/sshd_config) ]]"     "PasswordAuthentication disabled"     "PasswordAuthentication may be enabled"

# 2. UFW firewall status
echo -e "\n[FIREWALL STATUS]"
check "ufw status | grep -q 'active'"     "UFW is active"     "UFW is inactive"

# 3. Fail2Ban status
echo -e "\n[FAIL2BAN STATUS]"
check "systemctl is-active fail2ban | grep -q 'active'"     "Fail2Ban is running"     "Fail2Ban is not running"

# 4. Automatic updates (unattended-upgrades)
echo -e "\n[AUTOMATIC UPDATES]"
check "grep -q '^Unattended-Upgrade::Automatic-Reboot "true";' /etc/apt/apt.conf.d/50unattended-upgrades"     "Automatic updates configured"     "Automatic updates may not be configured"

# 5. Password aging policy
echo -e "\n[PASSWORD POLICY]"
PASS_MAX_DAYS=$(grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
if [[ $PASS_MAX_DAYS -le 90 && $PASS_MAX_DAYS -gt 0 ]]; then
    echo -e "${GREEN}✅ Password aging policy set (PASS_MAX_DAYS: $PASS_MAX_DAYS)${NC}"
    ((PASS_COUNT++))
else
    echo -e "${RED}❌ WARNING: Password aging policy not set properly (PASS_MAX_DAYS: $PASS_MAX_DAYS)${NC}"
    ((FAIL_COUNT++))
fi

# 6. Auditd status
echo -e "\n[AUDIT LOGGING]"
check "systemctl is-active auditd | grep -q 'active'"     "auditd is running"     "auditd is not running"

# 7. Warning banner presence
echo -e "\n[WARNING BANNER]"
check "grep -q 'Unauthorized access prohibited' /etc/issue.net"     "Warning banner is configured"     "No warning banner detected"

# Score summary
TOTAL_CHECKS=$((PASS_COUNT + FAIL_COUNT))
echo -e "\n============================"
echo -e " Hardening Check Complete"
echo -e " Score: ${GREEN}${PASS_COUNT} Passed${NC}, ${RED}${FAIL_COUNT} Failed${NC} out of ${YELLOW}${TOTAL_CHECKS} Checks${NC}"
echo "============================"

if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}❌ Some hardening checks failed. Please review the warnings above.${NC}"
else
    echo -e "${GREEN}✅ All hardening checks passed successfully!${NC}"
fi
