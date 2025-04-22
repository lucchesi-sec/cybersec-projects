#!/bin/bash

# Linux Server Hardening Check Script (Enhanced and Fixed)
# Includes colored output, score summary, and user-specific password policy check

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

PASS_COUNT=0
TOTAL_CHECKS=8

print_result() {
  if [ "$1" -eq 0 ]; then
    echo -e "${GREEN}✅ PASS:${RESET} $2"
    ((PASS_COUNT++))
  else
    echo -e "${RED}❌ FAIL:${RESET} $2"
  fi
}

echo -e "\n============================"
echo -e " Linux Server Hardening Check "
echo -e "============================\n"

# 1. Check SSH password login
echo "[SSH CONFIG]"
grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config
print_result $? "PasswordAuthentication is disabled"

# 2. Check UFW firewall status
echo -e "\n[FIREWALL STATUS]"
ufw status | grep -q "Status: active"
print_result $? "UFW firewall is active"

# 3. Check Fail2Ban status
echo -e "\n[FAIL2BAN STATUS]"
systemctl is-active fail2ban | grep -q "active"
print_result $? "Fail2Ban service is running"

# 4. Check for unattended-upgrades
echo -e "\n[AUTOMATIC UPDATES]"
grep -q "^Unattended-Upgrade::Automatic-Reboot \"true\";" /etc/apt/apt.conf.d/50unattended-upgrades
print_result $? "Unattended security upgrades are enabled"

# 5. Check password aging policy (system-wide)
echo -e "\n[PASSWORD POLICY]"
PASS_MAX_DAYS=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
PASS_MIN_DAYS=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
PASS_WARN_AGE=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')

if [[ "$PASS_MAX_DAYS" -le 90 && "$PASS_MIN_DAYS" -ge 7 && "$PASS_WARN_AGE" -ge 14 ]]; then
  print_result 0 "Password aging policy enforced: MAX_DAYS=$PASS_MAX_DAYS MIN_DAYS=$PASS_MIN_DAYS WARN_AGE=$PASS_WARN_AGE"
else
  print_result 1 "Password aging policy NOT enforced properly: MAX_DAYS=$PASS_MAX_DAYS MIN_DAYS=$PASS_MIN_DAYS WARN_AGE=$PASS_WARN_AGE"
fi

# Optional: Check user-specific password policy
USER_CHECK="enzo"
echo -e "\n[USER-SPECIFIC PASSWORD POLICY CHECK for $USER_CHECK]"
CHAGE_OUTPUT=$(chage -l "$USER_CHECK")
if echo "$CHAGE_OUTPUT" | grep -q "Maximum number of days between password change: 90" &&    echo "$CHAGE_OUTPUT" | grep -q "Minimum number of days between password change: 7" &&    echo "$CHAGE_OUTPUT" | grep -q "Number of days of warning before password expires: 14"; then
  print_result 0 "Password aging policy applied correctly for user $USER_CHECK"
else
  print_result 1 "Password aging policy NOT properly set for user $USER_CHECK"
fi

# 6. Check auditd status
echo -e "\n[AUDIT LOGGING]"
systemctl is-active auditd | grep -q "active"
print_result $? "auditd service is running"

# 7. Check warning banner
echo -e "\n[WARNING BANNER]"
grep -q "Unauthorized access prohibited" /etc/issue.net
print_result $? "Login banner is configured"

# Summary
echo -e "\n============================"
echo -e " Hardening Score: ${YELLOW}$PASS_COUNT / $TOTAL_CHECKS${RESET}"
if [ "$PASS_COUNT" -eq "$TOTAL_CHECKS" ]; then
  echo -e "${GREEN}✅ All checks passed. System is hardened.${RESET}"
else
  echo -e "${YELLOW}⚠️  Some hardening checks failed. Review recommended.${RESET}"
fi
echo -e "============================"
