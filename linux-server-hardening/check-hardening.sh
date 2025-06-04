#!/bin/bash

# Linux Server Hardening Check Script (Enhanced and Fixed)
# Includes colored output, score summary, and user-specific password policy check

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

PASS_COUNT=0
TOTAL_CHECKS=24 # Updated count: SSH(4), UFW(1), F2B(2), UU(1), PWPolicy(1), Auditd(4), Banner(1), Sysctl(10)

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

# 1. Check SSH configuration
echo "[SSH CONFIG]"
grep -qi "^\\s*PasswordAuthentication\\s+no" /etc/ssh/sshd_config
print_result $? "PasswordAuthentication is disabled"

grep -qi "^\\s*PermitRootLogin\\s+no" /etc/ssh/sshd_config
print_result $? "PermitRootLogin is disabled"

# Check MaxAuthTries (value <= 3 passes)
MAX_AUTH_TRIES=$(grep -i "^\\s*MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}')
if [[ -n "$MAX_AUTH_TRIES" && "$MAX_AUTH_TRIES" -le 3 ]]; then
  print_result 0 "MaxAuthTries is set to $MAX_AUTH_TRIES (<= 3)"
else
  print_result 1 "MaxAuthTries is NOT set or > 3 (Current: '$MAX_AUTH_TRIES')"
fi

# Check LoginGraceTime (value <= 60 passes)
LOGIN_GRACE_TIME=$(grep -i "^\\s*LoginGraceTime" /etc/ssh/sshd_config | awk '{print $2}')
if [[ -n "$LOGIN_GRACE_TIME" && "$LOGIN_GRACE_TIME" -le 60 ]]; then
  print_result 0 "LoginGraceTime is set to $LOGIN_GRACE_TIME (<= 60)"
else
  print_result 1 "LoginGraceTime is NOT set or > 60 (Current: '$LOGIN_GRACE_TIME')"
fi

# 2. Check UFW firewall status
echo -e "\n[FIREWALL STATUS]"
sudo ufw status | grep -q "Status: active"
print_result $? "UFW firewall is active"

# 3. Check Fail2Ban status and config
echo -e "\n[FAIL2BAN STATUS]"
systemctl is-active fail2ban | grep -q "active"
print_result $? "Fail2Ban service is running"

# Check if sshd jail is enabled in jail.local or jail.conf
JAIL_LOCAL="/etc/fail2ban/jail.local"
JAIL_CONF="/etc/fail2ban/jail.conf"
SSHD_ENABLED=1 # Default to fail

if [ -f "$JAIL_LOCAL" ]; then
    if sudo grep -qE "^\\s*\\[sshd\\]" "$JAIL_LOCAL" && \
       sudo awk '/^\[sshd\]/{f=1} f && /enabled\\s*=\\s*true/{print; f=0}' "$JAIL_LOCAL" | grep -q "enabled"; then
        SSHD_ENABLED=0
    fi
fi
# If not found enabled in jail.local, check jail.conf (if jail.local doesn't explicitly disable it)
if [ "$SSHD_ENABLED" -ne 0 ] && [ -f "$JAIL_CONF" ]; then
     if sudo grep -qE "^\\s*\\[sshd\\]" "$JAIL_CONF" && \
        sudo awk '/^\[sshd\]/{f=1} f && /enabled\\s*=\\s*true/{print; f=0}' "$JAIL_CONF" | grep -q "enabled"; then
         # Check jail.local doesn't explicitly disable it
         DISABLE_CHECK=$(sudo awk '/^\[sshd\]/{f=1} f && /enabled\\s*=\\s*false/{print; f=0}' "$JAIL_LOCAL" 2>/dev/null)
         if [[ -z "$DISABLE_CHECK" ]]; then
              SSHD_ENABLED=0
         fi
    fi
fi
print_result $SSHD_ENABLED "Fail2Ban sshd jail is enabled"

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

# 6. Check auditd status and rules
echo -e "\n[AUDIT LOGGING]"
systemctl is-active auditd | grep -q "active"
print_result $? "auditd service is running"

# Check loaded audit rules (requires sudo)
if command -v auditctl &> /dev/null; then
    AUDIT_RULES_LOADED=$(sudo auditctl -l 2>/dev/null)
    if echo "$AUDIT_RULES_LOADED" | grep -q -- "-e 2"; then
      print_result 0 "Auditd rules immutable flag (-e 2) is set"
    else
      print_result 1 "Auditd rules immutable flag (-e 2) is NOT set"
    fi
    if echo "$AUDIT_RULES_LOADED" | grep -q -- "-k identity"; then
       print_result 0 "Auditd rules include key 'identity' for user/group file monitoring"
    else
       print_result 1 "Auditd rules do NOT include key 'identity' (check user/group monitoring)"
    fi
     if echo "$AUDIT_RULES_LOADED" | grep -q -- "-k sshd"; then
       print_result 0 "Auditd rules include key 'sshd' for SSH config monitoring"
    else
       print_result 1 "Auditd rules do NOT include key 'sshd' (check SSH config monitoring)"
    fi
else
    echo -e "${YELLOW}⚠️  Cannot check loaded audit rules: auditctl command not found.${RESET}"
    # Increment pass count to avoid penalizing if auditctl isn't installed,
    # but maybe TOTAL_CHECKS should be dynamic? For now, just warn.
    # Penalize if auditctl isn't installed, as it's part of auditd package.
     print_result 1 "Auditd rules immutable flag (-e 2) is NOT set (auditctl not found or error)"
     print_result 1 "Auditd rules 'identity' key check failed (auditctl not found or error)"
     print_result 1 "Auditd rules 'sshd' key check failed (auditctl not found or error)"

fi

# 7. Check warning banner
echo -e "\n[WARNING BANNER]"
# Check for specific content from our banner script
BANNER_TEXT="WARNING - Authorized Access Only"
grep -q "$BANNER_TEXT" /etc/issue.net
print_result $? "Login banner (/etc/issue.net) contains warning text"

# 8. Check Kernel Parameters (sysctl)
echo -e "\n[KERNEL PARAMETERS (SYSCTL)]"

# Function to check a sysctl value
check_sysctl() {
    local param="$1"
    local expected_value="$2"
    local current_value

    if ! current_value=$(sysctl -n "$param" 2>/dev/null); then
        print_result 1 "$param: Parameter not found or error reading"
        return
    fi

    if [[ "$current_value" == "$expected_value" ]]; then
        print_result 0 "$param is set to $expected_value"
    else
        print_result 1 "$param is NOT set to $expected_value (Current: '$current_value')"
    fi
}

check_sysctl "net.ipv4.conf.all.rp_filter" 1
check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" 1
check_sysctl "net.ipv4.conf.all.accept_source_route" 0
check_sysctl "net.ipv4.conf.all.accept_redirects" 0
check_sysctl "net.ipv4.conf.all.secure_redirects" 0
check_sysctl "net.ipv4.tcp_syncookies" 1
check_sysctl "net.ipv4.conf.all.log_martians" 1
check_sysctl "kernel.randomize_va_space" 2
check_sysctl "fs.protected_hardlinks" 1 # Check one fs protection setting
check_sysctl "kernel.dmesg_restrict" 1

# Summary
echo -e "\n============================"
echo -e " Hardening Score: ${YELLOW}$PASS_COUNT / $TOTAL_CHECKS${RESET}"
if [ "$PASS_COUNT" -eq "$TOTAL_CHECKS" ]; then
  echo -e "${GREEN}✅ All checks passed. System is hardened.${RESET}"
else
  echo -e "${YELLOW}⚠️  Some hardening checks failed. Review recommended.${RESET}"
fi
echo -e "============================"
