# Cybersecurity Projects

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

This repository contains hands-on security projects focused on practical skills in system hardening, cloud security, and compliance. Each project is designed to demonstrate real-world security practices beyond certifications and theory.

The goal is to build a portfolio of work that reflects both technical ability and security mindset.

---

Each project is self-contained within its respective directory. For detailed information, setup instructions, and usage guidelines, please refer to the `README.md` file located inside each project's folder.

## 📂 Projects

### [AWS Security Suite](./aws-security-suite/)
![Python](https://img.shields.io/badge/Python-3.11-blue) ![AWS](https://img.shields.io/badge/AWS-Security-green)

Comprehensive AWS security suite with enterprise security hardening:
- Multi-service security scanning (EC2, S3, RDS, Lambda, IAM)
- Asynchronous scanning with rate limiting and context awareness
- Real-time monitoring and automated remediation capabilities
- NIST, CIS, and SOC 2 compliance mapping
- Advanced reporting with export capabilities

---

### [Linux Server Hardening Lab](./linux-server-hardening/)
![Linux](https://img.shields.io/badge/Linux-Hardening-yellow)

Hardened a Linux (Ubuntu 22.04 ARM) virtual machine using common security best practices:
- SSH key-only login
- Firewall configuration (UFW)
- Fail2ban for brute-force protection
- Automatic security updates
- Password policy enforcement (complexity + aging)
- Audit logging with `auditd`
- Legal warning banner for compliance

Includes configuration files, audit logs, and an automation script to collect these configs from the VM.

---

### [SSH Key Rotation Automation](./ssh-key-rotation/)
![Linux](https://img.shields.io/badge/Linux-Automation-yellow)

An automated script for rotating SSH keys on Linux servers with safety and audit logging features:
- Supports multiple old keys via `old-keys.txt`.
- Automatically detects old key fingerprints and matches against the server's `authorized_keys`.
- Backs up the existing `authorized_keys` before any changes.
- Prompts per old key found before removal to prevent accidental lockouts.
- Full session logging for auditability.

---

### [Password Strength Analyzer](./password-analyzer/)
![Python](https://img.shields.io/badge/Python-3.11-blue)

A Python-based tool for comprehensive password security evaluation according to NIST and OWASP guidelines:
- Password scoring against security best practices
- Detection of common patterns and vulnerabilities
- Entropy calculation and complexity analysis
- Secure password generation capabilities
- Interactive CLI with detailed recommendations

Includes test suite, dictionary data, and educational security guidance.

---

### [Basic Malware Analysis Lab](./malware-analysis-lab/)
![Python](https://img.shields.io/badge/Python-3.11-blue)

A safe and educational tool for performing static analysis on potentially malicious files:
- File type identification and hash calculation
- PE (Portable Executable) header analysis
- String extraction and pattern detection
- YARA rule matching for suspicious patterns
- High entropy detection for packed/encrypted content
- Safe analysis environment with no execution

Includes comprehensive analysis script, YARA rules, and educational documentation with safety protocols.

---

## 🔗 Related Repositories

### [Linux Automation Scripts](https://github.com/lucchesi-sec/linux-automation)
![Linux](https://img.shields.io/badge/Linux-Automation-yellow) ![Bash](https://img.shields.io/badge/Bash-Scripts-green)

Collection of Linux automation scripts for system administration and security tasks.

### [PowerShell Automation Scripts](https://github.com/lucchesi-sec/powershell-automation)
![PowerShell](https://img.shields.io/badge/PowerShell-Automation-blue) ![Windows](https://img.shields.io/badge/Windows-Security-red)

PowerShell automation scripts for Windows security administration and incident response.

---

## 📧 Contact

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/enzolucchesi)
