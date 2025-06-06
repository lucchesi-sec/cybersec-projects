# Cybersecurity Projects

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

This repository contains hands-on security projects focused on practical skills in system hardening, cloud security, and compliance. Each project is designed to demonstrate real-world security practices beyond certifications and theory.

The goal is to build a portfolio of work that reflects both technical ability and security mindset.

---

Each project is self-contained within its respective directory. For detailed information, setup instructions, and usage guidelines, please refer to the `README.md` file located inside each project's folder.

## 📂 Projects

### [AWS IAM Policy Analyzer](./cloud-iam-analyzer/)
![Python](https://img.shields.io/badge/Python-3.11-blue) ![AWS](https://img.shields.io/badge/AWS-Security-green)

Identifies excessive permissions in AWS IAM policies:
- Detects wildcard actions and resources
- Flags sensitive permissions (Delete, Put, Update)
- Provides risk assessment with remediation guidance
- Supports text and JSON output formats

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

### [AWS Security Scanner](./aws-security-scanner/)
![Python](https://img.shields.io/badge/Python-3.11-blue) ![AWS](https://img.shields.io/badge/AWS-Security-green)

A Python tool for detecting common security misconfigurations in AWS S3 buckets:
- Identifies publicly accessible buckets
- Checks for server-side encryption settings
- Verifies access logging configuration
- Provides detailed remediation recommendations
- Generates formatted reports for security review

Includes colored CLI output and CSV/text reporting capabilities.

---

### [PowerShell Automation Scripts](./powershell-automation/)
![PowerShell](https://img.shields.io/badge/PowerShell-Automation-blue)

A collection of PowerShell scripts for Windows system administration, security auditing, and basic incident response tasks.
- **System Information & Auditing:** Scripts to gather comprehensive system details, local user information, and monitor critical services.
- **Log Analysis:** Tools for querying system/security event logs for errors, warnings, or specific event IDs.
- **Security Configuration Checks:** Scripts to verify patch levels, antivirus status, and audit scheduled tasks.
- **Volatile Data Collection:** Utilities to capture live network connections, ARP/DNS cache, and logged-on user data.
- **Administrative Tasks:** Scripts for checking low disk space and managing temporary files.

Includes 13 initial scripts with comment-based help and clean console output.

---

## 📧 Contact

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/enzolucchesi)
