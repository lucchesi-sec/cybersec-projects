# Cybersecurity Projects Portfolio

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg) ![Projects](https://img.shields.io/badge/Projects-7-brightgreen) ![Security](https://img.shields.io/badge/Security-Enterprise--Ready-red)

Comprehensive cybersecurity toolkit covering the full spectrum of modern security challenges - from preventive scanning and hardening to reactive incident response. This portfolio demonstrates enterprise-grade security practices through hands-on implementation of defensive security tools and automation.

**Portfolio Coverage**: Cloud Security • Network Security • Incident Response • System Hardening • Malware Analysis • Identity Management • Compliance Automation

---

Each project is self-contained within its respective directory. For detailed information, setup instructions, and usage guidelines, please refer to the `README.md` file located inside each project's folder.

## 🔐 Security Projects Portfolio

### 🌩️ [AWS Security Suite](./aws-security-suite/)
![Python](https://img.shields.io/badge/Python-3.11-blue) ![AWS](https://img.shields.io/badge/AWS-Enterprise-orange) ![Async](https://img.shields.io/badge/Async-Concurrent-green)

**Enterprise-grade AWS security scanning and compliance automation**
- **Multi-service coverage**: EC2, S3, RDS, Lambda, IAM security assessment
- **Plugin architecture**: Modular, extensible design with 70+ security checks
- **Async scanning**: Concurrent operations with intelligent rate limiting
- **Compliance frameworks**: NIST, CIS, SOC2, PCI DSS mapping and reporting
- **Enterprise features**: Cross-account scanning, automated remediation
- **Recent enhancement**: Lambda scanner refactored into 7 specialized modules (933→200 lines avg)

---

### 🛡️ [Network Security Scanner](./network-security-scanner/) ⭐ **NEW**
![Python](https://img.shields.io/badge/Python-3.11-blue) ![Network](https://img.shields.io/badge/Network-Security-red) ![Ethical](https://img.shields.io/badge/Ethical-Scanning-green)

**Comprehensive network vulnerability assessment and security scanning**
- **Port scanning**: TCP/UDP with nmap integration and socket-based fallback
- **Service detection**: Banner grabbing and version fingerprinting
- **Security validation**: Built-in target validation and ethical scanning guidelines
- **SSL/TLS analysis**: Certificate validation and cipher suite assessment
- **Stealth options**: Configurable timing, fragmentation, and decoy addresses
- **Vulnerability framework**: Extensible plugin system for custom checks
- **Safety-first**: Prevents scanning unauthorized targets and critical infrastructure

---

### 🚨 [Incident Response Automation](./incident-response-automation/) ⭐ **NEW**
![Python](https://img.shields.io/badge/Python-3.11-blue) ![SIEM](https://img.shields.io/badge/SIEM-Integration-purple) ![NIST](https://img.shields.io/badge/NIST-Framework-blue)

**Enterprise incident response orchestration and automation platform**
- **Threat detection**: Real-time analysis with behavioral anomaly detection
- **Automated analysis**: Incident classification and severity scoring
- **Response orchestration**: NIST/SANS framework-compliant automation
- **SIEM integration**: ELK Stack, Splunk, and custom data source support
- **Escalation management**: Time-based thresholds and severity progression
- **Compliance ready**: SOC2, PCI DSS, NIST incident response requirements
- **Enterprise features**: Multi-tenant, audit logging, evidence preservation

---

### 🐧 [Linux Server Hardening](./linux-server-hardening/)
![Linux](https://img.shields.io/badge/Linux-Hardening-yellow) ![ELK](https://img.shields.io/badge/ELK-Stack-orange) ![CIS](https://img.shields.io/badge/CIS-Benchmarks-blue)

**Comprehensive Linux security hardening with monitoring integration**
- **Defense-in-depth**: SSH, firewall, intrusion prevention, audit logging
- **ELK Stack integration**: Centralized logging and security monitoring
- **Automated hardening**: Script-based deployment with idempotency
- **Compliance mapping**: CIS benchmarks and security best practices
- **Monitoring capabilities**: Real-time security event correlation
- **Recent updates**: Modern GPG key management and shell script security

---

### 🔑 [SSH Key Rotation Automation](./ssh-key-rotation/)
![Linux](https://img.shields.io/badge/Linux-Automation-yellow) ![Security](https://img.shields.io/badge/Key-Management-blue)

**Automated SSH key lifecycle management with enterprise safety features**
- **Safe rotation**: Multi-key support with fingerprint verification
- **Backup and rollback**: Comprehensive backup mechanisms with recovery
- **Audit logging**: Complete session logging for compliance requirements
- **Safety protocols**: Interactive confirmation and lockout prevention
- **Enterprise ready**: Batch operations and integration capabilities

---

### 🔐 [Password Analyzer](./password-analyzer/)
![Python](https://img.shields.io/badge/Python-3.11-blue) ![NIST](https://img.shields.io/badge/NIST-Compliant-green) ![OWASP](https://img.shields.io/badge/OWASP-Guidelines-red)

**NIST SP 800-63B compliant password security assessment**
- **Security standards**: NIST and OWASP guideline implementation
- **Pattern detection**: Advanced threat intelligence and dictionary analysis
- **Entropy calculation**: Cryptographic randomness assessment
- **Interactive CLI**: User-friendly interface with detailed recommendations
- **Recent security fix**: Replaced os.system() with secure subprocess implementation

---

### 🦠 [Malware Analysis Lab](./malware-analysis-lab/)
![Python](https://img.shields.io/badge/Python-3.11-blue) ![YARA](https://img.shields.io/badge/YARA-Rules-orange) ![Educational](https://img.shields.io/badge/Educational-Safe-green)

**Educational static malware analysis with YARA integration**
- **Static analysis**: PE header analysis, string extraction, entropy detection
- **YARA integration**: Custom rule development and threat pattern matching
- **Educational focus**: Safe learning environment with no-execution protocols
- **Threat intelligence**: Integration with security research methodologies
- **Safety protocols**: Comprehensive handling procedures for educational use

---

## 🎯 Portfolio Architecture

This cybersecurity portfolio demonstrates **enterprise-grade security practices** through:

### **🔍 Defensive Security Coverage**
- **Preventive Controls**: AWS security scanning, network vulnerability assessment, system hardening
- **Detective Controls**: Incident response automation, threat detection, behavioral analysis
- **Corrective Controls**: Automated remediation, response orchestration, compliance enforcement

### **🏗️ Technical Excellence**
- **Plugin Architecture**: Extensible, maintainable codebase across all projects
- **Async/Await Patterns**: High-performance concurrent operations for enterprise scale
- **Security-First Design**: Input validation, secure coding practices, ethical guidelines
- **Compliance Ready**: NIST, OWASP, CIS, SOC2, PCI DSS framework implementation

### **📊 Recent Enhancements**
- ✅ **Lambda scanner refactored**: 933 lines → 7 modular analyzers (avg 200 lines)
- ✅ **Security hardening**: Replaced os.system() with secure subprocess implementation
- ✅ **Modern package management**: Updated deprecated apt-key usage to GPG keys
- ⭐ **NEW: Network Security Scanner**: Comprehensive ethical scanning platform
- ⭐ **NEW: Incident Response Automation**: Enterprise threat response orchestration

---

## 🚀 Getting Started

Each project is self-contained with comprehensive documentation:

```bash
# Clone repository
git clone https://github.com/lucchesi-sec/cybersec-projects.git
cd cybersec-projects

# Explore individual projects
ls -la  # View all 7 security projects

# Each project includes:
# ├── README.md          # Comprehensive setup and usage guide
# ├── requirements.txt   # Dependencies and installation
# ├── src/              # Source code with security-first design
# ├── tests/            # Test suites and validation
# └── docs/             # Additional documentation
```

---

## 🔗 Related Repositories

### [Linux Automation Scripts](https://github.com/lucchesi-sec/linux-automation)
![Linux](https://img.shields.io/badge/Linux-Automation-yellow) ![Bash](https://img.shields.io/badge/Bash-Scripts-green)

Collection of Linux automation scripts for system administration and security tasks.

### [PowerShell Automation Scripts](https://github.com/lucchesi-sec/powershell-automation)
![PowerShell](https://img.shields.io/badge/PowerShell-Automation-blue) ![Windows](https://img.shields.io/badge/Windows-Security-red)

PowerShell automation scripts for Windows security administration and incident response.

---

## 📈 Impact & Metrics

**Portfolio Scope**: 7 comprehensive security tools covering prevention, detection, and response
**Code Quality**: 92/100 documentation coverage, 70% test coverage, security-first design
**Compliance**: NIST, OWASP, CIS, SOC2, PCI DSS framework implementation
**Architecture**: Plugin-based, async/await, enterprise-ready with audit capabilities

---

## 📧 Contact

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/enzolucchesi)
