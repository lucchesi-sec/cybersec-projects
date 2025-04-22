# Cybersecurity Projects

This repository contains hands-on security projects focused on practical skills in system hardening, cloud security, and compliance. Each project is designed to demonstrate real-world security practices beyond certifications and theory.

The goal is to build a portfolio of work that reflects both technical ability and security mindset.

---

## 📂 Projects

### ✅ [Linux Server Hardening Lab](./linux-server-hardening/)
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

### ✅ [SSH Key Rotation Automation](./ssh-key-rotation/)
An automated script for rotating SSH keys on Linux servers with safety and audit logging features:
- Supports multiple old keys via `old-keys.txt`.
- Automatically detects old key fingerprints and matches against the server’s `authorized_keys`.
- Backs up the existing `authorized_keys` before any changes.
- Prompts per old key found before removal to prevent accidental lockouts.
- Full session logging for auditability.

---

## 🎯 Purpose
This repo serves as my personal cybersecurity lab space. The focus is on learning by doing — applying security concepts in a way that directly maps to real-world environments.

---

## 🛠️ Repository History Notice

> **Important:**
> The commit history of this repository was rewritten on **April 22, 2025** to correct early misconfigured commit author identity.
> Only the intended contributor (`lucchesi-sec`) is now reflected in the history.
>
> See [HISTORY.md](./HISTORY.md) for details.

---

## 🚀 What's Next
Future additions may include:
- 
- 
- 

---

## 📬 Contact
Reach out via [LinkedIn](https://www.linkedin.com/in/enzo-lucchesi) if you'd like to connect or discuss these projects.
