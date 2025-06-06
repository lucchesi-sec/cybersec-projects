# Security Policy

## 🔒 Reporting Vulnerabilities
**Please report security issues to:** security@enzolucchesi.com  
**Response time:** We aim to respond within 48 hours

## 🛡️ Security Best Practices
This portfolio follows these security standards:
- Defense in Depth implementation
- Principle of Least Privilege
- Regular security scanning
- Infrastructure as Code (IaC) security reviews
- Automated compliance checks

## 🧪 Security Testing
All projects include:
- Static Application Security Testing (SAST)
- Dependency vulnerability scanning
- Infrastructure configuration checks
- Automated security hardening scripts

## 🚨 Incident Response
1. Immediate isolation of affected systems
2. Forensic analysis using audit logs
3. Patch deployment within 24 hours of vulnerability confirmation
4. Transparent disclosure to stakeholders

## 🔑 Cryptographic Standards
- SSH keys: ED25519 or RSA 4096-bit
- TLS: Minimum TLS 1.2 with strong cipher suites
- Password hashing: Argon2id with minimum 64MB memory cost

## 🛡️ Defense in Depth Implementation
```mermaid
graph LR
A[Perimeter Firewall] --> B[Host Hardening]
B --> C[Application Security]
C --> D[Data Encryption]
D --> E[Audit Logging]
E --> F[Incident Response]
