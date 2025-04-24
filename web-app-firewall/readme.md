# Web Application Firewall Implementation

## Overview
This project demonstrates a basic implementation of a Web Application Firewall (WAF) using ModSecurity with OWASP Core Rule Set (CRS). The WAF is configured to protect a simple web application against common web attacks, including SQL injection, cross-site scripting (XSS), and command injection.

## Why Use a Web Application Firewall?
- Protects web applications from common attack vectors
- Provides an additional layer of security beyond application code
- Helps comply with security regulations (PCI-DSS, etc.)
- Can be implemented without modifying application code

## How It Works
1. **ModSecurity**: An open-source WAF that works as a module for web servers (Apache, Nginx)
2. **OWASP CRS**: A set of generic attack detection rules for ModSecurity
3. **Request Filtering**: Analyzes HTTP requests before they reach the application
4. **Attack Prevention**: Blocks malicious requests based on rule matches
5. **Logging**: Records security events for analysis and reporting

## Implementation Steps
1. Install ModSecurity and OWASP CRS
2. Configure basic protection rules
3. Test with common attack payloads
4. Tune rules to reduce false positives
5. Deploy in production mode

## Security Controls Implemented
- SQL Injection Prevention
- Cross-Site Scripting (XSS) Protection
- Local File Inclusion (LFI) Protection
- Remote File Inclusion (RFI) Protection
- Command Injection Protection
- Protocol Violation Checks
- Scanner/Bot Detection

## Test Results
The WAF was tested against various attack vectors:
- SQL Injection attempts: Blocked ✅
- XSS Payloads: Blocked ✅
- Path Traversal Attacks: Blocked ✅
- Command Injection: Blocked ✅

## 📸 Screenshots
- WAF Installation and Configuration
- Attack Attempts and Blocked Requests
- Security Logging and Notifications

## Configuration Files
- `modsecurity.conf`: Main ModSecurity configuration
- `crs-setup.conf`: Core Rule Set configuration
- `custom-rules.conf`: Custom rules for specific application needs

## Notes
- Tested on Ubuntu 22.04 with Apache 2.4
- Uses ModSecurity v3.0 and OWASP CRS v3.3
- Configured in "detect and block" mode with logging