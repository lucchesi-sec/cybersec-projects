# Web Application Firewall Implementation

> **Note:** This project is a demonstration of how to set up and configure a web application firewall. It includes configuration files and documentation, but requires actual implementation on a web server to function.

## Overview
This project demonstrates how to implement a Web Application Firewall (WAF) using ModSecurity with OWASP Core Rule Set (CRS). The documentation shows how to protect a web application against common attacks like SQL injection, cross-site scripting (XSS), and command injection.

## Why Use a Web Application Firewall?
- Protects web applications from common attack vectors
- Provides an additional layer of security beyond application code
- Helps comply with security regulations (PCI-DSS, etc.)
- Can be implemented without modifying application code

## Prerequisites for Implementation

To follow the `install-guide.md` and set up this WAF demonstration, you will generally need:

-   **A Linux Server:** A virtual machine or physical server running a common Linux distribution (e.g., Ubuntu, Debian, CentOS). The guide was tested on Ubuntu 22.04.
-   **Web Server Software:** An installed and running web server. ModSecurity is commonly used with:
    -   Apache (version 2.4.x recommended, as used in testing)
    -   Nginx
-   **Administrative Privileges:** Root or `sudo` access on the server to install packages and modify web server configurations.
-   **Basic Linux & Web Server Knowledge:** Familiarity with using the Linux command line, text editors (like `nano` or `vim`), and basic concepts of web server configuration (e.g., virtual hosts, modules).
-   **PHP (for testing):** If you intend to use the provided `tests/vulnerable-app.php`, you'll need PHP installed and configured with your web server.

## Project Components

### Documentation
- `install-guide.md`: Step-by-step installation instructions for ModSecurity
- `before-after.md`: Examples of attacks before and after WAF implementation (conceptual examples)

### Configuration Files
- `config/modsecurity.conf`: Main ModSecurity configuration
- `config/custom-rules.conf`: Custom rules for specific application protection

### Testing
- `tests/vulnerable-app.php`: A deliberately vulnerable PHP application for testing WAF rules
- `tests/attack-test.sh`: Shell script to test various attack patterns against the app

## Getting Started

To implement this WAF on your own server:

1. Follow the detailed instructions in `install-guide.md`
2. Apply the configuration files from the `config/` directory
3. Test your implementation with the test scripts in `tests/`

## Security Controls Implemented

The configuration demonstrates protection against:
- SQL Injection attacks
- Cross-Site Scripting (XSS)
- Local/Remote File Inclusion
- Command Injection
- Path Traversal
- Protocol Violations
- Malicious Scanners and Bots

## Notes
- This is a demonstration project - implementation requires a real web server
- Tested on Ubuntu 22.04 with Apache 2.4
- Based on ModSecurity v3.0 and OWASP CRS v3.3
- Configuration is set to "detect and block" mode with logging

## Learning Resources
- [ModSecurity GitHub Repository](https://github.com/SpiderLabs/ModSecurity)
- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/)
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki)
