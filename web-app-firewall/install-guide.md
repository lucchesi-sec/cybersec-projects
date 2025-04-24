# ModSecurity WAF Installation and Configuration Guide

This guide provides step-by-step instructions for installing and configuring ModSecurity with OWASP Core Rule Set (CRS) on Ubuntu 22.04 with Apache.

## Prerequisites
- Ubuntu 22.04 LTS
- Apache 2.4
- Root or sudo access
- Internet connectivity

## Installation Steps

### 1. Update System Packages
```bash
sudo apt update
sudo apt upgrade -y
```

### 2. Install Apache (if not already installed)
```bash
sudo apt install -y apache2
```

### 3. Install ModSecurity and Required Dependencies
```bash
sudo apt install -y libapache2-mod-security2 libapache2-mod-security2-dev
```

### 4. Configure ModSecurity Base Setup
```bash
# Create backup of default configuration
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Enable ModSecurity
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
```

### 5. Download and Install OWASP CRS
```bash
# Move to the ModSecurity directory
cd /etc/modsecurity

# Download the latest OWASP CRS
sudo wget https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.4.tar.gz

# Extract the archive
sudo tar -xzvf v3.3.4.tar.gz

# Create a symbolic link for easier access
sudo ln -s coreruleset-3.3.4 crs

# Setup the CRS configuration
sudo cp crs/crs-setup.conf.example crs/crs-setup.conf
```

### 6. Configure Apache to Use ModSecurity
```bash
# Create ModSecurity configuration file for Apache
sudo bash -c 'cat << EOF > /etc/apache2/mods-available/security2.conf
<IfModule security2_module>
    # Load ModSecurity configuration
    IncludeOptional /etc/modsecurity/modsecurity.conf

    # Load OWASP CRS
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf

    # Load custom rules
    IncludeOptional /etc/modsecurity/custom-rules.conf
</IfModule>
EOF'

# Enable ModSecurity module
sudo a2enmod security2
```

### 7. Create Custom Rules Configuration
```bash
# Create custom rules file
sudo bash -c 'cat << EOF > /etc/modsecurity/custom-rules.conf
# Custom ModSecurity Rules
# Include your custom rules here

# Example: Block specific user agents
SecRule REQUEST_HEADERS:User-Agent "@contains vulnerability scanner" \
    "id:10000,phase:1,deny,status:403,log,msg:'Scanner User-Agent Blocked'"

# Example: Block common web shells
SecRule REQUEST_FILENAME "@rx (?:c99|r57|shell|webshell|cmd|phpshell)\\.(?:php|asp|aspx|jsp|pl)" \
    "id:10001,phase:1,deny,status:403,log,msg:'Web Shell Access Attempt'"
EOF'
```

### 8. Test the Configuration
```bash
# Test Apache configuration
sudo apache2ctl configtest

# If the test is successful, restart Apache
sudo systemctl restart apache2
```

### 9. Verify ModSecurity is Working
```bash
# Send a test request with a SQL injection payload
curl -I "http://localhost/?id=1' OR '1'='1"

# Check ModSecurity audit log
sudo tail -f /var/log/apache2/modsec_audit.log
```

## Configuring Protection Levels

### Basic Protection (Default)
The default OWASP CRS configuration provides a good balance between security and false positives.

### Enhanced Protection
To increase protection (may increase false positives):

```bash
# Edit CRS setup
sudo nano /etc/modsecurity/crs/crs-setup.conf

# Change paranoia level from 1 to 2 or higher (max 4)
# Find and change this line:
# - From: SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.paranoia_level=1"
# - To:   SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.paranoia_level=2"

# Restart Apache
sudo systemctl restart apache2
```

### Production Tuning
For production environments, you should:

1. Run ModSecurity in detection mode first
   ```bash
   sudo sed -i 's/SecRuleEngine On/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf
   ```

2. Monitor logs for false positives
   ```bash
   sudo tail -f /var/log/apache2/modsec_audit.log
   ```

3. Create whitelist rules for legitimate traffic that triggers rules

4. Re-enable blocking mode
   ```bash
   sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
   ```

## Troubleshooting

### Common Issues and Solutions

1. **Apache won't start after configuration:**
   - Check for syntax errors: `sudo apache2ctl configtest`
   - Look at Apache error logs: `sudo tail -f /var/log/apache2/error.log`

2. **ModSecurity blocks legitimate traffic:**
   - Identify the rule ID from the audit log
   - Create a whitelist rule for that specific case
   - Example whitelist:
     ```
     SecRule REQUEST_URI "@beginsWith /api/special-endpoint" \
        "id:1000,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
     ```

3. **Performance issues:**
   - Reduce rule set by disabling rules you don't need
   - Increase Apache performance settings in `/etc/apache2/mods-available/mpm_prefork.conf`
   - Consider running ModSecurity only on critical applications

## Logging and Monitoring

ModSecurity logs can be found at:
- Audit log: `/var/log/apache2/modsec_audit.log`
- Debug log: `/var/log/apache2/modsec_debug.log`

For better visibility, consider forwarding logs to a SIEM system or ELK stack.

## Security Maintenance

1. Regularly update the OWASP CRS to the latest version
2. Review ModSecurity logs for attack patterns
3. Update custom rules based on emerging threats
4. Test rule changes in a staging environment before deploying to production