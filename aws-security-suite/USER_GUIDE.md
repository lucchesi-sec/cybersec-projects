# AWS Security Suite - User Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Phase 2 Features](#phase-2-features)
3. [Service Coverage](#service-coverage)
4. [Common Usage Patterns](#common-usage-patterns)
5. [Understanding Findings](#understanding-findings)
6. [Remediation Guide](#remediation-guide)
7. [Advanced Configuration](#advanced-configuration)
8. [Integration Examples](#integration-examples)

## Quick Start

### Installation
```bash
cd aws-security-suite
pip install -e .
```

### Your First Scan
```bash
# Scan all services in your default region
aws-security-suite scan

# Scan specific services across multiple regions
aws-security-suite scan --services s3,ec2,rds --regions us-east-1,us-west-2

# Focus on critical findings only
aws-security-suite scan --severity critical

# Export findings to JSON for further processing
aws-security-suite scan --format json > security-findings.json
```

## Core Features

AWS Security Suite provides comprehensive scanning capabilities for core AWS services with automated remediation support.

### Security Scanners
- **EC2 Security Scanner**: 16 comprehensive security checks covering instances, security groups, EBS volumes, and VPC configuration
- **RDS Security Scanner**: Database security analysis including encryption, backup, and public accessibility checks
- **Lambda Security Scanner**: Function security assessment covering runtime, permissions, and configuration
- **S3 Security Scanner**: Bucket security assessment with public access and encryption validation
- **Async Performance Engine**: 5-10x faster scanning through concurrent operations
- **Auto-Remediation Framework**: 80%+ of findings can be automatically fixed with safety checks

### Enhanced Capabilities
- **Multi-Region Scanning**: Concurrent analysis across all AWS regions
- **Compliance Mapping**: Automatic mapping to CIS, SOC2, and AWS Config Rules frameworks
- **Rich CLI Interface**: Beautiful, interactive command-line experience
- **Export Options**: JSON, CSV, and formatted text outputs
- **Performance Optimized**: Handles enterprise-scale AWS environments

## Service Coverage

### EC2 Security Scanner
**16 Security Checks | 13 Auto-Remediations**

| Category | Checks | Auto-Fix |
|----------|--------|----------|
| Instance Security | 5 checks | 4 automated |
| Security Groups | 2 checks | 2 automated |
| EBS Security | 2 checks | 2 automated |
| VPC Security | 2 checks | 1 automated |
| Enhanced Checks | 5 checks | 4 automated |

**Key Security Validations:**
- Public instance detection and remediation
- Security group overly permissive rules (0.0.0.0/0)
- EBS volume encryption enforcement
- Instance Metadata Service v2 validation
- Production termination protection
- Tag compliance for governance

### RDS Security Scanner
**Database Security Assessment**

- **Encryption**: At-rest and in-transit encryption validation
- **Public Access**: Public RDS instance detection
- **Backup Security**: Automated backup configuration checks
- **Parameter Groups**: Security parameter validation
- **Subnet Groups**: Network isolation verification

### Lambda Security Scanner
**Function Security Analysis**

- **Runtime Security**: Deprecated runtime detection
- **IAM Permissions**: Overprivileged execution role analysis
- **Environment Variables**: Sensitive data exposure checks
- **VPC Configuration**: Network security validation
- **Monitoring**: CloudWatch logs and X-Ray tracing verification

### S3 Security Scanner
**Bucket Security Assessment**

- **Public Access**: Comprehensive public access detection
- **Encryption**: Server-side encryption validation
- **Logging**: Access logging configuration checks
- **Versioning**: Data protection through versioning
- **CORS Policies**: Cross-origin resource sharing security

## Common Usage Patterns

### Daily Security Assessment
```bash
# Quick daily scan focusing on critical issues
aws-security-suite scan --severity critical,high --format table

# Export for team review
aws-security-suite scan --format json | jq '.findings[] | select(.severity == "CRITICAL")'
```

### Compliance Auditing
```bash
# Scan for SOC2 compliance
aws-security-suite scan --compliance soc2

# Generate compliance report
aws-security-suite scan --format compliance-report > monthly-audit.txt
```

### Continuous Integration
```bash
# CI/CD pipeline integration
aws-security-suite scan --format json --exit-code-on-findings

# Only fail on critical findings
aws-security-suite scan --severity critical --exit-code-on-findings
```

### Multi-Account Scanning
```bash
# Scan across multiple AWS accounts using assume role
aws-security-suite scan --assume-role arn:aws:iam::123456789012:role/SecurityAuditRole

# Cross-account scanning with custom session name
aws-security-suite scan --assume-role arn:aws:iam::123456789012:role/SecurityAuditRole --session-name security-scan-$(date +%Y%m%d)
```

## Understanding Findings

### Severity Levels

| Severity | Description | Examples | Action Required |
|----------|-------------|----------|-----------------|
| **CRITICAL** | Immediate security risk | Public snapshots, databases accessible from internet | Fix immediately |
| **HIGH** | Significant vulnerability | Unencrypted data, overprivileged access | Fix within 24-48 hours |
| **MEDIUM** | Moderate security concern | Missing monitoring, default configurations | Fix within 1 week |
| **LOW** | Best practice violation | Missing tags, non-critical misconfigurations | Fix during next maintenance |

### Finding Structure
```json
{
  "id": "EC2_SG_OPEN_TO_WORLD_001",
  "service": "EC2",
  "severity": "HIGH",
  "title": "Security Group allows unrestricted access from internet",
  "description": "Security group sg-12345678 allows inbound access from 0.0.0.0/0 on port 22 (SSH)",
  "remediation": {
    "description": "Remove or restrict the overly permissive rule",
    "automated": true,
    "steps": ["aws ec2 revoke-security-group-ingress --group-id sg-12345678 --protocol tcp --port 22 --cidr 0.0.0.0/0"]
  },
  "compliance": ["CIS-3.10", "SOC2-CC6.1"],
  "resources": ["sg-12345678"],
  "region": "us-east-1"
}
```

## Remediation Guide

### Automated Remediation
The suite supports automated fixing of 80%+ of security findings with built-in safety checks.

#### Safe Auto-Remediation
```bash
# Dry-run to see what would be fixed
aws-security-suite remediate --dry-run

# Auto-fix specific finding types
aws-security-suite remediate --finding-type EC2_EBS_VOLUME_NOT_ENCRYPTED

# Auto-fix with confirmation prompts
aws-security-suite remediate --interactive

# Batch remediation with safety limits
aws-security-suite remediate --max-changes 10 --severity high
```

#### Manual Remediation
For findings that require manual intervention:

1. **Review the finding details** in the scan output
2. **Check remediation steps** provided in the finding
3. **Test changes in non-production** environment first
4. **Apply fixes incrementally** with monitoring
5. **Re-scan to verify** fixes were successful

### Remediation Safety Features
- **Dry-run mode**: Preview changes before applying
- **Rollback capability**: Reverse changes if needed
- **Change limits**: Prevent bulk accidental modifications
- **Audit logging**: All changes logged for compliance
- **Interactive mode**: Confirm each change individually

## Advanced Configuration

### Custom Severity Thresholds
```bash
# Create custom severity mapping
cat > custom-severity.yaml << EOF
severity_rules:
  EC2_INSTANCE_PUBLIC_IP: CRITICAL  # Upgrade from MEDIUM
  EC2_MISSING_TAGS: LOW             # Downgrade from MEDIUM
EOF

aws-security-suite scan --severity-config custom-severity.yaml
```

### Environment-Specific Scanning
```bash
# Production environment with strict rules
aws-security-suite scan --profile production --severity critical,high

# Development environment with relaxed checking
aws-security-suite scan --profile development --exclude-checks EC2_INSTANCE_PUBLIC_IP,EC2_DEFAULT_VPC_USAGE
```

### Performance Tuning
```bash
# Increase concurrency for large environments
aws-security-suite scan --max-concurrent-regions 5 --max-concurrent-services 10

# Rate limiting for sensitive environments
aws-security-suite scan --rate-limit 10  # 10 API calls per second
```

## Integration Examples

### CI/CD Pipeline Integration

#### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install AWS Security Suite
        run: pip install ./aws-security-suite
      - name: Run Security Scan
        run: aws-security-suite scan --format json --severity critical --exit-code-on-findings
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'aws-security-suite scan --format json > security-findings.json'
                sh 'aws-security-suite scan --severity critical --exit-code-on-findings'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-findings.json'
                }
            }
        }
    }
}
```

### Monitoring Integration

#### CloudWatch Integration
```bash
# Export findings to CloudWatch Logs
aws-security-suite scan --format json | aws logs put-log-events \
  --log-group-name /aws/security-suite/findings \
  --log-stream-name daily-scan-$(date +%Y%m%d)
```

#### Slack Notifications
```bash
# Send critical findings to Slack
CRITICAL_COUNT=$(aws-security-suite scan --severity critical --format json | jq '.findings | length')
if [ $CRITICAL_COUNT -gt 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"🚨 $CRITICAL_COUNT critical security findings detected!\"}" \
    $SLACK_WEBHOOK_URL
fi
```

### Security Orchestration

#### SOAR Integration
```python
import json
import subprocess

def run_security_scan():
    """Run AWS Security Suite and return structured findings"""
    result = subprocess.run([
        'aws-security-suite', 'scan', 
        '--format', 'json', 
        '--severity', 'critical,high'
    ], capture_output=True, text=True)
    
    return json.loads(result.stdout)

def create_tickets_for_critical_findings(findings):
    """Create SOAR tickets for critical findings"""
    for finding in findings['findings']:
        if finding['severity'] == 'CRITICAL':
            # Integration with your SOAR platform
            create_incident_ticket(finding)
```

## Next Steps

1. **Start with Quick Start**: Run your first scan to understand your security posture
2. **Review Findings**: Focus on CRITICAL and HIGH severity issues first
3. **Test Remediation**: Use dry-run mode to understand proposed fixes
4. **Automate Scanning**: Integrate into your CI/CD pipelines
5. **Customize Rules**: Adapt severity levels to your environment
6. **Monitor Progress**: Track security improvements over time

For troubleshooting help, see [TROUBLESHOOTING.md](./TROUBLESHOOTING.md).
For compliance mapping details, see [COMPLIANCE_MAPPING.md](./COMPLIANCE_MAPPING.md).