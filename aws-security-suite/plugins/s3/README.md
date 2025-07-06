# S3 Security Scanner Plugin

## Overview

The S3 Security Scanner Plugin provides comprehensive security analysis for Amazon S3 buckets, objects, and related storage infrastructure. It performs security assessments across bucket permissions, encryption, logging, versioning, and compliance validation to identify misconfigurations that could lead to data breaches.

## Security Checks Covered

### 🔒 Bucket Access Control (5 checks)
- **S3_PUBLIC_READ_ACCESS** - Detects buckets with public read permissions
- **S3_PUBLIC_WRITE_ACCESS** - Identifies buckets allowing public write access
- **S3_PUBLIC_ACCESS_BLOCK_DISABLED** - Validates Public Access Block settings
- **S3_BUCKET_POLICY_WILDCARD_ACTIONS** - Checks for overly permissive bucket policies
- **S3_ACL_WORLD_READABLE** - Identifies buckets with world-readable ACLs

### 🔐 Encryption Security (3 checks)
- **S3_ENCRYPTION_DISABLED** - Validates server-side encryption configuration
- **S3_KMS_KEY_ROTATION_DISABLED** - Checks KMS key rotation for encrypted buckets
- **S3_INSECURE_TRANSPORT** - Validates HTTPS-only access policies

### 📝 Logging and Monitoring (2 checks)
- **S3_ACCESS_LOGGING_DISABLED** - Checks access logging configuration
- **S3_CLOUDTRAIL_LOGGING_DISABLED** - Validates CloudTrail data events for buckets

### 🔄 Data Protection (3 checks)
- **S3_VERSIONING_DISABLED** - Validates versioning configuration for data protection
- **S3_MFA_DELETE_DISABLED** - Checks MFA Delete requirement for versioned buckets
- **S3_LIFECYCLE_POLICY_MISSING** - Validates lifecycle policies for cost optimization

### 🌐 Cross-Origin and Transfer (2 checks)
- **S3_CORS_POLICY_OVERPERMISSIVE** - Analyzes CORS configuration security
- **S3_TRANSFER_ACCELERATION_DISABLED** - Checks transfer acceleration for global access

## Severity Levels

| Severity | Examples | Impact |
|----------|----------|---------|
| **CRITICAL** | Public write access, unencrypted public buckets | Immediate data exposure and manipulation risk |
| **HIGH** | Public read access, disabled encryption, no access logging | Significant security vulnerability |
| **MEDIUM** | Disabled versioning, overpermissive CORS, insecure transport | Moderate security risk |
| **LOW** | Missing lifecycle policies, disabled MFA delete | Compliance and cost optimization issues |

## Required IAM Permissions

### Read-Only Scanning
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketLogging",
                "s3:GetBucketVersioning",
                "s3:GetBucketEncryption",
                "s3:GetBucketCors",
                "s3:GetBucketLifecycleConfiguration",
                "s3:GetBucketNotification",
                "s3:GetBucketTagging",
                "s3:GetAccelerateConfiguration",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:GetKeyRotationStatus",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:DescribeTrails"
            ],
            "Resource": "*"
        }
    ]
}
```

### With Remediation Capabilities
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:*",
                "kms:*",
                "cloudtrail:PutEventSelectors"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage Examples

### Basic S3 Security Scan
```bash
# Scan all S3 buckets in account
aws-security-suite scan --services s3

# Scan specific regions (note: S3 is global but regional analysis)
aws-security-suite scan --services s3 --regions us-east-1,us-west-2

# Focus on critical and high severity findings
aws-security-suite scan --services s3 --severity critical,high
```

### Targeted Scans
```bash
# Scan only public access issues
aws-security-suite scan --services s3 --checks S3_PUBLIC_READ_ACCESS,S3_PUBLIC_WRITE_ACCESS

# Focus on encryption-related issues
aws-security-suite scan --services s3 --checks S3_ENCRYPTION_DISABLED,S3_INSECURE_TRANSPORT

# Exclude specific buckets from scanning
aws-security-suite scan --services s3 --exclude-resources bucket1,bucket2
```

### Compliance Scanning
```bash
# CIS benchmark compliance
aws-security-suite scan --services s3 --compliance cis-aws

# SOC 2 compliance check
aws-security-suite scan --services s3 --compliance soc2

# PCI DSS compliance
aws-security-suite scan --services s3 --compliance pci-dss
```

## Automated Remediation

### Supported Remediations
| Finding Type | Remediation | Safety Level |
|-------------|-------------|--------------|
| `S3_PUBLIC_READ_ACCESS` | Block public read access | Safe |
| `S3_PUBLIC_WRITE_ACCESS` | Block public write access | Safe |
| `S3_PUBLIC_ACCESS_BLOCK_DISABLED` | Enable Public Access Block | Safe |
| `S3_ENCRYPTION_DISABLED` | Enable default encryption | Safe |
| `S3_ACCESS_LOGGING_DISABLED` | Enable access logging | Safe |
| `S3_VERSIONING_DISABLED` | Enable versioning | Safe |
| `S3_INSECURE_TRANSPORT` | Add HTTPS-only bucket policy | Safe |
| `S3_MFA_DELETE_DISABLED` | Enable MFA Delete requirement | Requires MFA |
| `S3_LIFECYCLE_POLICY_MISSING` | Create basic lifecycle policy | Safe |
| `S3_CORS_POLICY_OVERPERMISSIVE` | Restrict CORS policy | Requires validation |

### Remediation Examples
```bash
# Dry-run to preview changes
aws-security-suite remediate --services s3 --dry-run

# Auto-fix safe issues only
aws-security-suite remediate --services s3 --safety-level safe

# Interactive remediation with confirmation
aws-security-suite remediate --services s3 --interactive

# Remediate specific finding types
aws-security-suite remediate --finding-type S3_PUBLIC_READ_ACCESS,S3_ENCRYPTION_DISABLED
```

## Security Check Details

### Bucket Access Control

#### S3_PUBLIC_READ_ACCESS
**Description**: Identifies S3 buckets that allow public read access through bucket policies or ACLs.
**Risk**: Public read access can expose sensitive data to unauthorized users.
**Remediation**: Remove public read permissions and enable Public Access Block.

```bash
# Manual remediation
aws s3api put-public-access-block \
    --bucket mybucket \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

#### S3_PUBLIC_WRITE_ACCESS
**Description**: Detects buckets that allow public write access.
**Risk**: Public write access can lead to data tampering, malware uploads, and abuse of AWS resources.
**Remediation**: Immediately remove public write permissions.

```bash
# Remove public write ACL
aws s3api put-bucket-acl \
    --bucket mybucket \
    --acl private
```

#### S3_BUCKET_POLICY_WILDCARD_ACTIONS
**Description**: Identifies bucket policies with wildcard actions (s3:*) that may be overly permissive.
**Risk**: Overly broad permissions can grant unintended access to bucket operations.
**Remediation**: Replace wildcard actions with specific, necessary actions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::mybucket/*"
    }
  ]
}
```

### Encryption Security

#### S3_ENCRYPTION_DISABLED
**Description**: Detects buckets without default server-side encryption enabled.
**Risk**: Data stored without encryption violates compliance requirements and security best practices.
**Remediation**: Enable default encryption with AES-256 or KMS.

```bash
# Enable AES-256 encryption
aws s3api put-bucket-encryption \
    --bucket mybucket \
    --server-side-encryption-configuration \
    '{
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }
        ]
    }'

# Or enable KMS encryption
aws s3api put-bucket-encryption \
    --bucket mybucket \
    --server-side-encryption-configuration \
    '{
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "arn:aws:kms:region:account:key/key-id"
                }
            }
        ]
    }'
```

#### S3_INSECURE_TRANSPORT
**Description**: Checks if buckets enforce HTTPS-only access through bucket policies.
**Risk**: Data in transit may be intercepted if not encrypted.
**Remediation**: Add bucket policy to deny HTTP requests.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyInsecureConnections",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::mybucket",
                "arn:aws:s3:::mybucket/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
```

### Logging and Monitoring

#### S3_ACCESS_LOGGING_DISABLED
**Description**: Identifies buckets without access logging enabled.
**Risk**: No audit trail for bucket access, hindering security investigations.
**Remediation**: Enable access logging to a dedicated logging bucket.

```bash
# Enable access logging
aws s3api put-bucket-logging \
    --bucket mybucket \
    --bucket-logging-status \
    '{
        "LoggingEnabled": {
            "TargetBucket": "my-access-logs-bucket",
            "TargetPrefix": "mybucket-access-logs/"
        }
    }'
```

### Data Protection

#### S3_VERSIONING_DISABLED
**Description**: Detects buckets without versioning enabled.
**Risk**: No protection against accidental deletion or modification of objects.
**Remediation**: Enable versioning for data protection.

```bash
# Enable versioning
aws s3api put-bucket-versioning \
    --bucket mybucket \
    --versioning-configuration Status=Enabled
```

#### S3_MFA_DELETE_DISABLED
**Description**: Checks if MFA Delete is enabled for versioned buckets.
**Risk**: Objects can be permanently deleted without additional authentication.
**Remediation**: Enable MFA Delete (requires root account or MFA-authenticated user).

```bash
# Enable MFA Delete (requires MFA token)
aws s3api put-bucket-versioning \
    --bucket mybucket \
    --versioning-configuration Status=Enabled,MfaDelete=Enabled \
    --mfa "arn:aws:iam::123456789012:mfa/root-account-mfa-device 123456"
```

## Configuration Options

### Plugin Configuration
```yaml
# s3-config.yaml
s3:
  # Skip certain bucket patterns
  exclude_bucket_patterns:
    - ".*-test-.*"
    - ".*-temp-.*"
    - "aws-cloudtrail-logs-.*"
  
  # Minimum encryption standards
  required_encryption:
    algorithm: "aws:kms"  # or "AES256"
    key_rotation: true
  
  # Access logging requirements
  access_logging:
    required: true
    exclude_log_buckets: true
  
  # Compliance-specific settings
  compliance_mode: "strict"  # strict, moderate, relaxed
  
  # Regional scanning preferences
  regions_to_scan: ["us-east-1", "us-west-2", "eu-west-1"]
```

### Environment-Specific Settings
```bash
# Production environment - strict security
aws-security-suite scan --services s3 --config production-s3.yaml

# Development environment - relaxed rules
aws-security-suite scan --services s3 --config development-s3.yaml --exclude-checks S3_PUBLIC_READ_ACCESS
```

## Integration Examples

### CI/CD Pipeline Integration
```yaml
# .github/workflows/s3-security.yml
name: S3 Security Scan
on:
  schedule:
    - cron: '0 4 * * *'  # Daily at 4 AM
  push:
    paths:
      - 'infrastructure/s3/**'
    
jobs:
  s3-security:
    runs-on: ubuntu-latest
    steps:
      - name: S3 Security Scan
        run: |
          aws-security-suite scan \
            --services s3 \
            --format json \
            --severity critical,high \
            --exit-code-on-findings
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          
      - name: Upload Security Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: s3-security-report
          path: s3-findings.json
```

### Terraform Integration
```hcl
# Monitor S3 security with Lambda
resource "aws_lambda_function" "s3_security_monitor" {
  filename         = "s3-security-monitor.zip"
  function_name    = "s3-security-monitor"
  role            = aws_iam_role.lambda_role.arn
  handler         = "index.handler"
  runtime         = "python3.9"
  timeout         = 300
  
  environment {
    variables = {
      S3_SCANNER_CONFIG = "production"
    }
  }
}

resource "aws_cloudwatch_event_rule" "daily_s3_scan" {
  name                = "daily-s3-security-scan"
  description         = "Trigger S3 security scan daily"
  schedule_expression = "cron(0 6 * * ? *)"
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.daily_s3_scan.name
  target_id = "TriggerS3SecurityScan"
  arn       = aws_lambda_function.s3_security_monitor.arn
}
```

### Monitoring and Alerting
```bash
# Create CloudWatch dashboard for S3 security
aws cloudwatch put-dashboard \
  --dashboard-name "S3-Security-Dashboard" \
  --dashboard-body '{
    "widgets": [
      {
        "type": "metric",
        "properties": {
          "metrics": [
            ["AWS/SecuritySuite", "S3FindingsCount", "Severity", "CRITICAL"],
            [".", ".", ".", "HIGH"]
          ],
          "period": 300,
          "stat": "Sum",
          "region": "us-east-1",
          "title": "S3 Security Findings"
        }
      }
    ]
  }'

# Send critical findings to SNS
aws-security-suite scan --services s3 --severity critical --format json | \
jq -r '.findings[] | select(.severity == "CRITICAL") | .title' | \
while read finding; do
  aws sns publish \
    --topic-arn arn:aws:sns:us-east-1:123456789012:security-alerts \
    --message "Critical S3 Security Finding: $finding"
done
```

## Best Practices

### Regular Assessment
- **Hourly**: Monitor for new public buckets (automated)
- **Daily**: Scan for critical security issues
- **Weekly**: Comprehensive S3 security assessment
- **Monthly**: Full compliance and configuration review

### Remediation Prioritization
1. **Critical**: Public write access, unencrypted public buckets
2. **High**: Public read access, disabled encryption, no logging
3. **Medium**: Disabled versioning, overpermissive CORS
4. **Low**: Missing lifecycle policies, disabled MFA delete

### Security Hardening Checklist
- [ ] Enable Public Access Block on all buckets
- [ ] Enable default encryption (AES-256 or KMS)
- [ ] Enable access logging for audit trails
- [ ] Enable versioning for data protection
- [ ] Implement HTTPS-only access policies
- [ ] Configure appropriate CORS policies
- [ ] Set up lifecycle policies for cost optimization
- [ ] Enable MFA Delete for critical buckets
- [ ] Regular review of bucket policies and ACLs
- [ ] Monitor for new bucket creation

### Compliance Considerations
- **SOC 2**: Focus on access controls, encryption, and logging
- **PCI DSS**: Emphasize encryption and secure access requirements
- **HIPAA**: Ensure encryption at rest and in transit, audit logging
- **GDPR**: Implement data protection and retention policies
- **CIS**: Follow CIS benchmark recommendations for S3 security

### Cost Optimization
- Implement intelligent tiering for infrequently accessed data
- Set up lifecycle policies to transition to cheaper storage classes
- Enable transfer acceleration only when needed
- Regular cleanup of incomplete multipart uploads
- Monitor and optimize data transfer costs

## Advanced Features

### Custom Security Policies
```python
# Custom S3 security policy validation
def validate_custom_bucket_policy(bucket_name, policy):
    """
    Custom validation for organization-specific S3 policies
    """
    # Check for required conditions
    required_conditions = [
        "aws:SecureTransport",
        "aws:RequestedRegion"
    ]
    
    # Validate policy structure
    # Return findings for non-compliant policies
```

### Integration with SIEM
```bash
# Export findings to Splunk
aws-security-suite scan --services s3 --format json | \
jq -r '.findings[] | @json' | \
while read finding; do
  curl -X POST "https://splunk.company.com:8088/services/collector" \
    -H "Authorization: Splunk $SPLUNK_TOKEN" \
    -d "{\"event\": $finding, \"source\": \"aws-security-suite\"}"
done
```

For additional configuration options and troubleshooting, see the main [USER_GUIDE.md](../../USER_GUIDE.md) and [TROUBLESHOOTING.md](../../TROUBLESHOOTING.md).