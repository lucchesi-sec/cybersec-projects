# AWS Security Suite - Compliance Framework Mapping

## Table of Contents
1. [Overview](#overview)
2. [CIS AWS Foundations Benchmark](#cis-aws-foundations-benchmark)
3. [SOC 2 Type II Controls](#soc-2-type-ii-controls)
4. [AWS Config Rules](#aws-config-rules)
5. [PCI DSS Requirements](#pci-dss-requirements)
6. [NIST Cybersecurity Framework](#nist-cybersecurity-framework)
7. [Compliance Reporting](#compliance-reporting)
8. [Custom Compliance Frameworks](#custom-compliance-frameworks)

## Overview

AWS Security Suite automatically maps security findings to major compliance frameworks, helping organizations demonstrate adherence to industry standards and regulatory requirements.

### Supported Frameworks
- **CIS AWS Foundations Benchmark v1.4**: Industry best practices for AWS security
- **SOC 2 Type II**: Trust services criteria for security, availability, and confidentiality
- **AWS Config Rules**: AWS-recommended security configurations
- **PCI DSS**: Payment card industry data security standards
- **NIST Cybersecurity Framework**: Risk-based approach to cybersecurity

### Compliance Coverage
| Framework | Coverage | Automated Checks | Remediation |
|-----------|----------|------------------|-------------|
| CIS AWS v1.4 | 85% | 45+ checks | 80% automated |
| SOC 2 Type II | 70% | 35+ checks | 75% automated |
| AWS Config Rules | 90% | 50+ checks | 85% automated |
| PCI DSS | 60% | 25+ checks | 70% automated |
| NIST CSF | 65% | 30+ checks | 75% automated |

## CIS AWS Foundations Benchmark

### Identity and Access Management (Section 1)

| CIS Control | AWS Security Suite Check | Severity | Auto-Fix |
|-------------|---------------------------|----------|----------|
| 1.3 | Ensure credentials unused for 90 days or greater are disabled | `IAM_INACTIVE_USERS` | ✅ |
| 1.4 | Ensure access keys are rotated every 90 days | `IAM_OLD_ACCESS_KEYS` | ❌ |
| 1.5 | Ensure IAM password policy requires minimum length of 14 | `IAM_WEAK_PASSWORD_POLICY` | ✅ |
| 1.6 | Ensure IAM password policy prevents password reuse | `IAM_PASSWORD_REUSE_POLICY` | ✅ |
| 1.7 | Ensure IAM password policy requires uppercase characters | `IAM_PASSWORD_COMPLEXITY` | ✅ |
| 1.8 | Ensure IAM password policy requires lowercase characters | `IAM_PASSWORD_COMPLEXITY` | ✅ |
| 1.9 | Ensure IAM password policy requires symbols | `IAM_PASSWORD_COMPLEXITY` | ✅ |
| 1.10 | Ensure IAM password policy requires numbers | `IAM_PASSWORD_COMPLEXITY` | ✅ |
| 1.11 | Ensure IAM password policy expires passwords | `IAM_PASSWORD_EXPIRY` | ✅ |
| 1.12 | Ensure no root account access key exists | `IAM_ROOT_ACCESS_KEYS` | ❌ |
| 1.13 | Ensure MFA is enabled for root account | `IAM_ROOT_MFA_DISABLED` | ❌ |
| 1.14 | Ensure hardware MFA is enabled for root account | `IAM_ROOT_HARDWARE_MFA` | ❌ |

### Storage (Section 2)

| CIS Control | AWS Security Suite Check | Severity | Auto-Fix |
|-------------|---------------------------|----------|----------|
| 2.1.1 | Ensure S3 bucket access logging is enabled | `S3_ACCESS_LOGGING_DISABLED` | ✅ |
| 2.1.2 | Ensure S3 bucket has MFA Delete enabled | `S3_MFA_DELETE_DISABLED` | ❌ |
| 2.1.3 | Ensure S3 buckets are configured with 'Block public access' | `S3_PUBLIC_ACCESS_ENABLED` | ✅ |
| 2.1.4 | Ensure S3 bucket has object-level logging enabled | `S3_OBJECT_LOGGING_DISABLED` | ✅ |
| 2.2.1 | Ensure EBS volume encryption is enabled | `EC2_EBS_VOLUME_NOT_ENCRYPTED` | ✅ |
| 2.2.2 | Ensure EBS volumes are attached to EC2 instances | `EC2_EBS_VOLUME_UNATTACHED` | ❌ |

### Logging (Section 3)

| CIS Control | AWS Security Suite Check | Severity | Auto-Fix |
|-------------|---------------------------|----------|----------|
| 3.1 | Ensure CloudTrail is enabled in all regions | `CLOUDTRAIL_NOT_ENABLED` | ✅ |
| 3.2 | Ensure CloudTrail log file validation is enabled | `CLOUDTRAIL_LOG_VALIDATION_DISABLED` | ✅ |
| 3.3 | Ensure S3 bucket used for CloudTrail is not publicly accessible | `CLOUDTRAIL_S3_PUBLIC_ACCESS` | ✅ |
| 3.4 | Ensure CloudTrail trails are integrated with CloudWatch Logs | `CLOUDTRAIL_CLOUDWATCH_LOGS_DISABLED` | ✅ |
| 3.5 | Ensure AWS Config is enabled in all regions | `CONFIG_NOT_ENABLED` | ✅ |
| 3.6 | Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket | `CLOUDTRAIL_S3_ACCESS_LOGGING` | ✅ |
| 3.7 | Ensure CloudTrail logs are encrypted at rest | `CLOUDTRAIL_ENCRYPTION_DISABLED` | ✅ |
| 3.10 | Ensure that Object-level logging for write events is enabled for S3 bucket | `S3_OBJECT_WRITE_LOGGING` | ✅ |
| 3.11 | Ensure that Object-level logging for read events is enabled for S3 bucket | `S3_OBJECT_READ_LOGGING` | ✅ |

### Monitoring (Section 4)

| CIS Control | AWS Security Suite Check | Severity | Auto-Fix |
|-------------|---------------------------|----------|----------|
| 4.1 | Ensure log metric filter and alarm exist for unauthorized API calls | `CLOUDWATCH_UNAUTHORIZED_API_CALLS` | ✅ |
| 4.2 | Ensure log metric filter and alarm exist for Management Console sign-in without MFA | `CLOUDWATCH_CONSOLE_NO_MFA` | ✅ |
| 4.3 | Ensure log metric filter and alarm exist for usage of 'root' account | `CLOUDWATCH_ROOT_USAGE` | ✅ |
| 4.4 | Ensure log metric filter and alarm exist for IAM changes | `CLOUDWATCH_IAM_CHANGES` | ✅ |
| 4.5 | Ensure log metric filter and alarm exist for CloudTrail changes | `CLOUDWATCH_CLOUDTRAIL_CHANGES` | ✅ |

### Networking (Section 5)

| CIS Control | AWS Security Suite Check | Severity | Auto-Fix |
|-------------|---------------------------|----------|----------|
| 5.1 | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports | `EC2_NACL_UNRESTRICTED_ACCESS` | ✅ |
| 5.2 | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports | `EC2_SG_OPEN_TO_WORLD` | ✅ |
| 5.3 | Ensure VPC flow logging is enabled in all VPCs | `EC2_VPC_FLOW_LOGS_DISABLED` | ✅ |
| 5.4 | Ensure the default security group restricts all traffic | `EC2_DEFAULT_SG_UNRESTRICTED` | ✅ |

## SOC 2 Type II Controls

### Common Criteria (CC)

#### CC6.1 - Logical and Physical Access Controls
| Control | AWS Security Suite Check | Implementation |
|---------|---------------------------|----------------|
| Access restrictions | `IAM_OVERPRIVILEGED_USERS` | Detect excessive IAM permissions |
| Multi-factor authentication | `IAM_MFA_DISABLED` | Enforce MFA for privileged accounts |
| Network segmentation | `EC2_SG_OPEN_TO_WORLD` | Validate security group rules |
| Encryption in transit | `RDS_ENCRYPTION_IN_TRANSIT_DISABLED` | Verify SSL/TLS usage |

#### CC6.2 - System Access Monitoring
| Control | AWS Security Suite Check | Implementation |
|---------|---------------------------|----------------|
| Access logging | `S3_ACCESS_LOGGING_DISABLED` | Enable S3 access logs |
| Activity monitoring | `CLOUDTRAIL_NOT_ENABLED` | CloudTrail audit logging |
| Failed access attempts | `CLOUDWATCH_FAILED_CONSOLE_LOGINS` | Monitor authentication failures |

#### CC6.3 - Access Removal
| Control | AWS Security Suite Check | Implementation |
|---------|---------------------------|----------------|
| Inactive user accounts | `IAM_INACTIVE_USERS` | Disable unused accounts |
| Access key rotation | `IAM_OLD_ACCESS_KEYS` | Rotate long-term credentials |
| Privileged access review | `IAM_PRIVILEGED_USER_REVIEW` | Regular access audits |

#### CC6.6 - Data Protection
| Control | AWS Security Suite Check | Implementation |
|---------|---------------------------|----------------|
| Encryption at rest | `EC2_EBS_VOLUME_NOT_ENCRYPTED` | Encrypt storage volumes |
| Database encryption | `RDS_ENCRYPTION_AT_REST_DISABLED` | Enable RDS encryption |
| Backup encryption | `RDS_BACKUP_ENCRYPTION_DISABLED` | Encrypt database backups |

#### CC6.7 - System Monitoring
| Control | AWS Security Suite Check | Implementation |
|---------|---------------------------|----------------|
| System vulnerabilities | `EC2_INSTANCE_OUTDATED_AMI` | Detect outdated AMIs |
| Security configurations | `EC2_IMDS_V2_NOT_ENFORCED` | Validate secure configurations |
| Monitoring coverage | `EC2_DETAILED_MONITORING_DISABLED` | Enable detailed monitoring |

#### CC7.1 - System Development
| Control | AWS Security Suite Check | Implementation |
|---------|---------------------------|----------------|
| Secure development | `LAMBDA_INSECURE_ENVIRONMENT_VARIABLES` | Secure function configurations |
| Change management | `EC2_PRODUCTION_TERMINATION_PROTECTION` | Protect production resources |

## AWS Config Rules

### Security Group Rules
| Config Rule | AWS Security Suite Check | Description |
|-------------|---------------------------|-------------|
| incoming-ssh-disabled | `EC2_SG_SSH_OPEN_TO_WORLD` | SSH access from 0.0.0.0/0 |
| restricted-rdp | `EC2_SG_RDP_OPEN_TO_WORLD` | RDP access from 0.0.0.0/0 |
| restricted-common-ports | `EC2_SG_HIGH_RISK_PORTS_OPEN` | Common ports open to internet |

### Encryption Rules
| Config Rule | AWS Security Suite Check | Description |
|-------------|---------------------------|-------------|
| encrypted-volumes | `EC2_EBS_VOLUME_NOT_ENCRYPTED` | EBS volume encryption |
| rds-storage-encrypted | `RDS_ENCRYPTION_AT_REST_DISABLED` | RDS encryption at rest |
| s3-bucket-ssl-requests-only | `S3_INSECURE_TRANSPORT` | S3 HTTPS-only access |

### Backup and Recovery
| Config Rule | AWS Security Suite Check | Description |
|-------------|---------------------------|-------------|
| db-instance-backup-enabled | `RDS_BACKUP_DISABLED` | RDS automated backups |
| dynamodb-point-in-time-recovery | `DYNAMODB_PITR_DISABLED` | DynamoDB backup |

## PCI DSS Requirements

### Requirement 1: Network Security Controls
| PCI Requirement | AWS Security Suite Check | Implementation |
|-----------------|---------------------------|----------------|
| 1.2.1 | `EC2_SG_OPEN_TO_WORLD` | Restrict inbound/outbound traffic |
| 1.3.1 | `EC2_VPC_FLOW_LOGS_DISABLED` | DMZ subnet configuration |
| 1.3.4 | `EC2_NACL_UNRESTRICTED_ACCESS` | Network ACL restrictions |

### Requirement 2: Secure Configurations
| PCI Requirement | AWS Security Suite Check | Implementation |
|-----------------|---------------------------|----------------|
| 2.1 | `EC2_DEFAULT_SG_UNRESTRICTED` | Change default security settings |
| 2.2 | `EC2_IMDS_V2_NOT_ENFORCED` | Secure service configurations |
| 2.3 | `RDS_DEFAULT_PORT_USAGE` | Non-default service ports |

### Requirement 3: Data Protection
| PCI Requirement | AWS Security Suite Check | Implementation |
|-----------------|---------------------------|----------------|
| 3.4 | `EC2_EBS_VOLUME_NOT_ENCRYPTED` | Encrypt stored cardholder data |
| 3.5.2 | `RDS_ENCRYPTION_AT_REST_DISABLED` | Protect encryption keys |
| 3.6 | `S3_ENCRYPTION_DISABLED` | Document encryption procedures |

### Requirement 8: Identity Management
| PCI Requirement | AWS Security Suite Check | Implementation |
|-----------------|---------------------------|----------------|
| 8.1.1 | `IAM_INACTIVE_USERS` | Remove inactive user accounts |
| 8.1.4 | `IAM_SHARED_CREDENTIALS` | Prevent shared credentials |
| 8.2.3 | `IAM_WEAK_PASSWORD_POLICY` | Strong password requirements |

## NIST Cybersecurity Framework

### Identify (ID)
| Category | AWS Security Suite Check | Implementation |
|----------|---------------------------|----------------|
| ID.AM-2 | `EC2_INSTANCE_MISSING_REQUIRED_TAGS` | Asset inventory and tags |
| ID.AM-3 | `VPC_UNTAGGED_RESOURCES` | Data flow mapping |

### Protect (PR)
| Category | AWS Security Suite Check | Implementation |
|----------|---------------------------|----------------|
| PR.AC-1 | `IAM_OVERPRIVILEGED_USERS` | Access control management |
| PR.AC-4 | `IAM_MFA_DISABLED` | Multi-factor authentication |
| PR.DS-1 | `EC2_EBS_VOLUME_NOT_ENCRYPTED` | Data at rest protection |
| PR.DS-2 | `RDS_ENCRYPTION_IN_TRANSIT_DISABLED` | Data in transit protection |

### Detect (DE)
| Category | AWS Security Suite Check | Implementation |
|----------|---------------------------|----------------|
| DE.AE-3 | `CLOUDTRAIL_NOT_ENABLED` | Event correlation |
| DE.CM-1 | `EC2_DETAILED_MONITORING_DISABLED` | Network monitoring |
| DE.CM-7 | `VPC_FLOW_LOGS_DISABLED` | Monitor external connections |

### Respond (RS)
| Category | AWS Security Suite Check | Implementation |
|----------|---------------------------|----------------|
| RS.AN-1 | `CLOUDWATCH_ALARM_MISSING` | Incident analysis |
| RS.CO-2 | `SNS_TOPIC_MISSING` | Incident communication |

### Recover (RC)
| Category | AWS Security Suite Check | Implementation |
|----------|---------------------------|----------------|
| RC.RP-1 | `RDS_BACKUP_DISABLED` | Recovery planning |
| RC.CO-3 | `S3_VERSIONING_DISABLED` | Recovery communication |

## Compliance Reporting

### Generate Compliance Reports
```bash
# CIS AWS Foundations Benchmark report
aws-security-suite scan --compliance cis-aws --format compliance-report

# SOC 2 compliance assessment
aws-security-suite scan --compliance soc2 --format json > soc2-assessment.json

# Multiple frameworks
aws-security-suite scan --compliance cis-aws,soc2,pci-dss --format csv
```

### Compliance Dashboard
```bash
# Summary of compliance status
aws-security-suite compliance-summary

# Detailed compliance gaps
aws-security-suite compliance-gaps --framework cis-aws

# Compliance trend analysis
aws-security-suite compliance-trend --days 30
```

### Custom Compliance Checks
```bash
# Run specific compliance checks
aws-security-suite scan --checks CIS-1.3,CIS-1.4,CIS-1.5

# Exclude non-applicable checks
aws-security-suite scan --compliance cis-aws --exclude-checks CIS-1.12,CIS-1.13
```

## Custom Compliance Frameworks

### Define Custom Framework
```yaml
# custom-compliance.yaml
framework:
  name: "Custom Security Standard"
  version: "1.0"
  controls:
    - id: "CSS-1.1"
      title: "All EC2 instances must be encrypted"
      checks: ["EC2_EBS_VOLUME_NOT_ENCRYPTED"]
      severity: "HIGH"
    - id: "CSS-1.2"
      title: "S3 buckets must have access logging"
      checks: ["S3_ACCESS_LOGGING_DISABLED"]
      severity: "MEDIUM"
```

### Use Custom Framework
```bash
aws-security-suite scan --compliance-config custom-compliance.yaml
```

### Compliance Automation
```bash
# Automated compliance checking in CI/CD
aws-security-suite scan --compliance cis-aws --exit-code-on-non-compliance

# Remediate compliance violations
aws-security-suite remediate --compliance cis-aws --auto-approve-low-risk
```

## Compliance Best Practices

### Regular Assessment
- **Monthly**: Run comprehensive compliance scans
- **Weekly**: Check critical controls
- **Daily**: Monitor high-risk findings
- **Continuous**: Automated compliance monitoring

### Documentation
- Maintain evidence of compliance controls
- Document any accepted risks or exceptions
- Keep audit trails of all remediation actions
- Regular review and update of compliance mappings

### Remediation Prioritization
1. **Critical violations**: Immediate attention
2. **High-risk gaps**: 24-48 hour resolution
3. **Medium-risk issues**: Weekly remediation cycles
4. **Low-risk findings**: Monthly maintenance windows

### Continuous Improvement
- Regular framework updates as standards evolve
- Feedback incorporation from audit findings
- Automation of additional compliance checks
- Integration with organizational risk management