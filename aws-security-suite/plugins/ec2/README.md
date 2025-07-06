# EC2 Security Scanner Plugin

Comprehensive security analysis for Amazon EC2 instances, security groups, EBS volumes, and related networking resources.

## Overview

The EC2 Security Scanner provides production-ready security assessment capabilities for AWS EC2 infrastructure, covering instance security, network configuration, storage encryption, and compliance validation.

## Security Checks Covered

### 🔒 Instance Security (5 checks)
- **EC2_INSTANCE_PUBLIC_IP** - Detects instances with public IP addresses
- **EC2_IMDS_V2_NOT_ENFORCED** - Validates Instance Metadata Service v2 enforcement
- **EC2_NO_INSTANCE_PROFILE** - Identifies instances without IAM instance profiles
- **EC2_DEFAULT_VPC_USAGE** - Flags instances running in default VPC
- **EC2_DETAILED_MONITORING_DISABLED** - Checks detailed CloudWatch monitoring status

### 🛡️ Security Group Analysis (2 checks)
- **EC2_SG_OPEN_TO_WORLD** - Identifies overly permissive IPv4 rules (0.0.0.0/0)
- **EC2_SG_OPEN_TO_WORLD_IPV6** - Identifies overly permissive IPv6 rules (::/0)

### 💾 EBS Volume Security (2 checks)
- **EC2_EBS_VOLUME_NOT_ENCRYPTED** - Validates EBS volume encryption
- **EC2_PUBLIC_SNAPSHOT** - Detects publicly accessible EBS snapshots

### 🌐 VPC Security (2 checks)
- **EC2_DEFAULT_VPC_IN_USE** - Identifies default VPCs with running instances
- **EC2_VPC_FLOW_LOGS_DISABLED** - Validates VPC Flow Logs configuration

### ⚡ Enhanced Security Checks (5 checks)
- **EC2_PRODUCTION_TERMINATION_PROTECTION** - Validates termination protection for production instances
- **EC2_INSTANCE_MISSING_REQUIRED_TAGS** - Enforces tag compliance for governance
- **EC2_DEFAULT_NACL_OVERLY_PERMISSIVE** - Analyzes Network ACL security rules
- **EC2_UNUSED_SECURITY_GROUP** - Identifies unused security groups
- **EC2_EBS_NO_SNAPSHOTS** - Validates backup policies for EBS volumes

## Severity Levels

| Severity | Examples | Impact |
|----------|----------|---------|
| **CRITICAL** | Public snapshots, high-risk ports open to world | Immediate data exposure risk |
| **HIGH** | Unencrypted volumes, IMDSv1 enabled | Significant security vulnerability |
| **MEDIUM** | Public IPs, default VPC usage | Moderate security risk |
| **LOW** | Missing tags, disabled monitoring | Compliance and visibility issues |

## Required IAM Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSecurityGroupRules",
                "ec2:DescribeVolumes",
                "ec2:DescribeSnapshots",
                "ec2:DescribeSnapshotAttribute",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeRegions",
                "ec2:DescribeAvailabilityZones",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeNetworkAclAttribute",
                "ec2:DescribeRouteTables",
                "ec2:DescribeAddresses",
                "ec2:DescribeKeyPairs",
                "ec2:DescribePlacementGroups",
                "iam:GetInstanceProfile",
                "iam:ListInstanceProfiles"
            ],
            "Resource": "*"
        }
    ]
}
```

### Additional Permissions for Remediation

```json
{
    "Effect": "Allow",
    "Action": [
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifyInstanceMetadataOptions",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:CreateSnapshot",
        "ec2:CreateFlowLogs",
        "ec2:CreateTags",
        "ec2:DeleteSecurityGroup"
    ],
    "Resource": "*"
}
```

## Automated Remediation

The scanner provides automated remediation for 10+ security findings:

| Check ID | Remediation Function | Description |
|----------|---------------------|-------------|
| EC2_INSTANCE_PUBLIC_IP | `remove_public_ip` | Removes public IP association |
| EC2_IMDS_V2_NOT_ENFORCED | `enforce_imdsv2` | Enforces IMDSv2 requirement |
| EC2_SG_OPEN_TO_WORLD | `restrict_security_group` | Removes overly permissive rules |
| EC2_EBS_VOLUME_NOT_ENCRYPTED | `encrypt_ebs_volume` | Creates encrypted snapshot |
| EC2_VPC_FLOW_LOGS_DISABLED | `enable_vpc_flow_logs` | Enables VPC Flow Logs |
| EC2_PRODUCTION_TERMINATION_PROTECTION | `enable_termination_protection` | Enables termination protection |
| EC2_UNUSED_SECURITY_GROUP | `remove_unused_security_group` | Deletes unused security groups |
| EC2_EBS_NO_SNAPSHOTS | `create_snapshot_policy` | Creates backup snapshots |

## Usage

### Basic Scanning

```python
from aws_security_suite.plugins.ec2.scanner import scan_ec2
from aws_security_suite.core.audit_context import AuditContext

# Create audit context
context = AuditContext(
    account_id="123456789012",
    session=boto3.Session()
)

# Run EC2 security scan
findings = await scan_ec2(context)

# Process findings
for finding in findings:
    print(f"{finding.severity.value}: {finding.check_title}")
    print(f"Resource: {finding.resource_name}")
    print(f"Recommendation: {finding.recommendation}")
```

### Plugin Registration

```python
from aws_security_suite.plugins.ec2.scanner import register

# Register the plugin
plugin = register()

# Access plugin metadata
print(f"Service: {plugin.service}")
print(f"Permissions needed: {len(plugin.required_permissions)}")
print(f"Remediation available: {len(plugin.remediation_map)}")
```

### Applying Remediation

```python
from aws_security_suite.plugins.ec2.remediation import apply_remediation

# Apply automated fix for a finding
success = await apply_remediation(finding, context)
if success:
    print("Remediation applied successfully")
```

## Configuration

### Production Instance Detection

The scanner automatically identifies production instances using:

- Instance types (c5.*, m5.*, r5.* families)
- Name patterns (containing "prod", "production")
- Environment tags (Environment=prod/production)

### Required Tags

Configure required tags for compliance checking:

```python
REQUIRED_TAGS = ['Environment', 'Owner', 'Project', 'CostCenter']
```

### High-Risk Ports

Default high-risk ports monitored:

```python
HIGH_RISK_PORTS = [22, 3389, 5432, 3306, 1433, 6379, 27017, 9200, 5984]
```

## Performance

- **Multi-region support**: Scans all available AWS regions
- **Async processing**: Non-blocking concurrent scans
- **Pagination**: Handles large EC2 environments efficiently
- **Rate limiting**: Respects AWS API limits
- **Error resilience**: Continues scanning despite individual failures

## Integration

### CLI Integration

```bash
aws-security-suite scan --service ec2 --region us-east-1
aws-security-suite remediate --service ec2 --check-id EC2_IMDS_V2_NOT_ENFORCED
```

### Compliance Framework Mapping

The scanner maps findings to compliance frameworks:

- **CIS AWS Foundations Benchmark**
- **AWS Security Best Practices**
- **SOC 2 Type II**
- **PCI DSS**
- **NIST Cybersecurity Framework**

## Testing

Run comprehensive tests:

```bash
python test_ec2_comprehensive.py
```

Expected output:
```
✅ Core Plugin Registration
📋 Security Check Coverage (16 total checks)
🔧 Enhanced Security Functions
🛠️ Remediation Coverage: 13/16 (81.3%)
☁️ AWS Service Coverage (8 services)
🎉 ALL TESTS PASSED - EC2 Security Scanner is production-ready!
```

## Files Structure

```
plugins/ec2/
├── __init__.py              # Plugin module initialization
├── scanner.py               # Main scanning logic (16 security checks)
├── enhanced_checks.py       # Additional security validations
├── remediation.py           # Automated remediation functions
└── README.md               # This documentation
```

## Contributing

When adding new security checks:

1. Add the check function to `scanner.py` or `enhanced_checks.py`
2. Update the `register()` function with new remediation mappings
3. Add required IAM permissions
4. Implement remediation function if possible
5. Update tests in `test_ec2_comprehensive.py`
6. Document the new check in this README

## Security Considerations

- All API calls use least-privilege IAM permissions
- Remediation functions include safety checks
- Sensitive data is not logged or exposed
- Rate limiting prevents API throttling
- Multi-region scans respect regional service availability

---

**Last Updated**: 2024-07-06  
**Plugin Version**: 2.0.0  
**Security Checks**: 16  
**Automated Remediations**: 13  
**AWS Services Covered**: 8