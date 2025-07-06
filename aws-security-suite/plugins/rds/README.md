# RDS Security Scanner Plugin

## Overview

The RDS Security Scanner Plugin provides comprehensive security analysis for Amazon RDS instances, Aurora clusters, snapshots, and related database infrastructure. It performs security assessments across database encryption, network security, backup configurations, and compliance validation.

## Security Checks Covered

### 🔒 Database Instance Security (8 checks)
- **RDS_INSTANCE_PUBLIC_ACCESS** - Detects publicly accessible RDS instances
- **RDS_ENCRYPTION_AT_REST_DISABLED** - Validates encryption at rest for DB instances
- **RDS_ENCRYPTION_IN_TRANSIT_DISABLED** - Checks SSL/TLS enforcement for connections
- **RDS_MINOR_VERSION_UPGRADE_DISABLED** - Validates automatic minor version upgrades
- **RDS_MULTI_AZ_DISABLED** - Checks Multi-AZ deployment for high availability
- **RDS_BACKUP_RETENTION_SHORT** - Validates backup retention period (minimum 7 days)
- **RDS_DELETE_PROTECTION_DISABLED** - Checks deletion protection for production databases
- **RDS_MONITORING_DISABLED** - Validates enhanced monitoring configuration

### 🛡️ Snapshot Security (3 checks)
- **RDS_PUBLIC_SNAPSHOT** - Detects publicly accessible snapshots
- **RDS_SNAPSHOT_NOT_ENCRYPTED** - Validates snapshot encryption
- **RDS_AUTOMATED_BACKUP_DISABLED** - Checks automated backup configuration

### 🌐 Network Security (4 checks)
- **RDS_DEFAULT_PORT_USAGE** - Identifies databases using default ports
- **RDS_SECURITY_GROUP_OVERPERMISSIVE** - Validates security group rules
- **RDS_SUBNET_GROUP_PUBLIC** - Checks for public subnet deployments
- **RDS_VPC_SECURITY_GROUP_UNRESTRICTED** - Analyzes VPC security group rules

### ⚡ Aurora-Specific Checks (3 checks)
- **AURORA_CLUSTER_ENCRYPTION_DISABLED** - Validates Aurora cluster encryption
- **AURORA_BACKTRACK_DISABLED** - Checks Aurora backtrack configuration
- **AURORA_DELETION_PROTECTION_DISABLED** - Validates cluster deletion protection

### 📊 Parameter Group Security (2 checks)
- **RDS_PARAMETER_GROUP_INSECURE** - Analyzes database parameter security
- **RDS_LOG_EXPORTS_DISABLED** - Validates CloudWatch log exports

## Severity Levels

| Severity | Examples | Impact |
|----------|----------|---------|
| **CRITICAL** | Public snapshots, unencrypted public databases | Immediate data exposure risk |
| **HIGH** | Public instances, disabled encryption, no backups | Significant security vulnerability |
| **MEDIUM** | Default ports, overpermissive security groups | Moderate security risk |
| **LOW** | Disabled monitoring, short retention periods | Compliance and visibility issues |

## Required IAM Permissions

### Read-Only Scanning
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "rds:DescribeDBInstances",
                "rds:DescribeDBClusters",
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBClusterSnapshots",
                "rds:DescribeDBSubnetGroups",
                "rds:DescribeDBParameterGroups",
                "rds:DescribeDBParameters",
                "rds:DescribeDBClusterParameterGroups",
                "rds:DescribeDBClusterParameters",
                "rds:DescribeDBSecurityGroups",
                "rds:DescribeEventSubscriptions",
                "rds:DescribeOptionGroups",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs"
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
                "rds:*",
                "ec2:DescribeSecurityGroups",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs"
            ],
            "Resource": "*"
        }
    ]
}
```

## Usage Examples

### Basic RDS Security Scan
```bash
# Scan all RDS resources in default region
aws-security-suite scan --services rds

# Scan specific regions
aws-security-suite scan --services rds --regions us-east-1,us-west-2

# Focus on critical findings
aws-security-suite scan --services rds --severity critical,high
```

### Targeted Scans
```bash
# Scan only RDS instances (no Aurora)
aws-security-suite scan --services rds --resource-types db-instances

# Scan only snapshots
aws-security-suite scan --services rds --resource-types snapshots

# Scan Aurora clusters only
aws-security-suite scan --services rds --resource-types aurora-clusters
```

### Compliance Scanning
```bash
# CIS benchmark compliance
aws-security-suite scan --services rds --compliance cis-aws

# SOC 2 compliance check
aws-security-suite scan --services rds --compliance soc2

# PCI DSS compliance
aws-security-suite scan --services rds --compliance pci-dss
```

## Automated Remediation

### Supported Remediations
| Finding Type | Remediation | Safety Level |
|-------------|-------------|--------------|
| `RDS_INSTANCE_PUBLIC_ACCESS` | Modify DB instance to disable public access | Safe |
| `RDS_ENCRYPTION_IN_TRANSIT_DISABLED` | Enable SSL enforcement via parameter group | Safe |
| `RDS_MINOR_VERSION_UPGRADE_DISABLED` | Enable automatic minor version upgrades | Safe |
| `RDS_BACKUP_RETENTION_SHORT` | Extend backup retention period | Safe |
| `RDS_DELETE_PROTECTION_DISABLED` | Enable deletion protection | Safe |
| `RDS_MONITORING_DISABLED` | Enable enhanced monitoring | Safe |
| `RDS_PUBLIC_SNAPSHOT` | Remove public access from snapshots | Safe |
| `RDS_AUTOMATED_BACKUP_DISABLED` | Enable automated backups | Requires downtime |
| `RDS_DEFAULT_PORT_USAGE` | Change database port | Requires coordination |
| `RDS_SECURITY_GROUP_OVERPERMISSIVE` | Restrict security group rules | Requires validation |

### Remediation Examples
```bash
# Dry-run to preview changes
aws-security-suite remediate --services rds --dry-run

# Auto-fix safe issues
aws-security-suite remediate --services rds --safety-level safe

# Interactive remediation with confirmation
aws-security-suite remediate --services rds --interactive

# Remediate specific finding types
aws-security-suite remediate --finding-type RDS_INSTANCE_PUBLIC_ACCESS,RDS_DELETE_PROTECTION_DISABLED
```

## Security Check Details

### Database Instance Security

#### RDS_INSTANCE_PUBLIC_ACCESS
**Description**: Identifies RDS instances that are publicly accessible from the internet.
**Risk**: Public access exposes databases to potential unauthorized access and attacks.
**Remediation**: Modify the DB instance to set `PubliclyAccessible` to `false`.

```bash
# Manual remediation
aws rds modify-db-instance \
    --db-instance-identifier mydb \
    --no-publicly-accessible \
    --apply-immediately
```

#### RDS_ENCRYPTION_AT_REST_DISABLED
**Description**: Detects RDS instances without encryption at rest enabled.
**Risk**: Unencrypted data at rest violates compliance requirements and security best practices.
**Remediation**: Cannot be enabled on existing instances - requires creating encrypted copy.

```bash
# Create encrypted snapshot and restore
aws rds create-db-snapshot \
    --db-instance-identifier mydb \
    --db-snapshot-identifier mydb-snapshot

aws rds copy-db-snapshot \
    --source-db-snapshot-identifier mydb-snapshot \
    --target-db-snapshot-identifier mydb-encrypted-snapshot \
    --kms-key-id arn:aws:kms:region:account:key/key-id
```

#### RDS_ENCRYPTION_IN_TRANSIT_DISABLED
**Description**: Checks if SSL/TLS encryption is enforced for database connections.
**Risk**: Data in transit may be intercepted or modified.
**Remediation**: Enable SSL enforcement via parameter group modifications.

```bash
# Create parameter group with SSL enforcement
aws rds create-db-parameter-group \
    --db-parameter-group-name ssl-enforced \
    --db-parameter-group-family mysql8.0 \
    --description "SSL enforced parameter group"

aws rds modify-db-parameter-group \
    --db-parameter-group-name ssl-enforced \
    --parameters ParameterName=require_secure_transport,ParameterValue=1
```

### Snapshot Security

#### RDS_PUBLIC_SNAPSHOT
**Description**: Detects publicly accessible RDS snapshots.
**Risk**: Public snapshots can expose sensitive data to unauthorized users.
**Remediation**: Remove public access from snapshots.

```bash
# Remove public access from snapshot
aws rds modify-db-snapshot-attribute \
    --db-snapshot-identifier mydb-snapshot \
    --attribute-name restore \
    --values-to-remove all
```

### Network Security

#### RDS_SECURITY_GROUP_OVERPERMISSIVE
**Description**: Identifies security groups with overly permissive database access rules.
**Risk**: Broad network access increases attack surface.
**Remediation**: Restrict security group rules to specific IP ranges or security groups.

```bash
# Remove overly permissive rule
aws ec2 revoke-security-group-ingress \
    --group-id sg-12345678 \
    --protocol tcp \
    --port 3306 \
    --cidr 0.0.0.0/0

# Add restricted rule
aws ec2 authorize-security-group-ingress \
    --group-id sg-12345678 \
    --protocol tcp \
    --port 3306 \
    --cidr 10.0.0.0/8
```

### Aurora-Specific Security

#### AURORA_CLUSTER_ENCRYPTION_DISABLED
**Description**: Checks if Aurora clusters have encryption enabled.
**Risk**: Unencrypted Aurora clusters violate security best practices.
**Remediation**: Cannot be enabled on existing clusters - requires recreation.

```bash
# Create encrypted Aurora cluster
aws rds create-db-cluster \
    --db-cluster-identifier myaurora-encrypted \
    --engine aurora-mysql \
    --storage-encrypted \
    --kms-key-id arn:aws:kms:region:account:key/key-id
```

## Configuration Options

### Plugin Configuration
```yaml
# rds-config.yaml
rds:
  # Skip certain instance classes
  skip_instance_classes:
    - "db.t2.micro"
    - "db.t3.micro"
  
  # Minimum backup retention period
  min_backup_retention_days: 7
  
  # Required parameter group settings
  required_parameters:
    mysql:
      require_secure_transport: "1"
      log_bin_trust_function_creators: "0"
    postgres:
      ssl: "1"
      log_statement: "all"
  
  # Exclude test/development instances
  exclude_tags:
    Environment: ["test", "dev", "staging"]
```

### Environment-Specific Settings
```bash
# Production environment - strict security
aws-security-suite scan --services rds --config production-rds.yaml

# Development environment - relaxed rules
aws-security-suite scan --services rds --config development-rds.yaml --exclude-checks RDS_INSTANCE_PUBLIC_ACCESS
```

## Integration Examples

### CI/CD Pipeline Integration
```yaml
# .github/workflows/rds-security.yml
name: RDS Security Scan
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM
    
jobs:
  rds-security:
    runs-on: ubuntu-latest
    steps:
      - name: RDS Security Scan
        run: |
          aws-security-suite scan \
            --services rds \
            --format json \
            --severity critical,high \
            --exit-code-on-findings
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

### Monitoring Integration
```bash
# Send findings to CloudWatch
aws-security-suite scan --services rds --format json | \
aws logs put-log-events \
  --log-group-name /aws/security-suite/rds \
  --log-stream-name $(date +%Y%m%d) \
  --log-events timestamp=$(date +%s000),message="$(cat)"

# Create CloudWatch alarms for critical findings
aws cloudwatch put-metric-alarm \
  --alarm-name "RDS-Critical-Security-Findings" \
  --alarm-description "Alert on critical RDS security findings" \
  --metric-name SecurityFindingsCount \
  --namespace AWS/SecuritySuite \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold
```

## Best Practices

### Regular Assessment
- **Daily**: Scan for critical security issues
- **Weekly**: Comprehensive RDS security assessment
- **Monthly**: Full compliance and configuration review
- **Quarterly**: Review and update security policies

### Remediation Prioritization
1. **Critical**: Public snapshots, unencrypted public databases
2. **High**: Disabled encryption, missing backups
3. **Medium**: Default ports, overpermissive security groups
4. **Low**: Monitoring disabled, short retention periods

### Security Hardening Checklist
- [ ] Enable encryption at rest for all production databases
- [ ] Enforce SSL/TLS for all database connections
- [ ] Disable public access for all production instances
- [ ] Enable deletion protection for critical databases
- [ ] Configure automated backups with appropriate retention
- [ ] Enable enhanced monitoring and log exports
- [ ] Use non-default ports where possible
- [ ] Implement least-privilege security group rules
- [ ] Enable Multi-AZ for production workloads
- [ ] Regular security group and parameter group audits

### Compliance Considerations
- **SOC 2**: Focus on encryption, access controls, and monitoring
- **PCI DSS**: Emphasize network security and encryption requirements
- **HIPAA**: Ensure encryption at rest and in transit, audit logging
- **CIS**: Follow CIS benchmark recommendations for RDS security

For additional configuration options and troubleshooting, see the main [USER_GUIDE.md](../../USER_GUIDE.md) and [TROUBLESHOOTING.md](../../TROUBLESHOOTING.md).