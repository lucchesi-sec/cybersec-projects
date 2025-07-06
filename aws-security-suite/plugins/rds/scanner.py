"""
RDS Security Scanner - Comprehensive data-at-rest security validation.
Focuses on encryption, access controls, backups, and compliance.
"""

import asyncio
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
import logging

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext
from core.plugin import ScannerPlugin

logger = logging.getLogger(__name__)

# High-risk database engines that require special attention
HIGH_RISK_ENGINES = ['mysql', 'postgres', 'oracle-ee', 'sqlserver-ee']

# Default ports for different database engines
DB_ENGINE_PORTS = {
    'mysql': 3306,
    'postgres': 5432,
    'oracle-ee': 1521,
    'oracle-se2': 1521,
    'sqlserver-ee': 1433,
    'sqlserver-se': 1433,
    'sqlserver-ex': 1433,
    'sqlserver-web': 1433,
    'mariadb': 3306
}


async def scan_rds(context: AuditContext) -> List[Finding]:
    """Main RDS security scanning function."""
    findings = []
    
    for region in context.regions:
        if not context.supports_service_in_region("rds", region):
            logger.info(f"RDS not available in region {region}")
            continue
        
        try:
            rds_client = context.get_client('rds', region_name=region)
            
            # Scan RDS instances
            instance_findings = await scan_rds_instances(rds_client, context, region)
            findings.extend(instance_findings)
            
            # Scan RDS clusters (Aurora)
            cluster_findings = await scan_rds_clusters(rds_client, context, region)
            findings.extend(cluster_findings)
            
            # Scan RDS snapshots
            snapshot_findings = await scan_rds_snapshots(rds_client, context, region)
            findings.extend(snapshot_findings)
            
            # Scan parameter groups
            param_findings = await scan_parameter_groups(rds_client, context, region)
            findings.extend(param_findings)
            
            # Scan option groups
            option_findings = await scan_option_groups(rds_client, context, region)
            findings.extend(option_findings)
            
        except ClientError as e:
            logger.error(f"Failed to scan RDS in region {region}: {e}")
            continue
    
    return findings


async def scan_rds_instances(rds_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan RDS instances for security issues."""
    findings = []
    
    try:
        paginator = rds_client.get_paginator('describe_db_instances')
        
        async for page in paginator.paginate():
            for instance in page['DBInstances']:
                instance_findings = await analyze_rds_instance(instance, context, region)
                findings.extend(instance_findings)
                
    except ClientError as e:
        logger.error(f"Failed to describe RDS instances in {region}: {e}")
    
    return findings


async def analyze_rds_instance(instance: Dict, context: AuditContext, region: str) -> List[Finding]:
    """Analyze a single RDS instance for security issues."""
    findings = []
    instance_id = instance['DBInstanceIdentifier']
    instance_arn = instance['DBInstanceArn']
    
    # Check encryption at rest
    if not instance.get('StorageEncrypted', False):
        findings.append(Finding(
            service="rds",
            resource_id=instance_arn,
            resource_name=instance_id,
            check_id="RDS_INSTANCE_NOT_ENCRYPTED",
            check_title="RDS Instance Storage Not Encrypted",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=region,
            account_id=context.account_id,
            description=f"RDS instance '{instance_id}' does not have storage encryption enabled",
            recommendation="Enable storage encryption for RDS instances to protect data at rest",
            remediation_available=True,
            context={
                "engine": instance.get('Engine'),
                "engine_version": instance.get('EngineVersion'),
                "storage_type": instance.get('StorageType'),
                "allocated_storage": instance.get('AllocatedStorage')
            }
        ))
    
    # Check public accessibility
    if instance.get('PubliclyAccessible', False):
        severity = Severity.CRITICAL if instance.get('Engine') in HIGH_RISK_ENGINES else Severity.HIGH
        findings.append(Finding(
            service="rds",
            resource_id=instance_arn,
            resource_name=instance_id,
            check_id="RDS_INSTANCE_PUBLICLY_ACCESSIBLE",
            check_title="RDS Instance Publicly Accessible",
            status=Status.FAIL,
            severity=severity,
            region=region,
            account_id=context.account_id,
            description=f"RDS instance '{instance_id}' is publicly accessible from the internet",
            recommendation="Disable public accessibility and use VPC security groups to control access",
            remediation_available=True,
            context={
                "engine": instance.get('Engine'),
                "vpc_id": instance.get('DBSubnetGroup', {}).get('VpcId'),
                "availability_zone": instance.get('AvailabilityZone')
            }
        ))
    
    # Check backup retention
    backup_retention = instance.get('BackupRetentionPeriod', 0)
    if backup_retention < 7:
        severity = Severity.HIGH if backup_retention == 0 else Severity.MEDIUM
        findings.append(Finding(
            service="rds",
            resource_id=instance_arn,
            resource_name=instance_id,
            check_id="RDS_INSTANCE_BACKUP_RETENTION_LOW",
            check_title="RDS Instance Backup Retention Too Low",
            status=Status.FAIL,
            severity=severity,
            region=region,
            account_id=context.account_id,
            description=f"RDS instance '{instance_id}' has backup retention of {backup_retention} days (recommended: 7+ days)",
            recommendation="Set backup retention period to at least 7 days for compliance and disaster recovery",
            remediation_available=True,
            context={
                "current_retention": backup_retention,
                "backup_window": instance.get('PreferredBackupWindow'),
                "maintenance_window": instance.get('PreferredMaintenanceWindow')
            }
        ))
    
    # Check multi-AZ deployment for production instances
    if not instance.get('MultiAZ', False):
        # Determine if this is a production instance
        is_production = _is_production_instance(instance)
        if is_production:
            findings.append(Finding(
                service="rds",
                resource_id=instance_arn,
                resource_name=instance_id,
                check_id="RDS_PRODUCTION_NO_MULTI_AZ",
                check_title="Production RDS Instance Not Multi-AZ",
                status=Status.FAIL,
                severity=Severity.HIGH,
                region=region,
                account_id=context.account_id,
                description=f"Production RDS instance '{instance_id}' is not configured for Multi-AZ deployment",
                recommendation="Enable Multi-AZ deployment for high availability and automatic failover",
                remediation_available=True,
                context={
                    "engine": instance.get('Engine'),
                    "instance_class": instance.get('DBInstanceClass'),
                    "availability_zone": instance.get('AvailabilityZone')
                }
            ))
    
    # Check deletion protection
    if not instance.get('DeletionProtection', False):
        is_production = _is_production_instance(instance)
        if is_production:
            findings.append(Finding(
                service="rds",
                resource_id=instance_arn,
                resource_name=instance_id,
                check_id="RDS_PRODUCTION_NO_DELETION_PROTECTION",
                check_title="Production RDS Instance Missing Deletion Protection",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Production RDS instance '{instance_id}' does not have deletion protection enabled",
                recommendation="Enable deletion protection for production databases to prevent accidental deletion",
                remediation_available=True,
                context={
                    "engine": instance.get('Engine'),
                    "instance_class": instance.get('DBInstanceClass')
                }
            ))
    
    # Check minor version auto upgrade
    if not instance.get('AutoMinorVersionUpgrade', False):
        findings.append(Finding(
            service="rds",
            resource_id=instance_arn,
            resource_name=instance_id,
            check_id="RDS_INSTANCE_NO_AUTO_MINOR_VERSION_UPGRADE",
            check_title="RDS Instance Minor Version Auto Upgrade Disabled",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"RDS instance '{instance_id}' does not have automatic minor version upgrades enabled",
            recommendation="Enable automatic minor version upgrades to receive security and bug fixes",
            context={
                "engine": instance.get('Engine'),
                "engine_version": instance.get('EngineVersion'),
                "maintenance_window": instance.get('PreferredMaintenanceWindow')
            }
        ))
    
    # Check performance insights
    if not instance.get('PerformanceInsightsEnabled', False):
        findings.append(Finding(
            service="rds",
            resource_id=instance_arn,
            resource_name=instance_id,
            check_id="RDS_INSTANCE_PERFORMANCE_INSIGHTS_DISABLED",
            check_title="RDS Instance Performance Insights Disabled",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"RDS instance '{instance_id}' does not have Performance Insights enabled",
            recommendation="Enable Performance Insights for database performance monitoring and optimization",
            context={
                "engine": instance.get('Engine'),
                "instance_class": instance.get('DBInstanceClass')
            }
        ))
    
    return findings


async def scan_rds_clusters(rds_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan RDS clusters (Aurora) for security issues."""
    findings = []
    
    try:
        paginator = rds_client.get_paginator('describe_db_clusters')
        
        async for page in paginator.paginate():
            for cluster in page['DBClusters']:
                cluster_findings = await analyze_rds_cluster(cluster, context, region)
                findings.extend(cluster_findings)
                
    except ClientError as e:
        logger.error(f"Failed to describe RDS clusters in {region}: {e}")
    
    return findings


async def analyze_rds_cluster(cluster: Dict, context: AuditContext, region: str) -> List[Finding]:
    """Analyze a single RDS cluster for security issues."""
    findings = []
    cluster_id = cluster['DBClusterIdentifier']
    cluster_arn = cluster['DBClusterArn']
    
    # Check encryption at rest
    if not cluster.get('StorageEncrypted', False):
        findings.append(Finding(
            service="rds",
            resource_id=cluster_arn,
            resource_name=cluster_id,
            check_id="RDS_CLUSTER_NOT_ENCRYPTED",
            check_title="RDS Cluster Storage Not Encrypted",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=region,
            account_id=context.account_id,
            description=f"RDS cluster '{cluster_id}' does not have storage encryption enabled",
            recommendation="Enable storage encryption for RDS clusters to protect data at rest",
            remediation_available=True,
            context={
                "engine": cluster.get('Engine'),
                "engine_version": cluster.get('EngineVersion'),
                "engine_mode": cluster.get('EngineMode')
            }
        ))
    
    # Check backup retention
    backup_retention = cluster.get('BackupRetentionPeriod', 0)
    if backup_retention < 7:
        severity = Severity.HIGH if backup_retention == 0 else Severity.MEDIUM
        findings.append(Finding(
            service="rds",
            resource_id=cluster_arn,
            resource_name=cluster_id,
            check_id="RDS_CLUSTER_BACKUP_RETENTION_LOW",
            check_title="RDS Cluster Backup Retention Too Low",
            status=Status.FAIL,
            severity=severity,
            region=region,
            account_id=context.account_id,
            description=f"RDS cluster '{cluster_id}' has backup retention of {backup_retention} days (recommended: 7+ days)",
            recommendation="Set backup retention period to at least 7 days for compliance and disaster recovery",
            remediation_available=True,
            context={
                "current_retention": backup_retention,
                "backup_window": cluster.get('PreferredBackupWindow'),
                "maintenance_window": cluster.get('PreferredMaintenanceWindow')
            }
        ))
    
    # Check deletion protection
    if not cluster.get('DeletionProtection', False):
        is_production = _is_production_cluster(cluster)
        if is_production:
            findings.append(Finding(
                service="rds",
                resource_id=cluster_arn,
                resource_name=cluster_id,
                check_id="RDS_CLUSTER_NO_DELETION_PROTECTION",
                check_title="Production RDS Cluster Missing Deletion Protection",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Production RDS cluster '{cluster_id}' does not have deletion protection enabled",
                recommendation="Enable deletion protection for production database clusters",
                remediation_available=True,
                context={
                    "engine": cluster.get('Engine'),
                    "engine_mode": cluster.get('EngineMode')
                }
            ))
    
    return findings


async def scan_rds_snapshots(rds_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan RDS snapshots for security issues."""
    findings = []
    
    try:
        # Scan manual snapshots
        paginator = rds_client.get_paginator('describe_db_snapshots')
        async for page in paginator.paginate(SnapshotType='manual', OwnerIds=['self']):
            for snapshot in page['DBSnapshots']:
                snapshot_findings = await analyze_db_snapshot(snapshot, rds_client, context, region)
                findings.extend(snapshot_findings)
        
        # Scan cluster snapshots
        cluster_paginator = rds_client.get_paginator('describe_db_cluster_snapshots')
        async for page in cluster_paginator.paginate(SnapshotType='manual', OwnerIds=['self']):
            for snapshot in page['DBClusterSnapshots']:
                cluster_snapshot_findings = await analyze_cluster_snapshot(snapshot, rds_client, context, region)
                findings.extend(cluster_snapshot_findings)
                
    except ClientError as e:
        logger.error(f"Failed to describe RDS snapshots in {region}: {e}")
    
    return findings


async def analyze_db_snapshot(snapshot: Dict, rds_client, context: AuditContext, region: str) -> List[Finding]:
    """Analyze a DB snapshot for security issues."""
    findings = []
    snapshot_id = snapshot['DBSnapshotIdentifier']
    snapshot_arn = snapshot['DBSnapshotArn']
    
    # Check if snapshot is public
    try:
        attributes = rds_client.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_id)
        for attribute in attributes['DBSnapshotAttributesResult']['DBSnapshotAttributes']:
            if attribute['AttributeName'] == 'restore' and 'all' in attribute.get('AttributeValues', []):
                findings.append(Finding(
                    service="rds",
                    resource_id=snapshot_arn,
                    resource_name=snapshot_id,
                    check_id="RDS_SNAPSHOT_PUBLIC",
                    check_title="RDS Snapshot is Public",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    region=region,
                    account_id=context.account_id,
                    description=f"RDS snapshot '{snapshot_id}' is publicly accessible",
                    recommendation="Remove public access from RDS snapshots to prevent data exposure",
                    remediation_available=True,
                    context={
                        "engine": snapshot.get('Engine'),
                        "encrypted": snapshot.get('Encrypted', False)
                    }
                ))
                break
    except ClientError as e:
        logger.warning(f"Could not check snapshot attributes for {snapshot_id}: {e}")
    
    # Check if snapshot is encrypted
    if not snapshot.get('Encrypted', False):
        findings.append(Finding(
            service="rds",
            resource_id=snapshot_arn,
            resource_name=snapshot_id,
            check_id="RDS_SNAPSHOT_NOT_ENCRYPTED",
            check_title="RDS Snapshot Not Encrypted",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=region,
            account_id=context.account_id,
            description=f"RDS snapshot '{snapshot_id}' is not encrypted",
            recommendation="Ensure all RDS snapshots are encrypted to protect data at rest",
            context={
                "engine": snapshot.get('Engine'),
                "source_db": snapshot.get('DBInstanceIdentifier')
            }
        ))
    
    return findings


async def analyze_cluster_snapshot(snapshot: Dict, rds_client, context: AuditContext, region: str) -> List[Finding]:
    """Analyze a cluster snapshot for security issues."""
    findings = []
    snapshot_id = snapshot['DBClusterSnapshotIdentifier']
    snapshot_arn = snapshot['DBClusterSnapshotArn']
    
    # Check if cluster snapshot is public
    try:
        attributes = rds_client.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=snapshot_id)
        for attribute in attributes['DBClusterSnapshotAttributesResult']['DBClusterSnapshotAttributes']:
            if attribute['AttributeName'] == 'restore' and 'all' in attribute.get('AttributeValues', []):
                findings.append(Finding(
                    service="rds",
                    resource_id=snapshot_arn,
                    resource_name=snapshot_id,
                    check_id="RDS_CLUSTER_SNAPSHOT_PUBLIC",
                    check_title="RDS Cluster Snapshot is Public",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    region=region,
                    account_id=context.account_id,
                    description=f"RDS cluster snapshot '{snapshot_id}' is publicly accessible",
                    recommendation="Remove public access from RDS cluster snapshots to prevent data exposure",
                    remediation_available=True,
                    context={
                        "engine": snapshot.get('Engine'),
                        "encrypted": snapshot.get('StorageEncrypted', False)
                    }
                ))
                break
    except ClientError as e:
        logger.warning(f"Could not check cluster snapshot attributes for {snapshot_id}: {e}")
    
    # Check if cluster snapshot is encrypted
    if not snapshot.get('StorageEncrypted', False):
        findings.append(Finding(
            service="rds",
            resource_id=snapshot_arn,
            resource_name=snapshot_id,
            check_id="RDS_CLUSTER_SNAPSHOT_NOT_ENCRYPTED",
            check_title="RDS Cluster Snapshot Not Encrypted",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=region,
            account_id=context.account_id,
            description=f"RDS cluster snapshot '{snapshot_id}' is not encrypted",
            recommendation="Ensure all RDS cluster snapshots are encrypted to protect data at rest",
            context={
                "engine": snapshot.get('Engine'),
                "source_cluster": snapshot.get('DBClusterIdentifier')
            }
        ))
    
    return findings


async def scan_parameter_groups(rds_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan RDS parameter groups for security configuration issues."""
    findings = []
    
    try:
        paginator = rds_client.get_paginator('describe_db_parameter_groups')
        async for page in paginator.paginate():
            for param_group in page['DBParameterGroups']:
                if not param_group['DBParameterGroupName'].startswith('default.'):
                    param_findings = await analyze_parameter_group(param_group, rds_client, context, region)
                    findings.extend(param_findings)
                    
    except ClientError as e:
        logger.error(f"Failed to describe parameter groups in {region}: {e}")
    
    return findings


async def analyze_parameter_group(param_group: Dict, rds_client, context: AuditContext, region: str) -> List[Finding]:
    """Analyze parameter group for security misconfigurations."""
    findings = []
    param_group_name = param_group['DBParameterGroupName']
    param_group_arn = param_group['DBParameterGroupArn']
    
    try:
        # Get parameters for this group
        paginator = rds_client.get_paginator('describe_db_parameters')
        security_params = {}
        
        async for page in paginator.paginate(DBParameterGroupName=param_group_name):
            for param in page['Parameters']:
                param_name = param['ParameterName']
                param_value = param.get('ParameterValue', '')
                
                # Check for insecure logging settings
                if 'log' in param_name.lower() and param_value in ['0', 'OFF', 'false']:
                    if param_name in ['general_log', 'slow_query_log', 'log_statement']:
                        security_params[param_name] = param_value
        
        # Report insecure logging configuration
        if security_params:
            findings.append(Finding(
                service="rds",
                resource_id=param_group_arn,
                resource_name=param_group_name,
                check_id="RDS_PARAMETER_GROUP_INSECURE_LOGGING",
                check_title="RDS Parameter Group Has Insecure Logging Configuration",
                status=Status.WARNING,
                severity=Severity.LOW,
                region=region,
                account_id=context.account_id,
                description=f"Parameter group '{param_group_name}' has logging parameters disabled",
                recommendation="Enable appropriate logging parameters for security monitoring and compliance",
                context={
                    "engine_family": param_group.get('DBParameterGroupFamily'),
                    "disabled_logging": security_params
                }
            ))
            
    except ClientError as e:
        logger.warning(f"Could not analyze parameters for group {param_group_name}: {e}")
    
    return findings


async def scan_option_groups(rds_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan RDS option groups for security issues."""
    findings = []
    
    try:
        paginator = rds_client.get_paginator('describe_option_groups')
        async for page in paginator.paginate():
            for option_group in page['OptionGroupsList']:
                if not option_group['OptionGroupName'].startswith('default:'):
                    option_findings = await analyze_option_group(option_group, context, region)
                    findings.extend(option_findings)
                    
    except ClientError as e:
        logger.error(f"Failed to describe option groups in {region}: {e}")
    
    return findings


async def analyze_option_group(option_group: Dict, context: AuditContext, region: str) -> List[Finding]:
    """Analyze option group for security issues."""
    findings = []
    option_group_name = option_group['OptionGroupName']
    option_group_arn = option_group['OptionGroupArn']
    
    # Check for potentially insecure options
    insecure_options = []
    for option in option_group.get('Options', []):
        option_name = option['OptionName']
        
        # Flag potentially insecure options
        if option_name.upper() in ['OEM', 'APEX', 'TDE']:  # Oracle specific potentially risky options
            insecure_options.append(option_name)
    
    if insecure_options:
        findings.append(Finding(
            service="rds",
            resource_id=option_group_arn,
            resource_name=option_group_name,
            check_id="RDS_OPTION_GROUP_POTENTIALLY_INSECURE_OPTIONS",
            check_title="RDS Option Group Contains Potentially Insecure Options",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Option group '{option_group_name}' contains potentially insecure options: {', '.join(insecure_options)}",
            recommendation="Review option group configuration and ensure all options are necessary and properly configured",
            context={
                "engine_name": option_group.get('EngineName'),
                "major_engine_version": option_group.get('MajorEngineVersion'),
                "insecure_options": insecure_options
            }
        ))
    
    return findings


def _is_production_instance(instance: Dict) -> bool:
    """Determine if RDS instance is likely production based on various indicators."""
    instance_id = instance.get('DBInstanceIdentifier', '').lower()
    instance_class = instance.get('DBInstanceClass', '')
    
    # Check naming patterns
    if any(keyword in instance_id for keyword in ['prod', 'production', 'live']):
        return True
    
    # Check instance class (larger instances more likely to be production)
    if any(instance_class.startswith(prefix) for prefix in ['db.r5.', 'db.r6g.', 'db.m5.', 'db.m6i.']):
        return True
    
    # Check tags for environment indicators
    for tag in instance.get('TagList', []):
        if tag.get('Key', '').lower() == 'environment':
            env_value = tag.get('Value', '').lower()
            if env_value in ['prod', 'production', 'live']:
                return True
    
    return False


def _is_production_cluster(cluster: Dict) -> bool:
    """Determine if RDS cluster is likely production based on various indicators."""
    cluster_id = cluster.get('DBClusterIdentifier', '').lower()
    
    # Check naming patterns
    if any(keyword in cluster_id for keyword in ['prod', 'production', 'live']):
        return True
    
    # Check tags for environment indicators
    for tag in cluster.get('TagList', []):
        if tag.get('Key', '').lower() == 'environment':
            env_value = tag.get('Value', '').lower()
            if env_value in ['prod', 'production', 'live']:
                return True
    
    return False


def register() -> ScannerPlugin:
    """Register the RDS security scanner plugin."""
    return ScannerPlugin(
        service="rds",
        required_permissions=[
            "rds:DescribeDBInstances",
            "rds:DescribeDBClusters",
            "rds:DescribeDBSnapshots",
            "rds:DescribeDBClusterSnapshots",
            "rds:DescribeDBSnapshotAttributes",
            "rds:DescribeDBClusterSnapshotAttributes",
            "rds:DescribeDBParameterGroups",
            "rds:DescribeDBParameters",
            "rds:DescribeOptionGroups",
            "rds:DescribeDBSubnetGroups",
            "rds:ListTagsForResource"
        ],
        scan_function=scan_rds,
        remediation_map={
            "RDS_INSTANCE_NOT_ENCRYPTED": "create_encrypted_copy",
            "RDS_INSTANCE_PUBLICLY_ACCESSIBLE": "modify_instance_accessibility",
            "RDS_INSTANCE_BACKUP_RETENTION_LOW": "modify_backup_retention",
            "RDS_PRODUCTION_NO_MULTI_AZ": "enable_multi_az",
            "RDS_PRODUCTION_NO_DELETION_PROTECTION": "enable_deletion_protection",
            "RDS_CLUSTER_NOT_ENCRYPTED": "create_encrypted_cluster_copy",
            "RDS_CLUSTER_BACKUP_RETENTION_LOW": "modify_cluster_backup_retention",
            "RDS_CLUSTER_NO_DELETION_PROTECTION": "enable_cluster_deletion_protection",
            "RDS_SNAPSHOT_PUBLIC": "modify_snapshot_attributes",
            "RDS_CLUSTER_SNAPSHOT_PUBLIC": "modify_cluster_snapshot_attributes",
            "RDS_SNAPSHOT_NOT_ENCRYPTED": "create_encrypted_snapshot_copy",
            "RDS_CLUSTER_SNAPSHOT_NOT_ENCRYPTED": "create_encrypted_cluster_snapshot_copy"
        }
    )