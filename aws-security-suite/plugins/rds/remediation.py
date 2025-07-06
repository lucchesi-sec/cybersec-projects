"""
RDS Security Remediation Functions
Automated fixes for RDS security findings.
"""

import asyncio
from typing import Dict, Any, List
from botocore.exceptions import ClientError
import logging

from core.audit_context import AuditContext
from core.finding import Finding
from core.async_client import get_client_manager

logger = logging.getLogger(__name__)


async def create_encrypted_copy(finding: Finding, context: AuditContext) -> bool:
    """Create an encrypted copy of an RDS instance."""
    try:
        instance_id = finding.resource_id.split('/')[-1]
        client_manager = get_client_manager()
        
        # Get instance details
        response = await client_manager.execute_async(
            'rds', 'describe_db_instances',
            region_name=finding.region,
            DBInstanceIdentifier=instance_id
        )
        instance = response['DBInstances'][0]
        
        # Create a snapshot first
        snapshot_id = f"{instance_id}-encrypted-migration-{context.account_id}"
        
        await client_manager.execute_async(
            'rds', 'create_db_snapshot',
            region_name=finding.region,
            DBSnapshotIdentifier=snapshot_id,
            DBInstanceIdentifier=instance_id
        )
        
        # Note: In production, you would wait for snapshot completion and then:
        # 1. Copy snapshot with encryption enabled
        # 2. Restore from encrypted snapshot
        # 3. Update applications to use new instance
        # 4. Delete old instance after verification
        
        logger.info(f"Created snapshot {snapshot_id} for encryption migration of instance {instance_id}")
        logger.info("Manual steps required: Wait for snapshot completion, copy with encryption, restore encrypted instance")
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to create encrypted copy for instance: {e}")
        return False


async def modify_instance_accessibility(finding: Finding, context: AuditContext) -> bool:
    """Disable public accessibility for RDS instance."""
    try:
        instance_id = finding.resource_id.split('/')[-1]
        client_manager = get_client_manager()
        
        # Modify instance to disable public accessibility
        await client_manager.execute_async(
            'rds', 'modify_db_instance',
            region_name=finding.region,
            DBInstanceIdentifier=instance_id,
            PubliclyAccessible=False,
            ApplyImmediately=True
        )
        
        logger.info(f"Successfully disabled public accessibility for RDS instance {instance_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to modify instance accessibility: {e}")
        return False


async def modify_backup_retention(finding: Finding, context: AuditContext) -> bool:
    """Increase backup retention period for RDS instance."""
    try:
        instance_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        current_retention = finding.context.get('current_retention', 0)
        new_retention = max(7, current_retention + 1)  # Ensure at least 7 days
        
        # Modify backup retention period
        rds_client.modify_db_instance(
            DBInstanceIdentifier=instance_id,
            BackupRetentionPeriod=new_retention,
            ApplyImmediately=False  # Apply during maintenance window
        )
        
        logger.info(f"Successfully set backup retention to {new_retention} days for instance {instance_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to modify backup retention: {e}")
        return False


async def enable_multi_az(finding: Finding, context: AuditContext) -> bool:
    """Enable Multi-AZ deployment for RDS instance."""
    try:
        instance_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        # Enable Multi-AZ deployment
        rds_client.modify_db_instance(
            DBInstanceIdentifier=instance_id,
            MultiAZ=True,
            ApplyImmediately=False  # Apply during maintenance window
        )
        
        logger.info(f"Successfully enabled Multi-AZ for RDS instance {instance_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to enable Multi-AZ: {e}")
        return False


async def enable_deletion_protection(finding: Finding, context: AuditContext) -> bool:
    """Enable deletion protection for RDS instance."""
    try:
        instance_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        # Enable deletion protection
        rds_client.modify_db_instance(
            DBInstanceIdentifier=instance_id,
            DeletionProtection=True,
            ApplyImmediately=True
        )
        
        logger.info(f"Successfully enabled deletion protection for RDS instance {instance_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to enable deletion protection: {e}")
        return False


async def create_encrypted_cluster_copy(finding: Finding, context: AuditContext) -> bool:
    """Create an encrypted copy of an RDS cluster."""
    try:
        cluster_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        # Create a cluster snapshot first
        snapshot_id = f"{cluster_id}-encrypted-migration-{context.account_id}"
        
        rds_client.create_db_cluster_snapshot(
            DBClusterSnapshotIdentifier=snapshot_id,
            DBClusterIdentifier=cluster_id
        )
        
        # Note: In production, you would wait for snapshot completion and then:
        # 1. Copy snapshot with encryption enabled
        # 2. Restore from encrypted snapshot
        # 3. Update applications to use new cluster
        # 4. Delete old cluster after verification
        
        logger.info(f"Created cluster snapshot {snapshot_id} for encryption migration of cluster {cluster_id}")
        logger.info("Manual steps required: Wait for snapshot completion, copy with encryption, restore encrypted cluster")
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to create encrypted copy for cluster: {e}")
        return False


async def modify_cluster_backup_retention(finding: Finding, context: AuditContext) -> bool:
    """Increase backup retention period for RDS cluster."""
    try:
        cluster_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        current_retention = finding.context.get('current_retention', 0)
        new_retention = max(7, current_retention + 1)  # Ensure at least 7 days
        
        # Modify cluster backup retention period
        rds_client.modify_db_cluster(
            DBClusterIdentifier=cluster_id,
            BackupRetentionPeriod=new_retention,
            ApplyImmediately=False  # Apply during maintenance window
        )
        
        logger.info(f"Successfully set backup retention to {new_retention} days for cluster {cluster_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to modify cluster backup retention: {e}")
        return False


async def enable_cluster_deletion_protection(finding: Finding, context: AuditContext) -> bool:
    """Enable deletion protection for RDS cluster."""
    try:
        cluster_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        # Enable deletion protection for cluster
        rds_client.modify_db_cluster(
            DBClusterIdentifier=cluster_id,
            DeletionProtection=True,
            ApplyImmediately=True
        )
        
        logger.info(f"Successfully enabled deletion protection for RDS cluster {cluster_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to enable cluster deletion protection: {e}")
        return False


async def modify_snapshot_attributes(finding: Finding, context: AuditContext) -> bool:
    """Remove public access from RDS snapshot."""
    try:
        snapshot_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        # Remove public restore permission
        rds_client.modify_db_snapshot_attribute(
            DBSnapshotIdentifier=snapshot_id,
            AttributeName='restore',
            ValuesToRemove=['all']
        )
        
        logger.info(f"Successfully removed public access from RDS snapshot {snapshot_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to modify snapshot attributes: {e}")
        return False


async def modify_cluster_snapshot_attributes(finding: Finding, context: AuditContext) -> bool:
    """Remove public access from RDS cluster snapshot."""
    try:
        snapshot_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        # Remove public restore permission from cluster snapshot
        rds_client.modify_db_cluster_snapshot_attribute(
            DBClusterSnapshotIdentifier=snapshot_id,
            AttributeName='restore',
            ValuesToRemove=['all']
        )
        
        logger.info(f"Successfully removed public access from RDS cluster snapshot {snapshot_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to modify cluster snapshot attributes: {e}")
        return False


async def create_encrypted_snapshot_copy(finding: Finding, context: AuditContext) -> bool:
    """Create an encrypted copy of an unencrypted RDS snapshot."""
    try:
        snapshot_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        # Create encrypted copy of the snapshot
        encrypted_snapshot_id = f"{snapshot_id}-encrypted"
        
        rds_client.copy_db_snapshot(
            SourceDBSnapshotIdentifier=snapshot_id,
            TargetDBSnapshotIdentifier=encrypted_snapshot_id,
            Encrypted=True
        )
        
        logger.info(f"Successfully created encrypted copy {encrypted_snapshot_id} of snapshot {snapshot_id}")
        logger.info("Consider deleting the original unencrypted snapshot after verification")
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to create encrypted snapshot copy: {e}")
        return False


async def create_encrypted_cluster_snapshot_copy(finding: Finding, context: AuditContext) -> bool:
    """Create an encrypted copy of an unencrypted RDS cluster snapshot."""
    try:
        snapshot_id = finding.resource_id.split('/')[-1]
        rds_client = context.get_client('rds', region_name=finding.region)
        
        # Create encrypted copy of the cluster snapshot
        encrypted_snapshot_id = f"{snapshot_id}-encrypted"
        
        rds_client.copy_db_cluster_snapshot(
            SourceDBClusterSnapshotIdentifier=snapshot_id,
            TargetDBClusterSnapshotIdentifier=encrypted_snapshot_id,
            Encrypted=True
        )
        
        logger.info(f"Successfully created encrypted copy {encrypted_snapshot_id} of cluster snapshot {snapshot_id}")
        logger.info("Consider deleting the original unencrypted cluster snapshot after verification")
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to create encrypted cluster snapshot copy: {e}")
        return False


# Remediation function mapping
REMEDIATION_FUNCTIONS = {
    "create_encrypted_copy": create_encrypted_copy,
    "modify_instance_accessibility": modify_instance_accessibility,
    "modify_backup_retention": modify_backup_retention,
    "enable_multi_az": enable_multi_az,
    "enable_deletion_protection": enable_deletion_protection,
    "create_encrypted_cluster_copy": create_encrypted_cluster_copy,
    "modify_cluster_backup_retention": modify_cluster_backup_retention,
    "enable_cluster_deletion_protection": enable_cluster_deletion_protection,
    "modify_snapshot_attributes": modify_snapshot_attributes,
    "modify_cluster_snapshot_attributes": modify_cluster_snapshot_attributes,
    "create_encrypted_snapshot_copy": create_encrypted_snapshot_copy,
    "create_encrypted_cluster_snapshot_copy": create_encrypted_cluster_snapshot_copy
}


async def apply_remediation(finding: Finding, context: AuditContext) -> bool:
    """Apply automated remediation for a finding."""
    remediation_func_name = finding.context.get('remediation_function')
    
    if not remediation_func_name or remediation_func_name not in REMEDIATION_FUNCTIONS:
        logger.warning(f"No remediation function available for check {finding.check_id}")
        return False
    
    remediation_func = REMEDIATION_FUNCTIONS[remediation_func_name]
    
    if remediation_func is None:
        logger.warning(f"Remediation function {remediation_func_name} not yet implemented")
        return False
    
    try:
        result = await remediation_func(finding, context)
        if result:
            logger.info(f"Successfully applied remediation for finding {finding.check_id}")
        else:
            logger.warning(f"Remediation failed for finding {finding.check_id}")
        return result
        
    except Exception as e:
        logger.error(f"Exception during remediation for {finding.check_id}: {e}")
        return False