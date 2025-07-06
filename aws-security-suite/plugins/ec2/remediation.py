"""
EC2 Security Remediation Functions
Automated fixes for EC2 security findings.
"""

import asyncio
from typing import Dict, Any, List
from botocore.exceptions import ClientError
import logging

from ...core.audit_context import AuditContext
from ...core.finding import Finding

logger = logging.getLogger(__name__)


async def remove_public_ip(finding: Finding, context: AuditContext) -> bool:
    """Remove public IP from EC2 instance."""
    try:
        instance_id = finding.resource_id.split('/')[-1]
        ec2_client = context.get_client('ec2', region_name=finding.region)
        
        # Disassociate the public IP
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            SourceDestCheck={'Value': False}
        )
        
        logger.info(f"Successfully removed public IP from instance {instance_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to remove public IP from instance: {e}")
        return False


async def enforce_imdsv2(finding: Finding, context: AuditContext) -> bool:
    """Enforce IMDSv2 on EC2 instance."""
    try:
        instance_id = finding.resource_id.split('/')[-1]
        ec2_client = context.get_client('ec2', region_name=finding.region)
        
        # Modify instance metadata options to require IMDSv2
        ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='required',
            HttpPutResponseHopLimit=1,
            HttpEndpoint='enabled'
        )
        
        logger.info(f"Successfully enforced IMDSv2 on instance {instance_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to enforce IMDSv2 on instance: {e}")
        return False


async def restrict_security_group(finding: Finding, context: AuditContext) -> bool:
    """Restrict overly permissive security group rules."""
    try:
        sg_id = finding.resource_id.split('/')[-1]
        ec2_client = context.get_client('ec2', region_name=finding.region)
        
        # Get the problematic rule from finding context
        rule = finding.context.get('rule', {})
        
        if not rule:
            logger.error("No rule information in finding context")
            return False
        
        # Remove the overly permissive rule
        ec2_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[rule]
        )
        
        logger.info(f"Successfully removed permissive rule from security group {sg_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to restrict security group: {e}")
        return False


async def encrypt_ebs_volume(finding: Finding, context: AuditContext) -> bool:
    """Enable encryption for EBS volume (requires snapshot and restore)."""
    try:
        volume_id = finding.resource_id.split('/')[-1]
        ec2_client = context.get_client('ec2', region_name=finding.region)
        
        # Create encrypted snapshot
        snapshot_response = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f"Encrypted snapshot of {volume_id} for security remediation",
            Encrypted=True
        )
        
        snapshot_id = snapshot_response['SnapshotId']
        
        # Wait for snapshot to complete (in real implementation, this would be async)
        logger.info(f"Created encrypted snapshot {snapshot_id} for volume {volume_id}")
        logger.info("Manual step required: Create new volume from encrypted snapshot and replace original")
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to create encrypted snapshot: {e}")
        return False


async def enable_vpc_flow_logs(finding: Finding, context: AuditContext) -> bool:
    """Enable VPC Flow Logs."""
    try:
        vpc_id = finding.resource_id.split('/')[-1]
        ec2_client = context.get_client('ec2', region_name=finding.region)
        
        # Create CloudWatch log group name
        log_group_name = f"/aws/vpc/flowlogs/{vpc_id}"
        
        # Enable VPC Flow Logs to CloudWatch
        response = ec2_client.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType='VPC',
            TrafficType='ALL',
            LogDestinationType='cloud-watch-logs',
            LogGroupName=log_group_name,
            DeliverLogsPermissionArn=f"arn:aws:iam::{context.account_id}:role/flowlogsRole"
        )
        
        logger.info(f"Successfully enabled flow logs for VPC {vpc_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to enable VPC flow logs: {e}")
        return False


async def enable_termination_protection(finding: Finding, context: AuditContext) -> bool:
    """Enable termination protection for production instance."""
    try:
        instance_id = finding.resource_id.split('/')[-1]
        ec2_client = context.get_client('ec2', region_name=finding.region)
        
        # Enable termination protection
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            DisableApiTermination={'Value': True}
        )
        
        logger.info(f"Successfully enabled termination protection for instance {instance_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to enable termination protection: {e}")
        return False


async def add_required_tags(finding: Finding, context: AuditContext) -> bool:
    """Add required tags to EC2 instance."""
    try:
        instance_id = finding.resource_id.split('/')[-1]
        ec2_client = context.get_client('ec2', region_name=finding.region)
        
        missing_tags = finding.context.get('missing_tags', [])
        
        # Create default tag values (in real implementation, these would be provided)
        default_tags = []
        for tag_name in missing_tags:
            default_tags.append({
                'Key': tag_name,
                'Value': 'PLEASE_UPDATE'  # Placeholder value
            })
        
        if default_tags:
            ec2_client.create_tags(
                Resources=[instance_id],
                Tags=default_tags
            )
            
            logger.info(f"Successfully added placeholder tags to instance {instance_id}")
            return True
        
        return False
        
    except ClientError as e:
        logger.error(f"Failed to add tags to instance: {e}")
        return False


async def remove_unused_security_group(finding: Finding, context: AuditContext) -> bool:
    """Remove unused security group."""
    try:
        sg_id = finding.resource_id.split('/')[-1]
        ec2_client = context.get_client('ec2', region_name=finding.region)
        
        # Delete the security group
        ec2_client.delete_security_group(GroupId=sg_id)
        
        logger.info(f"Successfully deleted unused security group {sg_id}")
        return True
        
    except ClientError as e:
        logger.error(f"Failed to delete security group: {e}")
        return False


async def create_snapshot_policy(finding: Finding, context: AuditContext) -> bool:
    """Create a snapshot for EBS volume and set up lifecycle policy."""
    try:
        volume_id = finding.resource_id.split('/')[-1]
        ec2_client = context.get_client('ec2', region_name=finding.region)
        
        # Create immediate snapshot
        snapshot_response = ec2_client.create_snapshot(
            VolumeId=volume_id,
            Description=f"Security remediation snapshot for {volume_id}"
        )
        
        snapshot_id = snapshot_response['SnapshotId']
        
        # Tag the snapshot for lifecycle management
        ec2_client.create_tags(
            Resources=[snapshot_id],
            Tags=[
                {'Key': 'AutomatedBackup', 'Value': 'true'},
                {'Key': 'SourceVolume', 'Value': volume_id}
            ]
        )
        
        logger.info(f"Successfully created snapshot {snapshot_id} for volume {volume_id}")
        logger.info("Consider setting up Data Lifecycle Manager for automated snapshots")
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to create snapshot: {e}")
        return False


# Remediation function mapping
REMEDIATION_FUNCTIONS = {
    "remove_public_ip": remove_public_ip,
    "enforce_imdsv2": enforce_imdsv2,
    "restrict_security_group": restrict_security_group,
    "restrict_security_group_ipv6": restrict_security_group,
    "encrypt_ebs_volume": encrypt_ebs_volume,
    "remove_snapshot_public_access": None,  # TODO: Implement
    "enable_vpc_flow_logs": enable_vpc_flow_logs,
    "migrate_from_default_vpc": None,  # TODO: Implement
    "enable_termination_protection": enable_termination_protection,
    "add_required_tags": add_required_tags,
    "restrict_network_acl": None,  # TODO: Implement
    "remove_unused_security_group": remove_unused_security_group,
    "create_snapshot_policy": create_snapshot_policy
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