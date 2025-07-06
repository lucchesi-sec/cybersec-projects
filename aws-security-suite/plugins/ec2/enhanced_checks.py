"""
Enhanced EC2 Security Checks
Additional high-value security validations for EC2 resources.
"""

import asyncio
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
import logging

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext

logger = logging.getLogger(__name__)

# Production instance types that should have termination protection
PRODUCTION_INSTANCE_TYPES = [
    'c5.large', 'c5.xlarge', 'c5.2xlarge', 'c5.4xlarge',
    'm5.large', 'm5.xlarge', 'm5.2xlarge', 'm5.4xlarge',
    'r5.large', 'r5.xlarge', 'r5.2xlarge', 'r5.4xlarge'
]

# Required tags for compliance
REQUIRED_TAGS = ['Environment', 'Owner', 'Project', 'CostCenter']

# High-risk NACL rules (ports that should be carefully controlled)
SENSITIVE_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 27017]


async def check_instance_termination_protection(
    ec2_client, instance: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Check if production instances have termination protection enabled."""
    findings = []
    instance_id = instance['InstanceId']
    instance_name = _get_instance_name(instance)
    instance_type = instance.get('InstanceType', '')
    
    # Check if this looks like a production instance
    is_production = (
        instance_type in PRODUCTION_INSTANCE_TYPES or
        'prod' in instance_name.lower() or
        'production' in instance_name.lower() or
        any(tag.get('Key', '').lower() == 'environment' and 
            'prod' in tag.get('Value', '').lower() 
            for tag in instance.get('Tags', []))
    )
    
    if is_production:
        try:
            response = ec2_client.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute='disableApiTermination'
            )
            
            if not response.get('DisableApiTermination', {}).get('Value', False):
                findings.append(Finding(
                    service="ec2",
                    resource_id=f"arn:aws:ec2:{region}:{context.account_id}:instance/{instance_id}",
                    resource_name=instance_name,
                    check_id="EC2_PRODUCTION_TERMINATION_PROTECTION",
                    check_title="Production Instance Missing Termination Protection",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    region=region,
                    account_id=context.account_id,
                    description=f"Production instance '{instance_name}' does not have termination protection enabled",
                    recommendation="Enable termination protection for production instances",
                    remediation_available=True,
                    context={
                        "instance_type": instance_type,
                        "termination_protection": False
                    }
                ))
                
        except ClientError as e:
            logger.warning(f"Failed to check termination protection for {instance_id}: {e}")
    
    return findings


async def check_instance_tag_compliance(
    instance: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Check if instances have required tags for governance."""
    findings = []
    instance_id = instance['InstanceId']
    instance_name = _get_instance_name(instance)
    
    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
    missing_tags = [tag for tag in REQUIRED_TAGS if tag not in tags]
    
    if missing_tags:
        findings.append(Finding(
            service="ec2",
            resource_id=f"arn:aws:ec2:{region}:{context.account_id}:instance/{instance_id}",
            resource_name=instance_name,
            check_id="EC2_INSTANCE_MISSING_REQUIRED_TAGS",
            check_title="Instance Missing Required Tags",
            status=Status.FAIL,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Instance '{instance_name}' is missing required tags: {', '.join(missing_tags)}",
            recommendation=f"Add required tags: {', '.join(missing_tags)}",
            context={
                "missing_tags": missing_tags,
                "current_tags": list(tags.keys())
            }
        ))
    
    return findings


async def scan_network_acls(ec2_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan Network ACLs for security issues."""
    findings = []
    
    try:
        response = ec2_client.describe_network_acls()
        
        for nacl in response['NetworkAcls']:
            nacl_findings = await _analyze_network_acl(nacl, context, region)
            findings.extend(nacl_findings)
            
    except ClientError as e:
        logger.error(f"Failed to describe network ACLs in {region}: {e}")
    
    return findings


async def _analyze_network_acl(nacl: Dict, context: AuditContext, region: str) -> List[Finding]:
    """Analyze a single Network ACL for security issues."""
    findings = []
    nacl_id = nacl['NetworkAclId']
    is_default = nacl.get('IsDefault', False)
    
    # Check for overly permissive default NACL
    if is_default:
        for entry in nacl.get('Entries', []):
            if (entry.get('CidrBlock') == '0.0.0.0/0' and 
                entry.get('RuleAction') == 'allow' and
                not entry.get('Egress', False)):  # Ingress rule
                
                port_range = entry.get('PortRange', {})
                from_port = port_range.get('From', 0)
                to_port = port_range.get('To', 65535)
                
                # Check if sensitive ports are exposed
                for port in SENSITIVE_PORTS:
                    if from_port <= port <= to_port:
                        findings.append(Finding(
                            service="ec2",
                            resource_id=f"arn:aws:ec2:{region}:{context.account_id}:network-acl/{nacl_id}",
                            resource_name=f"Default NACL {nacl_id}",
                            check_id="EC2_DEFAULT_NACL_OVERLY_PERMISSIVE",
                            check_title="Default Network ACL Allows Sensitive Ports",
                            status=Status.FAIL,
                            severity=Severity.HIGH,
                            region=region,
                            account_id=context.account_id,
                            description=f"Default NACL allows access to sensitive port {port} from 0.0.0.0/0",
                            recommendation="Restrict Network ACL rules to specific IP ranges and required ports only",
                            context={
                                "sensitive_port": port,
                                "from_port": from_port,
                                "to_port": to_port,
                                "rule_number": entry.get('RuleNumber')
                            }
                        ))
                        break  # Only report once per rule
    
    return findings


async def scan_unused_security_groups(ec2_client, context: AuditContext, region: str) -> List[Finding]:
    """Identify unused security groups."""
    findings = []
    
    try:
        # Get all security groups
        sg_response = ec2_client.describe_security_groups()
        all_sgs = {sg['GroupId']: sg for sg in sg_response['SecurityGroups']}
        
        # Get security groups in use by instances
        used_sgs = set()
        
        instances_response = ec2_client.describe_instances()
        for reservation in instances_response['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] != 'terminated':
                    for sg in instance.get('SecurityGroups', []):
                        used_sgs.add(sg['GroupId'])
        
        # Check for unused security groups (excluding default)
        for sg_id, sg in all_sgs.items():
            if (sg_id not in used_sgs and 
                sg['GroupName'] != 'default' and
                not sg.get('IsDefault', False)):
                
                findings.append(Finding(
                    service="ec2",
                    resource_id=f"arn:aws:ec2:{region}:{context.account_id}:security-group/{sg_id}",
                    resource_name=sg['GroupName'],
                    check_id="EC2_UNUSED_SECURITY_GROUP",
                    check_title="Unused Security Group",
                    status=Status.WARNING,
                    severity=Severity.LOW,
                    region=region,
                    account_id=context.account_id,
                    description=f"Security group '{sg['GroupName']}' is not attached to any instances",
                    recommendation="Remove unused security groups to reduce attack surface",
                    remediation_available=True,
                    context={
                        "vpc_id": sg.get('VpcId'),
                        "description": sg.get('Description', ''),
                        "rules_count": len(sg.get('IpPermissions', []))
                    }
                ))
                
    except ClientError as e:
        logger.error(f"Failed to scan for unused security groups in {region}: {e}")
    
    return findings


async def check_ebs_snapshot_lifecycle(ec2_client, context: AuditContext, region: str) -> List[Finding]:
    """Check EBS volumes for snapshot lifecycle management."""
    findings = []
    
    try:
        volumes_response = ec2_client.describe_volumes()
        
        for volume in volumes_response['Volumes']:
            volume_id = volume['VolumeId']
            volume_name = _get_volume_name(volume)
            
            # Check if volume has recent snapshots
            snapshots_response = ec2_client.describe_snapshots(
                OwnerIds=['self'],
                Filters=[{'Name': 'volume-id', 'Values': [volume_id]}]
            )
            
            snapshots = snapshots_response.get('Snapshots', [])
            if not snapshots:
                # Volume has no snapshots
                findings.append(Finding(
                    service="ec2",
                    resource_id=f"arn:aws:ec2:{region}:{context.account_id}:volume/{volume_id}",
                    resource_name=volume_name,
                    check_id="EC2_EBS_NO_SNAPSHOTS",
                    check_title="EBS Volume Has No Snapshots",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    region=region,
                    account_id=context.account_id,
                    description=f"EBS volume '{volume_name}' has no snapshots for backup",
                    recommendation="Create regular snapshots or enable automated backup policies",
                    context={
                        "volume_size": volume.get('Size'),
                        "volume_type": volume.get('VolumeType'),
                        "state": volume.get('State')
                    }
                ))
            
    except ClientError as e:
        logger.error(f"Failed to check EBS snapshot lifecycle in {region}: {e}")
    
    return findings


def _get_instance_name(instance: Dict) -> str:
    """Get instance name from tags."""
    for tag in instance.get('Tags', []):
        if tag['Key'] == 'Name':
            return tag['Value']
    return instance['InstanceId']


def _get_volume_name(volume: Dict) -> str:
    """Get volume name from tags."""
    for tag in volume.get('Tags', []):
        if tag['Key'] == 'Name':
            return tag['Value']
    return volume['VolumeId']