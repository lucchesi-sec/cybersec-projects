"""
EC2 Security Scanner Plugin
Comprehensive security analysis for EC2 instances, security groups, and related resources.
"""

import asyncio
import json
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
import logging

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext
from core.plugin import ScannerPlugin
from .enhanced_checks import (
    check_instance_termination_protection,
    check_instance_tag_compliance,
    scan_network_acls,
    scan_unused_security_groups,
    check_ebs_snapshot_lifecycle
)


logger = logging.getLogger(__name__)

# High-risk ports that should not be open to 0.0.0.0/0
HIGH_RISK_PORTS = [22, 3389, 5432, 3306, 1433, 6379, 27017, 9200, 5984]

# Critical services that require additional scrutiny
CRITICAL_SERVICES = ['database', 'web', 'api', 'admin']


async def scan_ec2(context: AuditContext) -> List[Finding]:
    """Main EC2 scanning function."""
    findings = []
    
    try:
        ec2_client = context.get_client('ec2')
        
        # Get all regions for EC2 scanning
        regions = await _get_available_regions(ec2_client)
        
        for region in regions:
            logger.info(f"Scanning EC2 resources in region: {region}")
            region_client = context.get_client('ec2', region_name=region)
            
            # Scan EC2 instances
            instance_findings = await _scan_ec2_instances(region_client, context, region)
            findings.extend(instance_findings)
            
            # Scan security groups
            sg_findings = await _scan_security_groups(region_client, context, region)
            findings.extend(sg_findings)
            
            # Scan EBS volumes
            volume_findings = await _scan_ebs_volumes(region_client, context, region)
            findings.extend(volume_findings)
            
            # Scan VPC security
            vpc_findings = await _scan_vpc_security(region_client, context, region)
            findings.extend(vpc_findings)
            
            # Enhanced security checks
            nacl_findings = await scan_network_acls(region_client, context, region)
            findings.extend(nacl_findings)
            
            unused_sg_findings = await scan_unused_security_groups(region_client, context, region)
            findings.extend(unused_sg_findings)
            
            snapshot_findings = await check_ebs_snapshot_lifecycle(region_client, context, region)
            findings.extend(snapshot_findings)
            
    except Exception as e:
        logger.error(f"EC2 scan failed: {e}")
        
    return findings


async def _get_available_regions(ec2_client) -> List[str]:
    """Get list of available regions for the account."""
    try:
        response = ec2_client.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except ClientError as e:
        logger.warning(f"Failed to get regions, using default: {e}")
        return ['us-east-1']  # Fallback to default region
async def _scan_ec2_instances(ec2_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan EC2 instances for security issues."""
    findings = []
    
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'terminated':
                        continue
                        
                    instance_findings = await _analyze_instance_security(
                        ec2_client, instance, context, region
                    )
                    findings.extend(instance_findings)
                    
                    # Enhanced instance checks
                    termination_findings = await check_instance_termination_protection(
                        ec2_client, instance, context, region
                    )
                    findings.extend(termination_findings)
                    
                    tag_findings = await check_instance_tag_compliance(
                        instance, context, region
                    )
                    findings.extend(tag_findings)
                    
    except ClientError as e:
        logger.error(f"Failed to describe instances in {region}: {e}")
    
    return findings


async def _analyze_instance_security(
    ec2_client, instance: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze a single EC2 instance for security issues."""
    findings = []
    instance_id = instance['InstanceId']
    instance_name = _get_instance_name(instance)
    
    # Check for public IP assignment
    if instance.get('PublicIpAddress') or instance.get('PublicDnsName'):
        findings.append(Finding(
            service="ec2",
            resource_id=f"arn:aws:ec2:{region}:{context.account_id}:instance/{instance_id}",
            resource_name=instance_name,
            check_id="EC2_INSTANCE_PUBLIC_IP",
            check_title="EC2 Instance Has Public IP",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"EC2 instance '{instance_name}' has a public IP address assigned",
            recommendation="Remove public IP unless required, use ALB/NLB instead",
            remediation_available=True,
            context={
                "public_ip": instance.get('PublicIpAddress'),
                "public_dns": instance.get('PublicDnsName')
            }
        ))
    
    # Check Instance Metadata Service (IMDS) configuration
    imds_findings = await _check_imds_configuration(instance, context, region)
    findings.extend(imds_findings)    
    # Check IAM instance profile
    if not instance.get('IamInstanceProfile'):
        findings.append(Finding(
            service="ec2",
            resource_id=f"arn:aws:ec2:{region}:{context.account_id}:instance/{instance_id}",
            resource_name=instance_name,
            check_id="EC2_NO_INSTANCE_PROFILE",
            check_title="EC2 Instance Missing IAM Instance Profile",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"EC2 instance '{instance_name}' does not have an IAM instance profile",
            recommendation="Attach an IAM instance profile with minimal required permissions"
        ))
    
    # Check for default VPC usage
    vpc_id = instance.get('VpcId')
    if vpc_id:
        is_default = await _is_default_vpc(ec2_client, vpc_id)
        if is_default:
            findings.append(Finding(
                service="ec2",
                resource_id=f"arn:aws:ec2:{region}:{context.account_id}:instance/{instance_id}",
                resource_name=instance_name,
                check_id="EC2_DEFAULT_VPC_USAGE",
                check_title="EC2 Instance in Default VPC",
                status=Status.FAIL,
                severity=Severity.LOW,
                region=region,
                account_id=context.account_id,
                description=f"EC2 instance '{instance_name}' is running in the default VPC",
                recommendation="Move instance to a custom VPC with proper network segmentation"
            ))
    
    # Check for detailed monitoring
    if not instance.get('Monitoring', {}).get('State') == 'enabled':
        findings.append(Finding(
            service="ec2",
            resource_id=f"arn:aws:ec2:{region}:{context.account_id}:instance/{instance_id}",
            resource_name=instance_name,
            check_id="EC2_DETAILED_MONITORING_DISABLED",
            check_title="EC2 Instance Detailed Monitoring Disabled",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"EC2 instance '{instance_name}' does not have detailed monitoring enabled",
            recommendation="Enable detailed monitoring for better visibility"
        ))
    
    return findings
async def _check_imds_configuration(
    instance: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Check Instance Metadata Service configuration."""
    findings = []
    instance_id = instance['InstanceId']
    instance_name = _get_instance_name(instance)
    
    metadata_options = instance.get('MetadataOptions', {})
    
    # Check if IMDSv2 is enforced
    if metadata_options.get('HttpTokens') != 'required':
        findings.append(Finding(
            service="ec2",
            resource_id=f"arn:aws:ec2:{region}:{context.account_id}:instance/{instance_id}",
            resource_name=instance_name,
            check_id="EC2_IMDS_V2_NOT_ENFORCED",
            check_title="EC2 Instance Metadata Service v2 Not Enforced",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=region,
            account_id=context.account_id,
            description=f"EC2 instance '{instance_name}' does not enforce IMDSv2",
            recommendation="Configure instance to require IMDSv2 tokens",
            remediation_available=True,
            context={"current_setting": metadata_options.get('HttpTokens', 'optional')}
        ))
    
    # Check hop limit (should be 1 for enhanced security)
    hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
    if hop_limit > 1:
        findings.append(Finding(
            service="ec2",
            resource_id=f"arn:aws:ec2:{region}:{context.account_id}:instance/{instance_id}",
            resource_name=instance_name,
            check_id="EC2_IMDS_HOP_LIMIT_HIGH",
            check_title="EC2 IMDS Hop Limit Too High",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"EC2 instance '{instance_name}' has IMDS hop limit of {hop_limit}",
            recommendation="Set IMDS hop limit to 1 to prevent SSRF attacks"
        ))
    
    return findings


async def _scan_security_groups(ec2_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan security groups for security issues."""
    findings = []
    
    try:
        paginator = ec2_client.get_paginator('describe_security_groups')
        
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                sg_findings = await _analyze_security_group(sg, context, region)
                findings.extend(sg_findings)
                
    except ClientError as e:
        logger.error(f"Failed to describe security groups in {region}: {e}")
    
    return findings


async def _analyze_security_group(sg: Dict, context: AuditContext, region: str) -> List[Finding]:
    """Analyze a single security group for security issues."""
    findings = []
    sg_id = sg['GroupId']
    sg_name = sg['GroupName']
    
    # Check inbound rules for overly permissive access
    for rule in sg.get('IpPermissions', []):
        # Check for 0.0.0.0/0 access
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                severity = _get_rule_severity(rule)
                findings.append(Finding(
                    service="ec2",
                    resource_id=f"arn:aws:ec2:{region}:{context.account_id}:security-group/{sg_id}",
                    resource_name=sg_name,
                    check_id="EC2_SG_OPEN_TO_WORLD",
                    check_title="Security Group Open to Internet",
                    status=Status.FAIL,
                    severity=severity,
                    region=region,
                    account_id=context.account_id,
                    description=f"Security group '{sg_name}' allows access from 0.0.0.0/0",
                    recommendation="Restrict access to specific IP ranges or security groups",
                    remediation_available=True,
                    context={
                        "rule": rule,
                        "protocol": rule.get('IpProtocol'),
                        "from_port": rule.get('FromPort'),
                        "to_port": rule.get('ToPort')
                    }
                ))
        
        # Check for ::/0 IPv6 access
        for ipv6_range in rule.get('Ipv6Ranges', []):
            if ipv6_range.get('CidrIpv6') == '::/0':
                severity = _get_rule_severity(rule)
                findings.append(Finding(
                    service="ec2",
                    resource_id=f"arn:aws:ec2:{region}:{context.account_id}:security-group/{sg_id}",
                    resource_name=sg_name,
                    check_id="EC2_SG_OPEN_TO_WORLD_IPV6",
                    check_title="Security Group Open to Internet (IPv6)",
                    status=Status.FAIL,
                    severity=severity,
                    region=region,
                    account_id=context.account_id,
                    description=f"Security group '{sg_name}' allows IPv6 access from ::/0",
                    recommendation="Restrict IPv6 access to specific ranges"
                ))
    
    return findings


async def _scan_ebs_volumes(ec2_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan EBS volumes for security issues."""
    findings = []
    
    try:
        paginator = ec2_client.get_paginator('describe_volumes')
        
        for page in paginator.paginate():
            for volume in page['Volumes']:
                volume_findings = await _analyze_ebs_volume(volume, context, region)
                findings.extend(volume_findings)
                
    except ClientError as e:
        logger.error(f"Failed to describe volumes in {region}: {e}")
    
    return findings


async def _analyze_ebs_volume(volume: Dict, context: AuditContext, region: str) -> List[Finding]:
    """Analyze a single EBS volume for security issues."""
    findings = []
    volume_id = volume['VolumeId']
    volume_name = _get_volume_name(volume)
    
    # Check encryption status
    if not volume.get('Encrypted', False):
        findings.append(Finding(
            service="ec2",
            resource_id=f"arn:aws:ec2:{region}:{context.account_id}:volume/{volume_id}",
            resource_name=volume_name,
            check_id="EC2_EBS_VOLUME_NOT_ENCRYPTED",
            check_title="EBS Volume Not Encrypted",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=region,
            account_id=context.account_id,
            description=f"EBS volume '{volume_name}' is not encrypted",
            recommendation="Enable encryption for EBS volumes to protect data at rest",
            remediation_available=True,
            context={
                "volume_type": volume.get('VolumeType'),
                "size": volume.get('Size'),
                "state": volume.get('State')
            }
        ))
    
    # Check for public snapshots (if volume has snapshots)
    snapshot_findings = await _check_volume_snapshots(ec2_client, volume_id, context, region)
    findings.extend(snapshot_findings)
    
    return findings


async def _scan_vpc_security(ec2_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan VPC configuration for security issues."""
    findings = []
    
    try:
        # Check VPCs
        vpcs_response = ec2_client.describe_vpcs()
        for vpc in vpcs_response['Vpcs']:
            vpc_findings = await _analyze_vpc_security(ec2_client, vpc, context, region)
            findings.extend(vpc_findings)
            
        # Check flow logs
        flow_log_findings = await _check_vpc_flow_logs(ec2_client, context, region)
        findings.extend(flow_log_findings)
        
    except ClientError as e:
        logger.error(f"Failed to scan VPC security in {region}: {e}")
    
    return findings


async def _analyze_vpc_security(
    ec2_client, vpc: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze VPC security configuration."""
    findings = []
    vpc_id = vpc['VpcId']
    is_default = vpc.get('IsDefault', False)
    
    # Check if default VPC is in use with instances
    if is_default:
        instances = await _get_vpc_instances(ec2_client, vpc_id)
        if instances:
            findings.append(Finding(
                service="ec2",
                resource_id=f"arn:aws:ec2:{region}:{context.account_id}:vpc/{vpc_id}",
                resource_name=f"Default VPC ({vpc_id})",
                check_id="EC2_DEFAULT_VPC_IN_USE",
                check_title="Default VPC Contains Running Instances",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Default VPC '{vpc_id}' contains {len(instances)} running instances",
                recommendation="Migrate instances to custom VPC with proper network segmentation",
                context={"instance_count": len(instances)}
            ))
    
    return findings


async def _check_vpc_flow_logs(ec2_client, context: AuditContext, region: str) -> List[Finding]:
    """Check if VPC Flow Logs are enabled."""
    findings = []
    
    try:
        # Get all VPCs
        vpcs_response = ec2_client.describe_vpcs()
        vpc_ids = [vpc['VpcId'] for vpc in vpcs_response['Vpcs']]
        
        # Check flow logs
        flow_logs_response = ec2_client.describe_flow_logs()
        vpc_with_flow_logs = set()
        
        for flow_log in flow_logs_response['FlowLogs']:
            if flow_log.get('ResourceType') == 'VPC' and flow_log.get('FlowLogStatus') == 'ACTIVE':
                vpc_with_flow_logs.add(flow_log['ResourceIds'][0])
        
        # Find VPCs without flow logs
        for vpc_id in vpc_ids:
            if vpc_id not in vpc_with_flow_logs:
                findings.append(Finding(
                    service="ec2",
                    resource_id=f"arn:aws:ec2:{region}:{context.account_id}:vpc/{vpc_id}",
                    resource_name=f"VPC {vpc_id}",
                    check_id="EC2_VPC_FLOW_LOGS_DISABLED",
                    check_title="VPC Flow Logs Not Enabled",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    region=region,
                    account_id=context.account_id,
                    description=f"VPC '{vpc_id}' does not have flow logs enabled",
                    recommendation="Enable VPC Flow Logs for network monitoring and security analysis",
                    remediation_available=True
                ))
                
    except ClientError as e:
        logger.warning(f"Failed to check VPC flow logs in {region}: {e}")
    
    return findings# Helper functions

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


def _get_rule_severity(rule: Dict) -> Severity:
    """Determine severity based on the security group rule."""
    from_port = rule.get('FromPort')
    to_port = rule.get('ToPort')
    protocol = rule.get('IpProtocol')
    
    # Check for high-risk ports
    if from_port and to_port:
        for port in range(from_port, to_port + 1):
            if port in HIGH_RISK_PORTS:
                return Severity.CRITICAL
    elif from_port in HIGH_RISK_PORTS:
        return Severity.CRITICAL
    
    # All traffic allowed
    if protocol == '-1':
        return Severity.HIGH
    
    # HTTP/HTTPS to world (common but should be reviewed)
    if from_port in [80, 443]:
        return Severity.MEDIUM
    
    return Severity.HIGH  # Default for other open portsasync def _is_default_vpc(ec2_client, vpc_id: str) -> bool:
    """Check if VPC is the default VPC."""
    try:
        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        return response['Vpcs'][0].get('IsDefault', False)
    except Exception as e:
        logger.warning(f"Failed to check if VPC {vpc_id} is default: {e}")
        return False


async def _get_vpc_instances(ec2_client, vpc_id: str) -> List[str]:
    """Get running instances in a VPC."""
    try:
        response = ec2_client.describe_instances(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'instance-state-name', 'Values': ['running', 'pending']}
            ]
        )
        
        instance_ids = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_ids.append(instance['InstanceId'])
        
        return instance_ids
    except Exception as e:
        logger.warning(f"Failed to get instances for VPC {vpc_id}: {e}")
        return []


async def _check_volume_snapshots(
    ec2_client, volume_id: str, context: AuditContext, region: str
) -> List[Finding]:
    """Check for public snapshots of a volume."""
    findings = []
    
    try:
        response = ec2_client.describe_snapshots(
            OwnerIds=['self'],
            Filters=[{'Name': 'volume-id', 'Values': [volume_id]}]
        )
        
        for snapshot in response['Snapshots']:
            # Check if snapshot is public
            try:
                attrs = ec2_client.describe_snapshot_attribute(
                    SnapshotId=snapshot['SnapshotId'],
                    Attribute='createVolumePermission'
                )
                
                for perm in attrs.get('CreateVolumePermissions', []):
                    if perm.get('Group') == 'all':
                        findings.append(Finding(
                            service="ec2",
                            resource_id=f"arn:aws:ec2:{region}:{context.account_id}:snapshot/{snapshot['SnapshotId']}",
                            resource_name=snapshot['SnapshotId'],
                            check_id="EC2_PUBLIC_SNAPSHOT",
                            check_title="EBS Snapshot is Public",
                            status=Status.FAIL,
                            severity=Severity.CRITICAL,
                            region=region,
                            account_id=context.account_id,
                            description=f"EBS snapshot '{snapshot['SnapshotId']}' is publicly accessible",
                            recommendation="Remove public access from EBS snapshots",
                            remediation_available=True
                        ))
                        
            except ClientError:
                pass  # Snapshot might not have permissions set
                
    except Exception as e:
        logger.warning(f"Failed to check snapshots for volume {volume_id}: {e}")
    
    return findings


def register() -> ScannerPlugin:
    """Register EC2 scanner plugin."""
    return ScannerPlugin(
        service="ec2",
        required_permissions=[
            # EC2 Instances
            "ec2:DescribeInstances",
            "ec2:DescribeInstanceAttribute",
            "ec2:DescribeInstanceTypes",
            
            # Security Groups
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeSecurityGroupRules",
            
            # EBS Volumes and Snapshots
            "ec2:DescribeVolumes",
            "ec2:DescribeSnapshots",
            "ec2:DescribeSnapshotAttribute",
            
            # VPC and Networking
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "ec2:DescribeFlowLogs",
            "ec2:DescribeRegions",
            "ec2:DescribeAvailabilityZones",
            
            # Network ACLs and Route Tables
            "ec2:DescribeNetworkAcls",
            "ec2:DescribeRouteTables",
            "ec2:DescribeNetworkAclAttribute",
            
            # Elastic IPs
            "ec2:DescribeAddresses",
            
            # Key Pairs
            "ec2:DescribeKeyPairs",
            
            # Placement Groups
            "ec2:DescribePlacementGroups",
            
            # For IAM instance profile checks
            "iam:GetInstanceProfile",
            "iam:ListInstanceProfiles",
            
            # For enhanced security checks
            "ec2:DescribeInstanceAttribute",
            "ec2:ModifyInstanceAttribute"
        ],
        scan_function=scan_ec2,
        remediation_map={
            "EC2_INSTANCE_PUBLIC_IP": "remove_public_ip",
            "EC2_IMDS_V2_NOT_ENFORCED": "enforce_imdsv2",
            "EC2_SG_OPEN_TO_WORLD": "restrict_security_group",
            "EC2_SG_OPEN_TO_WORLD_IPV6": "restrict_security_group_ipv6",
            "EC2_EBS_VOLUME_NOT_ENCRYPTED": "encrypt_ebs_volume",
            "EC2_PUBLIC_SNAPSHOT": "remove_snapshot_public_access",
            "EC2_VPC_FLOW_LOGS_DISABLED": "enable_vpc_flow_logs",
            "EC2_DEFAULT_VPC_IN_USE": "migrate_from_default_vpc",
            "EC2_PRODUCTION_TERMINATION_PROTECTION": "enable_termination_protection",
            "EC2_INSTANCE_MISSING_REQUIRED_TAGS": "add_required_tags",
            "EC2_DEFAULT_NACL_OVERLY_PERMISSIVE": "restrict_network_acl",
            "EC2_UNUSED_SECURITY_GROUP": "remove_unused_security_group",
            "EC2_EBS_NO_SNAPSHOTS": "create_snapshot_policy"
        }
    )