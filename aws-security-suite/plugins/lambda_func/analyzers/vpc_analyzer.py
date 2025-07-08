"""
Lambda VPC Analyzer
Analyzes Lambda function VPC configurations for security and availability issues.
"""

import logging
from typing import List, Dict

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext

logger = logging.getLogger(__name__)


async def analyze_function_vpc_config(
    function_config: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze Lambda function VPC configuration."""
    findings = []
    function_name = function_config['FunctionName']
    function_arn = function_config['FunctionArn']
    
    vpc_config = function_config.get('VpcConfig', {})
    
    if vpc_config:
        # Function is VPC-enabled
        subnet_ids = vpc_config.get('SubnetIds', [])
        security_group_ids = vpc_config.get('SecurityGroupIds', [])
        
        if not subnet_ids:
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_VPC_NO_SUBNETS",
                check_title="Lambda Function VPC Configuration Missing Subnets",
                status=Status.FAIL,
                severity=Severity.HIGH,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' VPC config has no subnets",
                recommendation="Configure appropriate subnets for VPC access",
                remediation_available=True
            ))
        
        if not security_group_ids:
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_VPC_NO_SECURITY_GROUPS",
                check_title="Lambda Function VPC Configuration Missing Security Groups",
                status=Status.FAIL,
                severity=Severity.HIGH,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' VPC config has no security groups",
                recommendation="Configure appropriate security groups for network access control"
            ))
        
        # Check for multiple AZs (redundancy)
        if len(subnet_ids) < 2:
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_VPC_SINGLE_AZ",
                check_title="Lambda Function Only in Single Availability Zone",
                status=Status.WARNING,
                severity=Severity.LOW,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' only configured in {len(subnet_ids)} subnet(s)",
                recommendation="Configure subnets across multiple AZs for high availability",
                context={"subnet_count": len(subnet_ids)}
            ))
        
        # Additional VPC checks
        if subnet_ids and security_group_ids:
            vpc_findings = await _analyze_vpc_details(
                function_name, function_arn, subnet_ids, security_group_ids, context, region
            )
            findings.extend(vpc_findings)
    else:
        # Function is not VPC-enabled, check if it should be
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_NOT_IN_VPC",
            check_title="Lambda Function Not in VPC",
            status=Status.INFO,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' is not configured to run in a VPC",
            recommendation="Consider VPC configuration if function needs to access VPC resources",
            context={"vpc_enabled": False}
        ))
    
    return findings


async def _analyze_vpc_details(
    function_name: str, function_arn: str, subnet_ids: List[str], 
    security_group_ids: List[str], context: AuditContext, region: str
) -> List[Finding]:
    """Analyze detailed VPC configuration including subnets and security groups."""
    findings = []
    
    try:
        ec2_client = context.get_client('ec2', region_name=region)
        
        # Analyze subnets
        if subnet_ids:
            subnet_findings = await _analyze_subnets(
                ec2_client, function_name, function_arn, subnet_ids, context, region
            )
            findings.extend(subnet_findings)
        
        # Analyze security groups
        if security_group_ids:
            sg_findings = await _analyze_security_groups(
                ec2_client, function_name, function_arn, security_group_ids, context, region
            )
            findings.extend(sg_findings)
            
    except Exception as e:
        logger.warning(f"Failed to analyze VPC details for function {function_name}: {e}")
    
    return findings


async def _analyze_subnets(
    ec2_client, function_name: str, function_arn: str, 
    subnet_ids: List[str], context: AuditContext, region: str
) -> List[Finding]:
    """Analyze subnet configuration for Lambda function."""
    findings = []
    
    try:
        subnets_response = ec2_client.describe_subnets(SubnetIds=subnet_ids)
        subnets = subnets_response.get('Subnets', [])
        
        # Check subnet types and availability zones
        availability_zones = set()
        public_subnets = []
        private_subnets = []
        
        for subnet in subnets:
            availability_zones.add(subnet['AvailabilityZone'])
            
            # Check if subnet is public (has route to IGW)
            # This is a simplified check - in reality would need to check route tables
            map_public_ip = subnet.get('MapPublicIpOnLaunch', False)
            if map_public_ip:
                public_subnets.append(subnet['SubnetId'])
            else:
                private_subnets.append(subnet['SubnetId'])
        
        # Lambda functions should typically be in private subnets
        if public_subnets:
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_IN_PUBLIC_SUBNET",
                check_title="Lambda Function Configured in Public Subnet",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' is configured to use public subnet(s)",
                recommendation="Use private subnets for Lambda functions unless public access is required",
                context={"public_subnets": public_subnets}
            ))
        
        # Check for multi-AZ configuration
        if len(availability_zones) == 1:
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_SINGLE_AZ_SUBNETS",
                check_title="Lambda Function Subnets in Single AZ",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' subnets are all in single AZ: {list(availability_zones)[0]}",
                recommendation="Configure subnets across multiple availability zones for high availability",
                context={"availability_zones": list(availability_zones)}
            ))
            
    except Exception as e:
        logger.warning(f"Failed to analyze subnets for function {function_name}: {e}")
    
    return findings


async def _analyze_security_groups(
    ec2_client, function_name: str, function_arn: str, 
    security_group_ids: List[str], context: AuditContext, region: str
) -> List[Finding]:
    """Analyze security group configuration for Lambda function."""
    findings = []
    
    try:
        sg_response = ec2_client.describe_security_groups(GroupIds=security_group_ids)
        security_groups = sg_response.get('SecurityGroups', [])
        
        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', 'Unknown')
            
            # Check for overly permissive egress rules
            egress_rules = sg.get('IpPermissionsEgress', [])
            for rule in egress_rules:
                # Check for unrestricted outbound (0.0.0.0/0)
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # This is common for Lambda but worth noting
                        if rule.get('IpProtocol') == '-1':  # All protocols
                            findings.append(Finding(
                                service="lambda",
                                resource_id=function_arn,
                                resource_name=function_name,
                                check_id="LAMBDA_UNRESTRICTED_OUTBOUND",
                                check_title="Lambda Function Has Unrestricted Outbound Access",
                                status=Status.INFO,
                                severity=Severity.LOW,
                                region=region,
                                account_id=context.account_id,
                                description=f"Lambda function '{function_name}' security group allows unrestricted outbound access",
                                recommendation="Consider restricting outbound access to specific destinations if possible",
                                context={"security_group": sg_id, "security_group_name": sg_name}
                            ))
            
            # Check for ingress rules (Lambda doesn't need ingress)
            ingress_rules = sg.get('IpPermissions', [])
            if ingress_rules:
                findings.append(Finding(
                    service="lambda",
                    resource_id=function_arn,
                    resource_name=function_name,
                    check_id="LAMBDA_UNNECESSARY_INGRESS_RULES",
                    check_title="Lambda Function Security Group Has Ingress Rules",
                    status=Status.WARNING,
                    severity=Severity.MEDIUM,
                    region=region,
                    account_id=context.account_id,
                    description=f"Lambda function '{function_name}' security group has unnecessary ingress rules",
                    recommendation="Remove ingress rules as Lambda functions don't accept inbound connections",
                    context={
                        "security_group": sg_id,
                        "security_group_name": sg_name,
                        "ingress_rule_count": len(ingress_rules)
                    }
                ))
                
    except Exception as e:
        logger.warning(f"Failed to analyze security groups for function {function_name}: {e}")
    
    return findings