"""
Lambda Layer Analyzer
Analyzes Lambda layers for security and permission issues.
"""

import json
import logging
from typing import List, Dict
from botocore.exceptions import ClientError

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext

logger = logging.getLogger(__name__)


async def scan_lambda_layers(lambda_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan Lambda layers for security issues."""
    findings = []
    
    try:
        paginator = lambda_client.get_paginator('list_layers')
        
        for page in paginator.paginate():
            for layer in page['Layers']:
                layer_name = layer['LayerName']
                
                # Get layer versions
                try:
                    versions_response = lambda_client.list_layer_versions(
                        LayerName=layer_name
                    )
                    
                    for version in versions_response.get('LayerVersions', []):
                        layer_findings = await analyze_layer_version(
                            lambda_client, layer_name, version, context, region
                        )
                        findings.extend(layer_findings)
                        
                except ClientError as e:
                    logger.warning(f"Failed to get versions for layer {layer_name}: {e}")
                    continue
                    
    except ClientError as e:
        logger.error(f"Failed to list layers in {region}: {e}")
    
    return findings


async def analyze_layer_version(
    lambda_client, layer_name: str, version: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze a specific layer version for security issues."""
    findings = []
    layer_arn = version['LayerVersionArn']
    version_number = version['Version']
    
    # Check layer permissions
    try:
        policy_response = lambda_client.get_layer_version_policy(
            LayerName=layer_name,
            VersionNumber=version_number
        )
        
        policy = json.loads(policy_response['Policy'])
        
        # Check for overly permissive layer policies
        for statement in policy.get('Statement', []):
            principal = statement.get('Principal', {})
            
            # Check for public access
            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                findings.append(Finding(
                    service="lambda",
                    resource_id=layer_arn,
                    resource_name=f"{layer_name}:{version_number}",
                    check_id="LAMBDA_LAYER_PUBLIC_ACCESS",
                    check_title="Lambda Layer Allows Public Access",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    region=region,
                    account_id=context.account_id,
                    description=f"Lambda layer '{layer_name}' version {version_number} allows public access",
                    recommendation="Restrict layer access to specific accounts or remove public access",
                    remediation_available=True,
                    context={"policy_statement": statement}
                ))
            
            # Check for cross-account access
            elif isinstance(principal, dict):
                aws_principals = principal.get('AWS', [])
                if not isinstance(aws_principals, list):
                    aws_principals = [aws_principals]
                
                external_accounts = []
                for p in aws_principals:
                    if isinstance(p, str) and ':' in p:
                        # Extract account ID from ARN
                        account_id_from_arn = p.split(':')[4]
                        if account_id_from_arn != context.account_id:
                            external_accounts.append(account_id_from_arn)
                
                if external_accounts:
                    findings.append(Finding(
                        service="lambda",
                        resource_id=layer_arn,
                        resource_name=f"{layer_name}:{version_number}",
                        check_id="LAMBDA_LAYER_CROSS_ACCOUNT_ACCESS",
                        check_title="Lambda Layer Allows Cross-Account Access",
                        status=Status.WARNING,
                        severity=Severity.MEDIUM,
                        region=region,
                        account_id=context.account_id,
                        description=f"Lambda layer '{layer_name}' version {version_number} is shared with external accounts",
                        recommendation="Review cross-account access and ensure it's intentional",
                        context={"external_accounts": external_accounts}
                    ))
        
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            logger.warning(f"Failed to get layer policy for {layer_name}:{version_number}: {e}")
    
    # Check layer metadata
    layer_metadata_findings = await _analyze_layer_metadata(
        layer_name, version, context, region
    )
    findings.extend(layer_metadata_findings)
    
    return findings


async def _analyze_layer_metadata(
    layer_name: str, version: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze layer metadata for security and best practice issues."""
    findings = []
    layer_arn = version['LayerVersionArn']
    version_number = version['Version']
    
    # Check compatible runtimes
    compatible_runtimes = version.get('CompatibleRuntimes', [])
    if not compatible_runtimes:
        findings.append(Finding(
            service="lambda",
            resource_id=layer_arn,
            resource_name=f"{layer_name}:{version_number}",
            check_id="LAMBDA_LAYER_NO_COMPATIBLE_RUNTIMES",
            check_title="Lambda Layer Has No Compatible Runtimes Specified",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Lambda layer '{layer_name}' version {version_number} has no compatible runtimes specified",
            recommendation="Specify compatible runtimes for better compatibility checking",
            context={"version": version_number}
        ))
    else:
        # Check for deprecated runtimes
        from ..constants import HIGH_RISK_RUNTIMES
        deprecated_runtimes = [r for r in compatible_runtimes if r in HIGH_RISK_RUNTIMES]
        if deprecated_runtimes:
            findings.append(Finding(
                service="lambda",
                resource_id=layer_arn,
                resource_name=f"{layer_name}:{version_number}",
                check_id="LAMBDA_LAYER_DEPRECATED_RUNTIME_SUPPORT",
                check_title="Lambda Layer Supports Deprecated Runtimes",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Lambda layer '{layer_name}' supports deprecated runtimes: {', '.join(deprecated_runtimes)}",
                recommendation="Remove support for deprecated runtimes and update to supported versions",
                context={"deprecated_runtimes": deprecated_runtimes}
            ))
    
    # Check layer age (if creation date is available)
    creation_date = version.get('CreatedDate', '')
    if creation_date:
        # Convert to datetime and check age
        from datetime import datetime, timezone
        import dateutil.parser
        
        try:
            created_dt = dateutil.parser.parse(creation_date)
            age_days = (datetime.now(timezone.utc) - created_dt).days
            
            if age_days > 365:  # Layer is over a year old
                findings.append(Finding(
                    service="lambda",
                    resource_id=layer_arn,
                    resource_name=f"{layer_name}:{version_number}",
                    check_id="LAMBDA_LAYER_OUTDATED",
                    check_title="Lambda Layer Version is Outdated",
                    status=Status.WARNING,
                    severity=Severity.LOW,
                    region=region,
                    account_id=context.account_id,
                    description=f"Lambda layer '{layer_name}' version {version_number} is {age_days} days old",
                    recommendation="Consider updating layer with latest dependencies and security patches",
                    context={"age_days": age_days, "created_date": creation_date}
                ))
        except Exception as e:
            logger.warning(f"Failed to parse layer creation date: {e}")
    
    # Check license info
    license_info = version.get('LicenseInfo')
    if not license_info:
        findings.append(Finding(
            service="lambda",
            resource_id=layer_arn,
            resource_name=f"{layer_name}:{version_number}",
            check_id="LAMBDA_LAYER_NO_LICENSE_INFO",
            check_title="Lambda Layer Missing License Information",
            status=Status.INFO,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Lambda layer '{layer_name}' version {version_number} has no license information",
            recommendation="Add license information for better compliance tracking",
            context={"version": version_number}
        ))
    
    return findings