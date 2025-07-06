"""
Lambda Security Scanner Plugin
Comprehensive security analysis for AWS Lambda functions, layers, and related resources.
"""

import asyncio
import json
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError
import logging
import base64

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext
from core.plugin import ScannerPlugin


logger = logging.getLogger(__name__)

# High-risk runtime environments that require additional scrutiny
HIGH_RISK_RUNTIMES = ['nodejs8.10', 'python2.7', 'dotnetcore1.0', 'dotnetcore2.0']

# Critical environment variable patterns that might contain secrets
SENSITIVE_ENV_PATTERNS = [
    'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key', 
    'access_key', 'secret_key', 'private_key', 'auth', 'credential',
    'db_password', 'database_password', 'mysql_password', 'postgres_password'
]

# Lambda function timeout limits (in seconds) that indicate potential issues
EXCESSIVE_TIMEOUT_THRESHOLD = 600  # 10 minutes
MINIMAL_TIMEOUT_THRESHOLD = 3     # 3 seconds


async def scan_lambda(context: AuditContext) -> List[Finding]:
    """Main Lambda scanning function."""
    findings = []
    
    try:
        lambda_client = context.get_client('lambda')
        
        # Get all regions for Lambda scanning
        regions = await _get_available_regions(context)
        
        for region in regions:
            logger.info(f"Scanning Lambda resources in region: {region}")
            region_client = context.get_client('lambda', region_name=region)
            
            # Scan Lambda functions
            function_findings = await _scan_lambda_functions(region_client, context, region)
            findings.extend(function_findings)
            
            # Scan Lambda layers
            layer_findings = await _scan_lambda_layers(region_client, context, region)
            findings.extend(layer_findings)
            
            # Scan event source mappings
            esm_findings = await _scan_event_source_mappings(region_client, context, region)
            findings.extend(esm_findings)
            
            # Scan function permissions and policies
            permission_findings = await _scan_function_permissions(region_client, context, region)
            findings.extend(permission_findings)
            
    except Exception as e:
        logger.error(f"Lambda scan failed: {e}")
        
    return findings


async def _get_available_regions(context: AuditContext) -> List[str]:
    """Get list of available regions for Lambda service."""
    try:
        ec2_client = context.get_client('ec2')
        response = ec2_client.describe_regions()
        # Filter to regions where Lambda is available
        lambda_regions = [region['RegionName'] for region in response['Regions']]
        return lambda_regions
    except ClientError as e:
        logger.warning(f"Failed to get regions, using default: {e}")
        return ['us-east-1']  # Fallback to default region


async def _scan_lambda_functions(lambda_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan Lambda functions for security issues."""
    findings = []
    
    try:
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function['FunctionName']
                
                # Get detailed function configuration
                try:
                    function_config = lambda_client.get_function_configuration(
                        FunctionName=function_name
                    )
                    
                    # Analyze function security
                    config_findings = await _analyze_function_configuration(
                        function_config, context, region
                    )
                    findings.extend(config_findings)
                    
                    # Analyze function code and environment
                    code_findings = await _analyze_function_code_security(
                        lambda_client, function_name, function_config, context, region
                    )
                    findings.extend(code_findings)
                    
                    # Analyze VPC configuration
                    vpc_findings = await _analyze_function_vpc_config(
                        function_config, context, region
                    )
                    findings.extend(vpc_findings)
                    
                    # Analyze execution role
                    role_findings = await _analyze_function_execution_role(
                        function_config, context, region
                    )
                    findings.extend(role_findings)
                    
                except ClientError as e:
                    logger.warning(f"Failed to get configuration for function {function_name}: {e}")
                    continue
                    
    except ClientError as e:
        logger.error(f"Failed to list functions in {region}: {e}")
    
    return findings


async def _analyze_function_configuration(
    function_config: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze Lambda function configuration for security issues."""
    findings = []
    function_name = function_config['FunctionName']
    function_arn = function_config['FunctionArn']
    
    # Check for deprecated runtime versions
    runtime = function_config.get('Runtime', '')
    if runtime in HIGH_RISK_RUNTIMES:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_DEPRECATED_RUNTIME",
            check_title="Lambda Function Uses Deprecated Runtime",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' uses deprecated runtime '{runtime}'",
            recommendation="Update to a supported runtime version",
            remediation_available=True,
            context={"current_runtime": runtime}
        ))
    
    # Check timeout configuration
    timeout = function_config.get('Timeout', 3)
    if timeout > EXCESSIVE_TIMEOUT_THRESHOLD:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_EXCESSIVE_TIMEOUT",
            check_title="Lambda Function Has Excessive Timeout",
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' has timeout of {timeout} seconds",
            recommendation="Review timeout setting and reduce if possible to limit resource consumption",
            context={"timeout": timeout, "threshold": EXCESSIVE_TIMEOUT_THRESHOLD}
        ))
    elif timeout < MINIMAL_TIMEOUT_THRESHOLD:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_MINIMAL_TIMEOUT",
            check_title="Lambda Function Has Very Low Timeout",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' has very low timeout of {timeout} seconds",
            recommendation="Ensure timeout is sufficient for function execution",
            context={"timeout": timeout}
        ))
    
    # Check memory allocation (performance and cost optimization)
    memory_size = function_config.get('MemorySize', 128)
    if memory_size < 512:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_LOW_MEMORY_ALLOCATION",
            check_title="Lambda Function Has Low Memory Allocation",
            status=Status.INFO,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' has low memory allocation of {memory_size}MB",
            recommendation="Consider increasing memory for better performance",
            context={"memory_size": memory_size}
        ))
    
    # Check reserved concurrency (if set)
    reserved_concurrency = function_config.get('ReservedConcurrencyExecutions')
    if reserved_concurrency == 0:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_RESERVED_CONCURRENCY_ZERO",
            check_title="Lambda Function Has Zero Reserved Concurrency",
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' has reserved concurrency set to 0",
            recommendation="Review concurrency settings to ensure function can execute when needed",
            context={"reserved_concurrency": reserved_concurrency}
        ))
    
    # Check environment variables for sensitive data
    env_findings = await _check_environment_variables(function_config, context, region)
    findings.extend(env_findings)
    
    # Check dead letter queue configuration
    dlq_findings = await _check_dead_letter_queue(function_config, context, region)
    findings.extend(dlq_findings)
    
    return findings


async def _analyze_function_code_security(
    lambda_client, function_name: str, function_config: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze Lambda function code for security issues."""
    findings = []
    function_arn = function_config['FunctionArn']
    
    try:
        # Get function code information
        function_info = lambda_client.get_function(FunctionName=function_name)
        code_config = function_info.get('Code', {})
        
        # Check if function uses layers
        layers = function_config.get('Layers', [])
        if not layers:
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_NO_LAYERS",
                check_title="Lambda Function Does Not Use Layers",
                status=Status.INFO,
                severity=Severity.LOW,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' does not use any layers",
                recommendation="Consider using layers for shared code and dependencies",
                context={"layers_count": len(layers)}
            ))
        
        # Check function package size
        code_size = function_config.get('CodeSize', 0)
        if code_size > 50 * 1024 * 1024:  # 50MB
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_LARGE_DEPLOYMENT_PACKAGE",
                check_title="Lambda Function Has Large Deployment Package",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' has large deployment package ({code_size / (1024*1024):.1f}MB)",
                recommendation="Optimize package size by removing unnecessary dependencies",
                context={"code_size_mb": code_size / (1024*1024)}
            ))
        
        # Check code repository type and location
        repository_type = code_config.get('RepositoryType')
        if repository_type == 'S3':
            s3_location = code_config.get('Location', '')
            if 's3://' in s3_location.lower():
                # Check if S3 bucket is publicly accessible (this would be a finding in S3 plugin)
                findings.append(Finding(
                    service="lambda",
                    resource_id=function_arn,
                    resource_name=function_name,
                    check_id="LAMBDA_CODE_IN_S3",
                    check_title="Lambda Function Code Stored in S3",
                    status=Status.INFO,
                    severity=Severity.LOW,
                    region=region,
                    account_id=context.account_id,
                    description=f"Lambda function '{function_name}' code is stored in S3",
                    recommendation="Ensure S3 bucket has proper access controls",
                    context={"s3_location": s3_location}
                ))
        
    except ClientError as e:
        logger.warning(f"Failed to get function code info for {function_name}: {e}")
    
    return findings

async def _analyze_function_vpc_config(
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


async def _analyze_function_execution_role(
    function_config: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze Lambda function execution role and permissions."""
    findings = []
    function_name = function_config['FunctionName']
    function_arn = function_config['FunctionArn']
    
    role_arn = function_config.get('Role')
    if not role_arn:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_NO_EXECUTION_ROLE",
            check_title="Lambda Function Missing Execution Role",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' has no execution role",
            recommendation="Assign an appropriate IAM execution role",
            remediation_available=True
        ))
        return findings
    
    # Extract role name from ARN
    role_name = role_arn.split('/')[-1]
    
    # Check if using AWS managed policies (potential over-privileged access)
    try:
        iam_client = context.get_client('iam')
        
        # Get attached policies
        role_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        
        for policy in role_policies.get('AttachedPolicies', []):
            policy_arn = policy['PolicyArn']
            if 'aws:policy' in policy_arn.lower():
                # AWS managed policy
                if 'FullAccess' in policy['PolicyName'] or 'PowerUser' in policy['PolicyName']:
                    findings.append(Finding(
                        service="lambda",
                        resource_id=function_arn,
                        resource_name=function_name,
                        check_id="LAMBDA_OVERPRIVILEGED_ROLE",
                        check_title="Lambda Function Has Over-Privileged Execution Role",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        region=region,
                        account_id=context.account_id,
                        description=f"Lambda function '{function_name}' uses over-privileged policy '{policy['PolicyName']}'",
                        recommendation="Replace with a custom policy following principle of least privilege",
                        context={"overprivileged_policy": policy['PolicyName']}
                    ))
        
        # Check for inline policies
        inline_policies = iam_client.list_role_policies(RoleName=role_name)
        
        if inline_policies.get('PolicyNames'):
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_INLINE_POLICIES",
                check_title="Lambda Function Role Has Inline Policies",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' execution role has {len(inline_policies['PolicyNames'])} inline policies",
                recommendation="Convert inline policies to managed policies for better governance",
                context={"inline_policy_count": len(inline_policies['PolicyNames'])}
            ))
        
    except ClientError as e:
        logger.warning(f"Failed to analyze IAM role {role_name}: {e}")
    
    return findings


async def _check_environment_variables(
    function_config: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Check environment variables for sensitive data exposure."""
    findings = []
    function_name = function_config['FunctionName']
    function_arn = function_config['FunctionArn']
    
    environment = function_config.get('Environment', {})
    variables = environment.get('Variables', {})
    
    if not variables:
        return findings
    
    # Check for potentially sensitive variable names
    sensitive_vars = []
    for var_name in variables.keys():
        var_name_lower = var_name.lower()
        for pattern in SENSITIVE_ENV_PATTERNS:
            if pattern in var_name_lower:
                sensitive_vars.append(var_name)
                break
    
    if sensitive_vars:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_SENSITIVE_ENV_VARS",
            check_title="Lambda Function May Have Sensitive Data in Environment Variables",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' has potentially sensitive environment variables",
            recommendation="Use AWS Systems Manager Parameter Store or Secrets Manager for sensitive data",
            remediation_available=True,
            context={"sensitive_variables": sensitive_vars}
        ))
    
    # Check for encryption of environment variables
    kms_key_arn = environment.get('KMSKeyArn')
    if variables and not kms_key_arn:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_ENV_VARS_NOT_ENCRYPTED",
            check_title="Lambda Function Environment Variables Not Encrypted",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' environment variables are not encrypted with KMS",
            recommendation="Enable KMS encryption for environment variables",
            remediation_available=True,
            context={"variable_count": len(variables)}
        ))
    
    return findings


async def _check_dead_letter_queue(
    function_config: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Check dead letter queue configuration."""
    findings = []
    function_name = function_config['FunctionName']
    function_arn = function_config['FunctionArn']
    
    dlq_config = function_config.get('DeadLetterConfig', {})
    target_arn = dlq_config.get('TargetArn')
    
    if not target_arn:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_NO_DLQ",
            check_title="Lambda Function Missing Dead Letter Queue",
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' does not have a dead letter queue configured",
            recommendation="Configure a dead letter queue for failed executions",
            remediation_available=True,
            context={"dlq_configured": False}
        ))
    
    return findings


async def _scan_lambda_layers(lambda_client, context: AuditContext, region: str) -> List[Finding]:
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
                        layer_findings = await _analyze_layer_version(
                            lambda_client, layer_name, version, context, region
                        )
                        findings.extend(layer_findings)
                        
                except ClientError as e:
                    logger.warning(f"Failed to get versions for layer {layer_name}: {e}")
                    continue
                    
    except ClientError as e:
        logger.error(f"Failed to list layers in {region}: {e}")
    
    return findings


async def _analyze_layer_version(
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
        
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            logger.warning(f"Failed to get layer policy for {layer_name}:{version_number}: {e}")
    
    # Check if layer is outdated (compare with latest version)
    creation_date = version.get('CreatedDate', '')
    # Note: In a real implementation, you'd check against current date
    # and flag layers that are very old
    
    return findings
async def _scan_event_source_mappings(lambda_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan Lambda event source mappings for security issues."""
    findings = []
    
    try:
        paginator = lambda_client.get_paginator('list_event_source_mappings')
        
        for page in paginator.paginate():
            for mapping in page['EventSourceMappings']:
                mapping_findings = await _analyze_event_source_mapping(
                    mapping, context, region
                )
                findings.extend(mapping_findings)
                
    except ClientError as e:
        logger.error(f"Failed to list event source mappings in {region}: {e}")
    
    return findings


async def _analyze_event_source_mapping(
    mapping: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze event source mapping for security issues."""
    findings = []
    uuid = mapping['UUID']
    function_arn = mapping.get('FunctionArn', '')
    event_source_arn = mapping.get('EventSourceArn', '')
    
    # Extract function name from ARN
    function_name = function_arn.split(':')[-1] if function_arn else 'Unknown'
    
    # Check if mapping is enabled but function doesn't exist
    state = mapping.get('State', '')
    if state == 'Enabled' and not function_arn:
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_ORPHANED",
            check_title="Event Source Mapping References Missing Function",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"Event source mapping {uuid} is enabled but references missing function",
            recommendation="Remove orphaned event source mapping or fix function reference",
            remediation_available=True,
            context={"mapping_uuid": uuid, "state": state}
        ))
    
    # Check batch size for performance and cost optimization
    batch_size = mapping.get('BatchSize', 1)
    if batch_size == 1 and 'kinesis' in event_source_arn.lower():
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_INEFFICIENT_BATCH_SIZE",
            check_title="Event Source Mapping Has Inefficient Batch Size",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Kinesis event source mapping has batch size of 1, which may be inefficient",
            recommendation="Consider increasing batch size for better performance and cost optimization",
            context={"batch_size": batch_size, "event_source": event_source_arn}
        ))
    
    # Check for DLQ configuration on event source mapping
    failure_destination = mapping.get('DestinationConfig', {}).get('OnFailure', {})
    if not failure_destination and state == 'Enabled':
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_NO_FAILURE_DESTINATION",
            check_title="Event Source Mapping Missing Failure Destination",
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"Event source mapping for function '{function_name}' has no failure destination",
            recommendation="Configure failure destination for better error handling",
            context={"function_name": function_name}
        ))
    
    return findings


async def _scan_function_permissions(lambda_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan Lambda function permissions and policies."""
    findings = []
    
    try:
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function['FunctionName']
                
                try:
                    # Get function policy
                    policy_response = lambda_client.get_policy(FunctionName=function_name)
                    policy = json.loads(policy_response['Policy'])
                    
                    permission_findings = await _analyze_function_policy(
                        function_name, policy, context, region
                    )
                    findings.extend(permission_findings)
                    
                except ClientError as e:
                    if e.response['Error']['Code'] != 'ResourceNotFoundException':
                        logger.warning(f"Failed to get policy for function {function_name}: {e}")
                
    except ClientError as e:
        logger.error(f"Failed to analyze function permissions in {region}: {e}")
    
    return findings


async def _analyze_function_policy(
    function_name: str, policy: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze Lambda function resource-based policy."""
    findings = []
    function_arn = f"arn:aws:lambda:{region}:{context.account_id}:function:{function_name}"
    
    for statement in policy.get('Statement', []):
        effect = statement.get('Effect', 'Deny')
        principal = statement.get('Principal', {})
        action = statement.get('Action', [])
        
        if effect == 'Allow':
            # Check for overly permissive principals
            if principal == '*':
                findings.append(Finding(
                    service="lambda",
                    resource_id=function_arn,
                    resource_name=function_name,
                    check_id="LAMBDA_FUNCTION_PUBLIC_ACCESS",
                    check_title="Lambda Function Allows Public Access",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    region=region,
                    account_id=context.account_id,
                    description=f"Lambda function '{function_name}' allows public access",
                    recommendation="Restrict function access to specific principals",
                    remediation_available=True,
                    context={"policy_statement": statement}
                ))
            
            # Check for overly broad actions
            if isinstance(action, list):
                actions = action
            else:
                actions = [action]
            
            for act in actions:
                if act == 'lambda:*':
                    findings.append(Finding(
                        service="lambda",
                        resource_id=function_arn,
                        resource_name=function_name,
                        check_id="LAMBDA_FUNCTION_WILDCARD_ACTIONS",
                        check_title="Lambda Function Policy Uses Wildcard Actions",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        region=region,
                        account_id=context.account_id,
                        description=f"Lambda function '{function_name}' policy uses wildcard actions",
                        recommendation="Specify specific actions instead of using wildcards",
                        context={"actions": actions}
                    ))
    
    return findings


# Helper functions for monitoring and alerting checks

async def _check_function_monitoring(
    lambda_client, function_name: str, context: AuditContext, region: str
) -> List[Finding]:
    """Check if function has proper monitoring and alerting configured."""
    findings = []
    function_arn = f"arn:aws:lambda:{region}:{context.account_id}:function:{function_name}"
    
    try:
        # Check CloudWatch Logs configuration
        # Note: This would require CloudWatch Logs client to check log group retention
        
        # Check if X-Ray tracing is enabled
        tracing_response = lambda_client.get_function_configuration(FunctionName=function_name)
        tracing_config = tracing_response.get('TracingConfig', {})
        
        if tracing_config.get('Mode') != 'Active':
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_XRAY_TRACING_DISABLED",
                check_title="Lambda Function X-Ray Tracing Disabled",
                status=Status.WARNING,
                severity=Severity.LOW,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' does not have X-Ray tracing enabled",
                recommendation="Enable X-Ray tracing for better observability",
                remediation_available=True,
                context={"tracing_mode": tracing_config.get('Mode', 'PassThrough')}
            ))
        
    except ClientError as e:
        logger.warning(f"Failed to check monitoring for function {function_name}: {e}")
    
    return findings


def register() -> ScannerPlugin:
    """Register Lambda scanner plugin."""
    return ScannerPlugin(
        service="lambda",
        required_permissions=[
            # Lambda Functions
            "lambda:ListFunctions",
            "lambda:GetFunction",
            "lambda:GetFunctionConfiguration",
            "lambda:GetPolicy",
            "lambda:ListVersionsByFunction",
            "lambda:ListAliases",
            
            # Lambda Layers
            "lambda:ListLayers",
            "lambda:ListLayerVersions",
            "lambda:GetLayerVersion",
            "lambda:GetLayerVersionPolicy",
            
            # Event Source Mappings
            "lambda:ListEventSourceMappings",
            "lambda:GetEventSourceMapping",
            
            # For analyzing execution roles
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:GetRolePolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            
            # For VPC analysis
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeRegions",
            
            # For monitoring checks
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams",
            
            # For CloudWatch metrics
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:ListMetrics",
            
            # For X-Ray tracing
            "xray:GetTracingSummaries",
            "xray:BatchGetTraces"
        ],
        scan_function=scan_lambda,
        remediation_map={
            "LAMBDA_DEPRECATED_RUNTIME": "update_runtime",
            "LAMBDA_SENSITIVE_ENV_VARS": "migrate_to_secrets_manager",
            "LAMBDA_ENV_VARS_NOT_ENCRYPTED": "enable_env_var_encryption",
            "LAMBDA_NO_DLQ": "configure_dead_letter_queue",
            "LAMBDA_VPC_NO_SUBNETS": "configure_vpc_subnets",
            "LAMBDA_NO_EXECUTION_ROLE": "create_execution_role",
            "LAMBDA_OVERPRIVILEGED_ROLE": "reduce_role_permissions",
            "LAMBDA_LAYER_PUBLIC_ACCESS": "restrict_layer_access",
            "LAMBDA_FUNCTION_PUBLIC_ACCESS": "restrict_function_access",
            "LAMBDA_FUNCTION_WILDCARD_ACTIONS": "specify_precise_actions",
            "LAMBDA_ESM_ORPHANED": "remove_orphaned_mapping",
            "LAMBDA_XRAY_TRACING_DISABLED": "enable_xray_tracing"
        }
    )