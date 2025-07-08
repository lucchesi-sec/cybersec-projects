"""
Lambda Function Analyzer
Analyzes Lambda function configurations, code, and execution roles for security issues.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext
from ..constants import (
    HIGH_RISK_RUNTIMES, EXCESSIVE_TIMEOUT_THRESHOLD, MINIMAL_TIMEOUT_THRESHOLD,
    LOW_MEMORY_THRESHOLD, LARGE_PACKAGE_THRESHOLD
)
from ..utils.lambda_utils import is_aws_managed_policy, is_overprivileged_policy

logger = logging.getLogger(__name__)


async def scan_lambda_functions(lambda_client, context: AuditContext, region: str) -> List[Finding]:
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
                    config_findings = await analyze_function_configuration(
                        function_config, context, region
                    )
                    findings.extend(config_findings)
                    
                    # Analyze function code and environment
                    code_findings = await analyze_function_code_security(
                        lambda_client, function_name, function_config, context, region
                    )
                    findings.extend(code_findings)
                    
                    # Analyze execution role
                    role_findings = await analyze_function_execution_role(
                        function_config, context, region
                    )
                    findings.extend(role_findings)
                    
                except ClientError as e:
                    logger.warning(f"Failed to get configuration for function {function_name}: {e}")
                    continue
                    
    except ClientError as e:
        logger.error(f"Failed to list functions in {region}: {e}")
    
    return findings


async def analyze_function_configuration(
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
    if memory_size < LOW_MEMORY_THRESHOLD:
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
    
    return findings


async def analyze_function_code_security(
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
        if code_size > LARGE_PACKAGE_THRESHOLD:
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


async def analyze_function_execution_role(
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
            if is_aws_managed_policy(policy_arn) and is_overprivileged_policy(policy['PolicyName']):
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