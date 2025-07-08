"""
Lambda Environment Analyzer
Analyzes Lambda function environment variables and configurations for security issues.
"""

import logging
from typing import List, Dict

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext
from ..constants import SENSITIVE_ENV_PATTERNS

logger = logging.getLogger(__name__)


async def check_environment_variables(
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
    
    # Check for hardcoded AWS credentials patterns
    aws_cred_patterns = ['AKID', 'aws_access_key_id', 'aws_secret_access_key']
    potential_aws_creds = []
    
    for var_name, var_value in variables.items():
        # Check variable names
        if any(pattern in var_name.lower() for pattern in aws_cred_patterns):
            potential_aws_creds.append(var_name)
        # Check if value looks like AWS access key (starts with AKIA, AKID, etc.)
        elif isinstance(var_value, str) and var_value.startswith(('AKIA', 'AKID', 'ASIS')):
            potential_aws_creds.append(var_name)
    
    if potential_aws_creds:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_HARDCODED_AWS_CREDENTIALS",
            check_title="Lambda Function May Have Hardcoded AWS Credentials",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' may have hardcoded AWS credentials in environment variables",
            recommendation="Use IAM roles instead of hardcoded credentials",
            remediation_available=True,
            context={"suspicious_variables": potential_aws_creds}
        ))
    
    return findings


async def check_dead_letter_queue(
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
    else:
        # Validate DLQ configuration
        if 'sqs' in target_arn:
            dlq_type = 'SQS'
        elif 'sns' in target_arn:
            dlq_type = 'SNS'
        else:
            dlq_type = 'Unknown'
            
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_DLQ_CONFIGURED",
            check_title="Lambda Function Has Dead Letter Queue",
            status=Status.PASS,
            severity=Severity.INFO,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' has {dlq_type} dead letter queue configured",
            context={"dlq_type": dlq_type, "dlq_arn": target_arn}
        ))
    
    return findings


async def check_function_tags(
    lambda_client, function_arn: str, function_name: str, context: AuditContext, region: str
) -> List[Finding]:
    """Check function tags for compliance and governance."""
    findings = []
    
    try:
        tags_response = lambda_client.list_tags(Resource=function_arn)
        tags = tags_response.get('Tags', {})
        
        # Check for required tags
        required_tags = ['Environment', 'Owner', 'Project', 'CostCenter']
        missing_tags = [tag for tag in required_tags if tag not in tags]
        
        if missing_tags:
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_MISSING_REQUIRED_TAGS",
                check_title="Lambda Function Missing Required Tags",
                status=Status.WARNING,
                severity=Severity.LOW,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' is missing required tags: {', '.join(missing_tags)}",
                recommendation="Add missing tags for better governance and cost tracking",
                context={"missing_tags": missing_tags, "existing_tags": list(tags.keys())}
            ))
        
        # Check for sensitive information in tags
        sensitive_tag_patterns = ['password', 'secret', 'key', 'token']
        sensitive_tags = []
        
        for tag_key, tag_value in tags.items():
            tag_key_lower = tag_key.lower()
            if any(pattern in tag_key_lower for pattern in sensitive_tag_patterns):
                sensitive_tags.append(tag_key)
            # Also check tag values
            elif isinstance(tag_value, str) and any(pattern in tag_value.lower() for pattern in sensitive_tag_patterns):
                sensitive_tags.append(f"{tag_key} (value)")
        
        if sensitive_tags:
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_SENSITIVE_TAGS",
                check_title="Lambda Function Has Potentially Sensitive Tags",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' has potentially sensitive information in tags",
                recommendation="Remove sensitive information from tags and use secure storage methods",
                context={"sensitive_tags": sensitive_tags}
            ))
            
    except Exception as e:
        logger.warning(f"Failed to check tags for function {function_name}: {e}")
    
    return findings