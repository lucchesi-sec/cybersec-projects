"""
Lambda Permission Analyzer
Analyzes Lambda function permissions, policies, and resource-based access controls.
"""

import json
import logging
from typing import List, Dict
from botocore.exceptions import ClientError

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext

logger = logging.getLogger(__name__)


async def scan_function_permissions(lambda_client, context: AuditContext, region: str) -> List[Finding]:
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
                    
                    permission_findings = await analyze_function_policy(
                        function_name, policy, context, region
                    )
                    findings.extend(permission_findings)
                    
                except ClientError as e:
                    if e.response['Error']['Code'] != 'ResourceNotFoundException':
                        logger.warning(f"Failed to get policy for function {function_name}: {e}")
                
    except ClientError as e:
        logger.error(f"Failed to analyze function permissions in {region}: {e}")
    
    return findings


async def analyze_function_policy(
    function_name: str, policy: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze Lambda function resource-based policy."""
    findings = []
    function_arn = f"arn:aws:lambda:{region}:{context.account_id}:function:{function_name}"
    
    for statement in policy.get('Statement', []):
        effect = statement.get('Effect', 'Deny')
        principal = statement.get('Principal', {})
        action = statement.get('Action', [])
        condition = statement.get('Condition', {})
        
        if effect == 'Allow':
            # Analyze principals
            principal_findings = await _analyze_policy_principals(
                function_name, function_arn, statement, principal, context, region
            )
            findings.extend(principal_findings)
            
            # Analyze actions
            action_findings = await _analyze_policy_actions(
                function_name, function_arn, statement, action, context, region
            )
            findings.extend(action_findings)
            
            # Analyze conditions
            condition_findings = await _analyze_policy_conditions(
                function_name, function_arn, statement, condition, context, region
            )
            findings.extend(condition_findings)
    
    return findings


async def _analyze_policy_principals(
    function_name: str, function_arn: str, statement: Dict, 
    principal: Any, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze policy principals for security issues."""
    findings = []
    
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
    elif isinstance(principal, dict):
        # Check AWS principals
        aws_principals = principal.get('AWS', [])
        if not isinstance(aws_principals, list):
            aws_principals = [aws_principals] if aws_principals else []
        
        for p in aws_principals:
            if p == '*':
                findings.append(Finding(
                    service="lambda",
                    resource_id=function_arn,
                    resource_name=function_name,
                    check_id="LAMBDA_FUNCTION_WILDCARD_AWS_PRINCIPAL",
                    check_title="Lambda Function Allows Any AWS Principal",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    region=region,
                    account_id=context.account_id,
                    description=f"Lambda function '{function_name}' allows any AWS principal",
                    recommendation="Specify exact AWS principals instead of wildcards",
                    context={"statement_id": statement.get('Sid', 'Unknown')}
                ))
            elif isinstance(p, str) and ':root' in p:
                # Check if it's external account root
                account_id_from_arn = p.split(':')[4]
                if account_id_from_arn != context.account_id:
                    findings.append(Finding(
                        service="lambda",
                        resource_id=function_arn,
                        resource_name=function_name,
                        check_id="LAMBDA_FUNCTION_EXTERNAL_ROOT_ACCESS",
                        check_title="Lambda Function Allows External Account Root Access",
                        status=Status.WARNING,
                        severity=Severity.MEDIUM,
                        region=region,
                        account_id=context.account_id,
                        description=f"Lambda function '{function_name}' allows root access from external account {account_id_from_arn}",
                        recommendation="Use specific IAM principals instead of account root",
                        context={"external_account": account_id_from_arn}
                    ))
        
        # Check Service principals
        service_principals = principal.get('Service', [])
        if not isinstance(service_principals, list):
            service_principals = [service_principals] if service_principals else []
        
        # Check for unusual service principals
        common_services = [
            'apigateway.amazonaws.com', 's3.amazonaws.com', 'events.amazonaws.com',
            'sns.amazonaws.com', 'sqs.amazonaws.com', 'cognito-idp.amazonaws.com',
            'lex.amazonaws.com', 'alexa-appkit.amazon.com', 'iot.amazonaws.com'
        ]
        
        for service in service_principals:
            if service not in common_services and not service.endswith('.amazonaws.com'):
                findings.append(Finding(
                    service="lambda",
                    resource_id=function_arn,
                    resource_name=function_name,
                    check_id="LAMBDA_FUNCTION_UNUSUAL_SERVICE_PRINCIPAL",
                    check_title="Lambda Function Has Unusual Service Principal",
                    status=Status.WARNING,
                    severity=Severity.LOW,
                    region=region,
                    account_id=context.account_id,
                    description=f"Lambda function '{function_name}' allows access from unusual service: {service}",
                    recommendation="Verify if this service principal is intended",
                    context={"service_principal": service}
                ))
    
    return findings


async def _analyze_policy_actions(
    function_name: str, function_arn: str, statement: Dict, 
    action: Any, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze policy actions for security issues."""
    findings = []
    
    # Normalize actions to list
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
        elif act == 'lambda:InvokeFunction':
            # This is normal, but check if combined with permissive principals
            principal = statement.get('Principal', {})
            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                findings.append(Finding(
                    service="lambda",
                    resource_id=function_arn,
                    resource_name=function_name,
                    check_id="LAMBDA_FUNCTION_PUBLIC_INVOKE",
                    check_title="Lambda Function Allows Public Invocation",
                    status=Status.FAIL,
                    severity=Severity.CRITICAL,
                    region=region,
                    account_id=context.account_id,
                    description=f"Lambda function '{function_name}' can be invoked by anyone",
                    recommendation="Restrict invoke permissions to specific principals",
                    remediation_available=True,
                    context={"statement_id": statement.get('Sid', 'Unknown')}
                ))
    
    # Check for dangerous action combinations
    dangerous_actions = ['lambda:UpdateFunctionCode', 'lambda:UpdateFunctionConfiguration', 
                        'lambda:DeleteFunction', 'lambda:PutFunctionConcurrency']
    
    found_dangerous = [act for act in actions if act in dangerous_actions]
    if found_dangerous:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_FUNCTION_DANGEROUS_PERMISSIONS",
            check_title="Lambda Function Policy Grants Dangerous Permissions",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' policy grants dangerous permissions: {', '.join(found_dangerous)}",
            recommendation="Remove or restrict dangerous permissions to trusted principals only",
            context={"dangerous_actions": found_dangerous}
        ))
    
    return findings


async def _analyze_policy_conditions(
    function_name: str, function_arn: str, statement: Dict, 
    condition: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze policy conditions for security issues."""
    findings = []
    
    if not condition:
        # No conditions on an Allow statement might be too permissive
        principal = statement.get('Principal', {})
        if principal == '*' or (isinstance(principal, dict) and '*' in str(principal)):
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_FUNCTION_NO_CONDITIONS",
                check_title="Lambda Function Policy Has No Conditions",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' has permissive policy with no conditions",
                recommendation="Add conditions to restrict access (e.g., IP restrictions, MFA requirements)",
                context={"statement_id": statement.get('Sid', 'Unknown')}
            ))
    else:
        # Check for weak conditions
        for condition_type, condition_values in condition.items():
            if condition_type == 'IpAddress':
                # Check if IP range is too broad
                for key, values in condition_values.items():
                    if not isinstance(values, list):
                        values = [values]
                    
                    for ip_range in values:
                        if ip_range == '0.0.0.0/0' or ip_range == '::/0':
                            findings.append(Finding(
                                service="lambda",
                                resource_id=function_arn,
                                resource_name=function_name,
                                check_id="LAMBDA_FUNCTION_BROAD_IP_CONDITION",
                                check_title="Lambda Function Policy Has Overly Broad IP Condition",
                                status=Status.WARNING,
                                severity=Severity.LOW,
                                region=region,
                                account_id=context.account_id,
                                description=f"Lambda function '{function_name}' has IP condition that allows all IPs",
                                recommendation="Restrict to specific IP ranges",
                                context={"ip_condition": ip_range}
                            ))
    
    return findings