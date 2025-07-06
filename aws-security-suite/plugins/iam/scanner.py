"""
IAM Security Scanner Plugin
Migrated from cloud-iam-analyzer/iam_analyzer.py
"""

import asyncio
import json
import re
from typing import List, Dict, Any
from botocore.exceptions import ClientError
import logging

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext
from core.plugin import ScannerPlugin


logger = logging.getLogger(__name__)

# High-risk actions that should be flagged
HIGH_RISK_ACTIONS = [
    "iam:*",
    "sts:AssumeRole",
    "*:*",
    "s3:*",
    "ec2:*",
    "lambda:*"
]

# Administrative permissions patterns
ADMIN_PATTERNS = [
    r".*:.*\*",  # Any wildcard action
    r"\*:\*",    # Full wildcard
    r"iam:.*",   # IAM permissions
]


async def scan_iam(context: AuditContext) -> List[Finding]:
    """Main IAM scanning function."""
    findings = []
    
    try:
        iam_client = context.get_client('iam')
        
        # Scan IAM policies
        policy_findings = await _scan_iam_policies(iam_client, context)
        findings.extend(policy_findings)
        
        # Scan IAM users
        user_findings = await _scan_iam_users(iam_client, context)
        findings.extend(user_findings)
        
        # Scan IAM roles
        role_findings = await _scan_iam_roles(iam_client, context)
        findings.extend(role_findings)
        
    except Exception as e:
        logger.error(f"IAM scan failed: {e}")
        
    return findings


async def _scan_iam_policies(iam_client, context: AuditContext) -> List[Finding]:
    """Scan IAM policies for security issues."""
    findings = []
    
    try:
        # Get customer managed policies
        paginator = iam_client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for policy in page['Policies']:
                policy_findings = await _analyze_policy(iam_client, policy, context)
                findings.extend(policy_findings)
                
    except ClientError as e:
        logger.error(f"Failed to list IAM policies: {e}")
    
    return findings


async def _analyze_policy(iam_client, policy: Dict, context: AuditContext) -> List[Finding]:
    """Analyze a single IAM policy for security issues."""
    findings = []
    
    try:
        # Get policy document
        response = iam_client.get_policy_version(
            PolicyArn=policy['Arn'],
            VersionId=policy['DefaultVersionId']
        )
        
        policy_doc = response['PolicyVersion']['Document']
        
        # Check for overly permissive policies
        if _is_overly_permissive(policy_doc):
            findings.append(Finding(
                service="iam",
                resource_id=policy['Arn'],
                resource_name=policy['PolicyName'],
                check_id="IAM_OVERLY_PERMISSIVE_POLICY",
                check_title="IAM Policy Too Permissive",
                status=Status.FAIL,
                severity=Severity.HIGH,
                region=context.region,
                account_id=context.account_id,
                description=f"IAM policy '{policy['PolicyName']}' contains overly broad permissions",
                recommendation="Review and restrict policy permissions to minimum required",
                context={"policy_document": policy_doc}
            ))
        
        # Check for wildcard actions
        if _has_wildcard_actions(policy_doc):
            findings.append(Finding(
                service="iam",
                resource_id=policy['Arn'],
                resource_name=policy['PolicyName'],
                check_id="IAM_WILDCARD_ACTIONS",
                check_title="IAM Policy Uses Wildcard Actions",
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                region=context.region,
                account_id=context.account_id,
                description=f"IAM policy '{policy['PolicyName']}' uses wildcard actions",
                recommendation="Replace wildcards with specific actions"
            ))
            
    except Exception as e:
        logger.warning(f"Failed to analyze policy {policy['PolicyName']}: {e}")
    
    return findings


async def _scan_iam_users(iam_client, context: AuditContext) -> List[Finding]:
    """Scan IAM users for security issues."""
    findings = []
    
    try:
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                # Check for users with access keys
                access_keys = iam_client.list_access_keys(UserName=user['UserName'])
                if access_keys['AccessKeyMetadata']:
                    for key in access_keys['AccessKeyMetadata']:
                        # Check for old access keys (>90 days)
                        import datetime
                        age = datetime.datetime.now(datetime.timezone.utc) - key['CreateDate']
                        if age.days > 90:
                            findings.append(Finding(
                                service="iam",
                                resource_id=user['Arn'],
                                resource_name=user['UserName'],
                                check_id="IAM_OLD_ACCESS_KEY",
                                check_title="IAM User Has Old Access Key",
                                status=Status.FAIL,
                                severity=Severity.MEDIUM,
                                region=context.region,
                                account_id=context.account_id,
                                description=f"User '{user['UserName']}' has access key older than 90 days",
                                recommendation="Rotate access keys regularly"
                            ))
                            
    except Exception as e:
        logger.warning(f"Failed to scan IAM users: {e}")
    
    return findings


async def _scan_iam_roles(iam_client, context: AuditContext) -> List[Finding]:
    """Scan IAM roles for security issues."""
    findings = []
    
    try:
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                # Check for overly permissive trust policies
                trust_policy = role['AssumeRolePolicyDocument']
                if _has_overly_permissive_trust_policy(trust_policy):
                    findings.append(Finding(
                        service="iam",
                        resource_id=role['Arn'],
                        resource_name=role['RoleName'],
                        check_id="IAM_PERMISSIVE_TRUST_POLICY",
                        check_title="IAM Role Has Permissive Trust Policy",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        region=context.region,
                        account_id=context.account_id,
                        description=f"Role '{role['RoleName']}' has overly permissive trust policy",
                        recommendation="Restrict trust policy to specific principals"
                    ))
                    
    except Exception as e:
        logger.warning(f"Failed to scan IAM roles: {e}")
    
    return findings


def _is_overly_permissive(policy_doc: Dict) -> bool:
    """Check if policy document is overly permissive."""
    statements = policy_doc.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        if statement.get('Effect') == 'Allow':
            actions = statement.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
            
            for action in actions:
                if action in HIGH_RISK_ACTIONS:
                    return True
                    
                for pattern in ADMIN_PATTERNS:
                    if re.match(pattern, action):
                        return True
    
    return False


def _has_wildcard_actions(policy_doc: Dict) -> bool:
    """Check if policy uses wildcard actions."""
    statements = policy_doc.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        if statement.get('Effect') == 'Allow':
            actions = statement.get('Action', [])
            if not isinstance(actions, list):
                actions = [actions]
            
            for action in actions:
                if '*' in action:
                    return True
    
    return False


def _has_overly_permissive_trust_policy(trust_policy: Dict) -> bool:
    """Check if trust policy is overly permissive."""
    statements = trust_policy.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        if statement.get('Effect') == 'Allow':
            principal = statement.get('Principal', {})
            if principal == '*' or principal.get('AWS') == '*':
                return True
    
    return False


def register() -> ScannerPlugin:
    """Register IAM scanner plugin."""
    return ScannerPlugin(
        service="iam",
        required_permissions=[
            "iam:ListPolicies",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:ListUsers",
            "iam:ListAccessKeys",
            "iam:ListRoles",
            "iam:GetRole"
        ],
        scan_function=scan_iam,
        remediation_map={
            "IAM_OVERLY_PERMISSIVE_POLICY": "restrict_policy_permissions",
            "IAM_OLD_ACCESS_KEY": "rotate_access_key"
        }
    )