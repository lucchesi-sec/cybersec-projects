"""
Lambda Security Scanner Utilities
Common helper functions used across Lambda analyzers.
"""

import logging
from typing import List
from botocore.exceptions import ClientError

from core.audit_context import AuditContext

logger = logging.getLogger(__name__)


async def get_available_regions(context: AuditContext) -> List[str]:
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


def extract_function_name_from_arn(function_arn: str) -> str:
    """Extract function name from Lambda ARN."""
    if not function_arn:
        return 'Unknown'
    
    # ARN format: arn:aws:lambda:region:account-id:function:function-name[:version]
    parts = function_arn.split(':')
    if len(parts) >= 7:
        # Handle versioned ARNs
        return parts[6]
    return function_arn.split(':')[-1]


def is_aws_managed_policy(policy_arn: str) -> bool:
    """Check if a policy ARN is an AWS managed policy."""
    return 'aws:policy' in policy_arn.lower()


def is_overprivileged_policy(policy_name: str) -> bool:
    """Check if a policy name indicates over-privileged access."""
    overprivileged_patterns = [
        'FullAccess',
        'PowerUser',
        'AdministratorAccess',
        'ReadOnlyAccess'  # May be too broad for Lambda functions
    ]
    
    return any(pattern in policy_name for pattern in overprivileged_patterns)