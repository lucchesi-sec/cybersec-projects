"""
S3 Security Scanner Plugin
Migrated from aws-security-scanner/s3_scanner.py
"""

import asyncio
from typing import List, Dict, Any
from botocore.exceptions import ClientError
import logging

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext
from core.plugin import ScannerPlugin


logger = logging.getLogger(__name__)


async def scan_s3(context: AuditContext) -> List[Finding]:
    """Main S3 scanning function."""
    findings = []
    
    try:
        s3_client = context.get_client('s3')
        
        # Get all buckets
        buckets = await _get_all_buckets(s3_client)
        
        # Scan each bucket
        for bucket_name in buckets:
            bucket_findings = await _scan_bucket(s3_client, bucket_name, context)
            findings.extend(bucket_findings)
            
    except Exception as e:
        logger.error(f"S3 scan failed: {e}")
        
    return findings


async def _get_all_buckets(s3_client) -> List[str]:
    """Get list of all S3 buckets."""
    try:
        response = s3_client.list_buckets()
        return [bucket['Name'] for bucket in response['Buckets']]
    except ClientError as e:
        logger.error(f"Failed to list buckets: {e}")
        return []


async def _scan_bucket(s3_client, bucket_name: str, context: AuditContext) -> List[Finding]:
    """Scan a single bucket for security issues."""
    findings = []
    
    # Check public access
    public_access = await _check_bucket_public_access(s3_client, bucket_name)
    if public_access:
        findings.append(Finding(
            service="s3",
            resource_id=f"arn:aws:s3:::{bucket_name}",
            resource_name=bucket_name,
            check_id="S3_PUBLIC_ACCESS",
            check_title="S3 Bucket Public Access",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region=context.region,
            account_id=context.account_id,
            description="S3 bucket allows public access",
            recommendation="Enable S3 bucket public access block settings",
            remediation_available=True
        ))
    
    # Check encryption
    encryption_enabled = await _check_bucket_encryption(s3_client, bucket_name)
    if not encryption_enabled:
        findings.append(Finding(
            service="s3",
            resource_id=f"arn:aws:s3:::{bucket_name}",
            resource_name=bucket_name,
            check_id="S3_ENCRYPTION_DISABLED",
            check_title="S3 Bucket Encryption Disabled",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            region=context.region,
            account_id=context.account_id,
            description="S3 bucket does not have default encryption enabled",
            recommendation="Enable default encryption on S3 bucket"
        ))
    
    # Check versioning
    versioning_enabled = await _check_bucket_versioning(s3_client, bucket_name)
    if not versioning_enabled:
        findings.append(Finding(
            service="s3",
            resource_id=f"arn:aws:s3:::{bucket_name}",
            resource_name=bucket_name,
            check_id="S3_VERSIONING_DISABLED",
            check_title="S3 Bucket Versioning Disabled",
            status=Status.FAIL,
            severity=Severity.LOW,
            region=context.region,
            account_id=context.account_id,
            description="S3 bucket does not have versioning enabled",
            recommendation="Enable versioning on S3 bucket for data protection"
        ))
    
    return findings
async def _check_bucket_public_access(s3_client, bucket_name: str) -> bool:
    """Check if bucket has public access enabled."""
    try:
        # Check public access block settings
        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            block_config = public_access_block['PublicAccessBlockConfiguration']
            
            if (block_config.get('BlockPublicAcls', False) and
                block_config.get('IgnorePublicAcls', False) and
                block_config.get('BlockPublicPolicy', False) and
                block_config.get('RestrictPublicBuckets', False)):
                return False
        except ClientError:
            pass
        
        # Check bucket ACL
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                return True
        
        # Check bucket policy
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            if '"Principal": "*"' in policy['Policy'] or '"Principal":"*"' in policy['Policy']:
                return True
        except ClientError:
            pass
        
        return False
    except Exception as e:
        logger.warning(f"Could not check public access for {bucket_name}: {e}")
        return False


async def _check_bucket_encryption(s3_client, bucket_name: str) -> bool:
    """Check if bucket has default encryption enabled."""
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError:
        return False
    except Exception as e:
        logger.warning(f"Could not check encryption for {bucket_name}: {e}")
        return False


async def _check_bucket_versioning(s3_client, bucket_name: str) -> bool:
    """Check if bucket has versioning enabled."""
    try:
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        return versioning.get('Status') == 'Enabled'
    except Exception as e:
        logger.warning(f"Could not check versioning for {bucket_name}: {e}")
        return False


def register() -> ScannerPlugin:
    """Register S3 scanner plugin."""
    return ScannerPlugin(
        service="s3",
        required_permissions=[
            "s3:ListAllMyBuckets",
            "s3:GetBucketAcl",
            "s3:GetBucketPolicy",
            "s3:GetBucketVersioning",
            "s3:GetBucketEncryption",
            "s3:GetBucketPublicAccessBlock"
        ],
        scan_function=scan_s3,
        remediation_map={
            "S3_PUBLIC_ACCESS": "fix_bucket_public_access",
            "S3_ENCRYPTION_DISABLED": "enable_bucket_encryption"
        }
    )