"""
S3 Security Scanner Plugin - Async Enhanced Version
Demonstrates the new async foundation and patterns.
"""

import asyncio
from typing import List, Dict, Any
from botocore.exceptions import ClientError
import logging

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext
from core.plugin import PluginBase


logger = logging.getLogger(__name__)


class AsyncS3Scanner(PluginBase):
    """
    Async-enhanced S3 security scanner using the new plugin base.
    Demonstrates unified sync/async patterns and concurrent operations.
    """
    
    @property
    def service_name(self) -> str:
        """Return the AWS service name this plugin scans."""
        return "s3"
    
    @property
    def required_permissions(self) -> List[str]:
        """Return list of required AWS IAM permissions."""
        return [
            "s3:ListAllMyBuckets",
            "s3:GetBucketAcl",
            "s3:GetBucketPolicy",
            "s3:GetBucketLogging",
            "s3:GetBucketVersioning",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetEncryptionConfiguration",
            "s3:GetBucketLocation"
        ]
    
    def supports_remediation(self) -> bool:
        """Return True if plugin supports automated remediation."""
        return True
    
    async def run_scan(self, context: AuditContext) -> List[Finding]:
        """Execute the S3 security scan using async patterns."""
        findings = []
        
        try:
            # Get all buckets using async client
            buckets = await self._get_all_buckets_async(context)
            
            if not buckets:
                self._logger.warning("No S3 buckets found or unable to list buckets")
                return findings
            
            # Scan buckets concurrently
            findings = await self._scan_buckets_concurrent(context, buckets)
            
        except Exception as e:
            self._logger.error(f"S3 async scan failed: {e}")
            
        return findings
    
    async def _get_all_buckets_async(self, context: AuditContext) -> List[str]:
        """Get list of all S3 buckets using async client."""
        try:
            response = await context.execute_async("s3", "list_buckets")
            return [bucket['Name'] for bucket in response.get('Buckets', [])]
        except ClientError as e:
            self._logger.error(f"Failed to list buckets: {e}")
            return []
    
    async def _scan_buckets_concurrent(self, context: AuditContext, bucket_names: List[str]) -> List[Finding]:
        """Scan multiple buckets concurrently."""
        # Create operations for all bucket checks
        operations = []
        for bucket_name in bucket_names:
            # Batch multiple checks per bucket
            bucket_operations = [
                {'method': 'get_bucket_acl', 'kwargs': {'Bucket': bucket_name}},
                {'method': 'get_bucket_policy', 'kwargs': {'Bucket': bucket_name}},
                {'method': 'get_bucket_logging', 'kwargs': {'Bucket': bucket_name}},
                {'method': 'get_bucket_versioning', 'kwargs': {'Bucket': bucket_name}},
                {'method': 'get_public_access_block', 'kwargs': {'Bucket': bucket_name}},
                {'method': 'get_bucket_encryption', 'kwargs': {'Bucket': bucket_name}},
            ]
            operations.extend(bucket_operations)
        
        # Execute all operations concurrently
        results = await self.execute_async_operations(context, operations)
        
        # Process results and generate findings
        findings = []
        for i, bucket_name in enumerate(bucket_names):
            bucket_results = results[i*6:(i+1)*6]  # 6 operations per bucket
            bucket_findings = self._analyze_bucket_results(bucket_name, bucket_results, context)
            findings.extend(bucket_findings)
        
        return findings
    
    def _analyze_bucket_results(self, bucket_name: str, results: List[Any], context: AuditContext) -> List[Finding]:
        """Analyze bucket check results and generate findings."""
        findings = []
        
        try:
            acl_result, policy_result, logging_result, versioning_result, public_block_result, encryption_result = results
            
            # Check for public read access
            if self._is_bucket_publicly_readable(acl_result, policy_result, public_block_result):
                findings.append(Finding(
                    service="s3",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    resource_name=bucket_name,
                    check_id="S3_BUCKET_PUBLIC_READ",
                    check_title="S3 Bucket Public Read Access",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    region=context.region,
                    account_id=context.account_id,
                    description=f"S3 bucket '{bucket_name}' allows public read access",
                    recommendation="Restrict bucket access to authorized users only"
                ))
            
            # Check for missing encryption
            if self._is_encryption_missing(encryption_result):
                findings.append(Finding(
                    service="s3",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    resource_name=bucket_name,
                    check_id="S3_BUCKET_NO_ENCRYPTION",
                    check_title="S3 Bucket Missing Encryption",
                    status=Status.FAIL,
                    severity=Severity.MEDIUM,
                    region=context.region,
                    account_id=context.account_id,
                    description=f"S3 bucket '{bucket_name}' does not have server-side encryption enabled",
                    recommendation="Enable server-side encryption with AES-256 or KMS"
                ))
            
            # Check for missing access logging
            if self._is_logging_missing(logging_result):
                findings.append(Finding(
                    service="s3",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    resource_name=bucket_name,
                    check_id="S3_BUCKET_NO_LOGGING",
                    check_title="S3 Bucket Missing Access Logging",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    region=context.region,
                    account_id=context.account_id,
                    description=f"S3 bucket '{bucket_name}' does not have access logging enabled",
                    recommendation="Enable access logging to track bucket access patterns"
                ))
            
            # Check for missing versioning
            if self._is_versioning_disabled(versioning_result):
                findings.append(Finding(
                    service="s3",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    resource_name=bucket_name,
                    check_id="S3_BUCKET_NO_VERSIONING",
                    check_title="S3 Bucket Versioning Disabled",
                    status=Status.FAIL,
                    severity=Severity.LOW,
                    region=context.region,
                    account_id=context.account_id,
                    description=f"S3 bucket '{bucket_name}' does not have versioning enabled",
                    recommendation="Enable versioning to protect against accidental deletion"
                ))
                
        except Exception as e:
            self._logger.error(f"Error analyzing bucket {bucket_name}: {e}")
        
        return findings
    
    def _is_bucket_publicly_readable(self, acl_result: Any, policy_result: Any, public_block_result: Any) -> bool:
        """Check if bucket allows public read access."""
        # Handle errors in results
        if isinstance(acl_result, Exception) or isinstance(policy_result, Exception):
            return False
        
        # Check if public access block prevents public access
        if not isinstance(public_block_result, Exception):
            config = public_block_result.get('PublicAccessBlockConfiguration', {})
            if config.get('BlockPublicAcls') and config.get('BlockPublicPolicy'):
                return False
        
        # Check ACL for public read access
        if not isinstance(acl_result, Exception):
            grants = acl_result.get('Grants', [])
            for grant in grants:
                grantee = grant.get('Grantee', {})
                if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                    permission = grant.get('Permission', '')
                    if permission in ['READ', 'FULL_CONTROL']:
                        return True
        
        # Check bucket policy for public access
        if not isinstance(policy_result, Exception):
            # This would require parsing the policy JSON - simplified for example
            policy_text = str(policy_result)
            if '*' in policy_text and 's3:GetObject' in policy_text:
                return True
        
        return False
    
    def _is_encryption_missing(self, encryption_result: Any) -> bool:
        """Check if bucket encryption is missing."""
        if isinstance(encryption_result, Exception):
            # If we get an error, encryption is likely not configured
            return True
        
        rules = encryption_result.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        return len(rules) == 0
    
    def _is_logging_missing(self, logging_result: Any) -> bool:
        """Check if access logging is missing."""
        if isinstance(logging_result, Exception):
            return True
        
        logging_enabled = logging_result.get('LoggingEnabled')
        return logging_enabled is None
    
    def _is_versioning_disabled(self, versioning_result: Any) -> bool:
        """Check if versioning is disabled."""
        if isinstance(versioning_result, Exception):
            return True
        
        status = versioning_result.get('Status', 'Disabled')
        return status != 'Enabled'
    
    async def remediate(self, finding: Finding, context: AuditContext, dry_run: bool = True) -> Dict[str, Any]:
        """Attempt to remediate specific S3 findings."""
        if finding.check_id == "S3_BUCKET_NO_ENCRYPTION":
            return await self._remediate_missing_encryption(finding, context, dry_run)
        elif finding.check_id == "S3_BUCKET_NO_VERSIONING":
            return await self._remediate_missing_versioning(finding, context, dry_run)
        elif finding.check_id == "S3_BUCKET_PUBLIC_READ":
            return await self._remediate_public_access(finding, context, dry_run)
        else:
            return await super().remediate(finding, context, dry_run)
    
    async def _remediate_missing_encryption(self, finding: Finding, context: AuditContext, dry_run: bool) -> Dict[str, Any]:
        """Remediate missing bucket encryption."""
        bucket_name = finding.resource_name
        
        if dry_run:
            return {
                "success": True,
                "action": "enable_encryption",
                "dry_run": True,
                "details": f"Would enable AES-256 encryption on bucket {bucket_name}"
            }
        
        try:
            await context.execute_async("s3", "put_bucket_encryption", Bucket=bucket_name, 
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }]
                })
            
            return {
                "success": True,
                "action": "enable_encryption",
                "dry_run": False,
                "details": f"Enabled AES-256 encryption on bucket {bucket_name}"
            }
        except Exception as e:
            return {
                "success": False,
                "action": "enable_encryption",
                "dry_run": False,
                "error": str(e)
            }
    
    async def _remediate_missing_versioning(self, finding: Finding, context: AuditContext, dry_run: bool) -> Dict[str, Any]:
        """Remediate missing bucket versioning."""
        bucket_name = finding.resource_name
        
        if dry_run:
            return {
                "success": True,
                "action": "enable_versioning",
                "dry_run": True,
                "details": f"Would enable versioning on bucket {bucket_name}"
            }
        
        try:
            await context.execute_async("s3", "put_bucket_versioning", 
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'})
            
            return {
                "success": True,
                "action": "enable_versioning", 
                "dry_run": False,
                "details": f"Enabled versioning on bucket {bucket_name}"
            }
        except Exception as e:
            return {
                "success": False,
                "action": "enable_versioning",
                "dry_run": False,
                "error": str(e)
            }
    
    async def _remediate_public_access(self, finding: Finding, context: AuditContext, dry_run: bool) -> Dict[str, Any]:
        """Remediate public bucket access."""
        bucket_name = finding.resource_name
        
        if dry_run:
            return {
                "success": True,
                "action": "block_public_access",
                "dry_run": True,
                "details": f"Would enable public access block on bucket {bucket_name}"
            }
        
        try:
            await context.execute_async("s3", "put_public_access_block",
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                })
            
            return {
                "success": True,
                "action": "block_public_access",
                "dry_run": False,
                "details": f"Enabled public access block on bucket {bucket_name}"
            }
        except Exception as e:
            return {
                "success": False,
                "action": "block_public_access",
                "dry_run": False,
                "error": str(e)
            }


def register() -> AsyncS3Scanner:
    """Register the async S3 scanner plugin."""
    return AsyncS3Scanner()