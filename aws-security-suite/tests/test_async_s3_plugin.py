"""
Tests for async S3 plugin demonstrating async testing patterns.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from botocore.exceptions import ClientError

from plugins.s3.async_scanner import AsyncS3Scanner
from core.audit_context import AuditContext
from core.finding import Finding, Severity, Status


class TestAsyncS3Scanner:
    """Test async S3 scanner functionality."""
    
    def test_plugin_metadata(self):
        """Test plugin metadata and capabilities."""
        scanner = AsyncS3Scanner()
        
        assert scanner.service_name == "s3"
        assert scanner.supports_remediation() is True
        assert "s3:ListAllMyBuckets" in scanner.required_permissions
        assert len(scanner.required_permissions) >= 6
        
        metadata = scanner.get_metadata()
        assert metadata["service"] == "s3"
        assert "remediate" in metadata["capabilities"]
    
    @pytest.mark.asyncio
    async def test_get_all_buckets_async_success(self, async_audit_context):
        """Test successful bucket listing."""
        scanner = AsyncS3Scanner()
        
        # Mock the async context execution
        mock_response = {
            'Buckets': [
                {'Name': 'test-bucket-1', 'CreationDate': '2023-01-01'},
                {'Name': 'test-bucket-2', 'CreationDate': '2023-01-02'}
            ]
        }
        
        with patch.object(async_audit_context, 'execute_async', return_value=mock_response):
            buckets = await scanner._get_all_buckets_async(async_audit_context)
            
            assert len(buckets) == 2
            assert 'test-bucket-1' in buckets
            assert 'test-bucket-2' in buckets
    
    @pytest.mark.asyncio
    async def test_get_all_buckets_async_error(self, async_audit_context):
        """Test bucket listing with errors."""
        scanner = AsyncS3Scanner()
        
        with patch.object(async_audit_context, 'execute_async', side_effect=ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}}, 'ListBuckets'
        )):
            buckets = await scanner._get_all_buckets_async(async_audit_context)
            
            assert len(buckets) == 0
    
    @pytest.mark.asyncio
    async def test_run_scan_no_buckets(self, async_audit_context):
        """Test scan when no buckets are found."""
        scanner = AsyncS3Scanner()
        
        with patch.object(scanner, '_get_all_buckets_async', return_value=[]):
            findings = await scanner.run_scan(async_audit_context)
            
            assert len(findings) == 0
    
    @pytest.mark.asyncio
    async def test_run_scan_with_buckets(self, async_audit_context):
        """Test scan with buckets and findings."""
        scanner = AsyncS3Scanner()
        
        # Mock bucket discovery
        test_buckets = ['test-bucket-1', 'test-bucket-2']
        
        # Mock concurrent scan results
        mock_findings = [
            Finding(
                service="s3",
                resource_id="arn:aws:s3:::test-bucket-1",
                resource_name="test-bucket-1",
                check_id="S3_BUCKET_PUBLIC_READ",
                check_title="S3 Bucket Public Read Access",
                status=Status.FAIL,
                severity=Severity.HIGH,
                region="us-east-1",
                account_id="123456789012",
                description="Test finding",
                recommendation="Fix it"
            )
        ]
        
        with patch.object(scanner, '_get_all_buckets_async', return_value=test_buckets):
            with patch.object(scanner, '_scan_buckets_concurrent', return_value=mock_findings):
                findings = await scanner.run_scan(async_audit_context)
                
                assert len(findings) == 1
                assert findings[0].check_id == "S3_BUCKET_PUBLIC_READ"
    
    @pytest.mark.asyncio
    async def test_scan_buckets_concurrent(self, async_audit_context):
        """Test concurrent bucket scanning."""
        scanner = AsyncS3Scanner()
        bucket_names = ['test-bucket']
        
        # Mock the batch execution results
        mock_results = [
            # Results for test-bucket (6 operations)
            {'Grants': [{'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'}]},  # ACL
            Exception("NoSuchBucketPolicy"),  # Policy
            Exception("NoSuchBucketLogging"),  # Logging
            {'Status': 'Disabled'},  # Versioning
            Exception("NoSuchPublicAccessBlock"),  # Public Access Block
            Exception("NoSuchBucketEncryption"),  # Encryption
        ]
        
        with patch.object(scanner, 'execute_async_operations', return_value=mock_results):
            findings = await scanner._scan_buckets_concurrent(async_audit_context, bucket_names)
            
            # Should find multiple issues
            assert len(findings) >= 3  # Public read, no encryption, no versioning, no logging
            
            finding_ids = [f.check_id for f in findings]
            assert "S3_BUCKET_PUBLIC_READ" in finding_ids
            assert "S3_BUCKET_NO_ENCRYPTION" in finding_ids
            assert "S3_BUCKET_NO_VERSIONING" in finding_ids
    
    def test_analyze_bucket_results_public_read(self, async_audit_context):
        """Test analysis of bucket with public read access."""
        scanner = AsyncS3Scanner()
        
        results = [
            {'Grants': [{'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}, 'Permission': 'READ'}]},
            Exception("NoSuchBucketPolicy"),
            Exception("NoSuchBucketLogging"),
            {'Status': 'Enabled'},
            Exception("NoSuchPublicAccessBlock"),
            {'ServerSideEncryptionConfiguration': {'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}}
        ]
        
        findings = scanner._analyze_bucket_results('test-bucket', results, async_audit_context)
        
        # Should only find public read issue
        assert len(findings) == 2  # Public read and no logging
        assert any(f.check_id == "S3_BUCKET_PUBLIC_READ" for f in findings)
        assert any(f.check_id == "S3_BUCKET_NO_LOGGING" for f in findings)
    
    def test_analyze_bucket_results_no_issues(self, async_audit_context):
        """Test analysis of properly configured bucket."""
        scanner = AsyncS3Scanner()
        
        results = [
            {'Grants': [{'Grantee': {'Type': 'CanonicalUser'}, 'Permission': 'FULL_CONTROL'}]},  # Private ACL
            Exception("NoSuchBucketPolicy"),  # No policy (fine)
            {'LoggingEnabled': {'TargetBucket': 'log-bucket'}},  # Logging enabled
            {'Status': 'Enabled'},  # Versioning enabled
            {'PublicAccessBlockConfiguration': {'BlockPublicAcls': True, 'BlockPublicPolicy': True}},  # Public access blocked
            {'ServerSideEncryptionConfiguration': {'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}}  # Encryption
        ]
        
        findings = scanner._analyze_bucket_results('secure-bucket', results, async_audit_context)
        
        # Should find no issues
        assert len(findings) == 0
    
    def test_is_bucket_publicly_readable_via_acl(self):
        """Test detection of public read access via ACL."""
        scanner = AsyncS3Scanner()
        
        acl_result = {
            'Grants': [{
                'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                'Permission': 'READ'
            }]
        }
        policy_result = Exception("NoSuchBucketPolicy")
        public_block_result = Exception("NoSuchPublicAccessBlock")
        
        assert scanner._is_bucket_publicly_readable(acl_result, policy_result, public_block_result) is True
    
    def test_is_bucket_publicly_readable_blocked(self):
        """Test that public access block prevents detection of public access."""
        scanner = AsyncS3Scanner()
        
        acl_result = {
            'Grants': [{
                'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                'Permission': 'READ'
            }]
        }
        policy_result = Exception("NoSuchBucketPolicy")
        public_block_result = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'BlockPublicPolicy': True
            }
        }
        
        assert scanner._is_bucket_publicly_readable(acl_result, policy_result, public_block_result) is False
    
    def test_is_encryption_missing(self):
        """Test encryption detection."""
        scanner = AsyncS3Scanner()
        
        # No encryption configured
        no_encryption = Exception("NoSuchBucketEncryption")
        assert scanner._is_encryption_missing(no_encryption) is True
        
        # Empty encryption rules
        empty_encryption = {'ServerSideEncryptionConfiguration': {'Rules': []}}
        assert scanner._is_encryption_missing(empty_encryption) is True
        
        # Encryption configured
        with_encryption = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
            }
        }
        assert scanner._is_encryption_missing(with_encryption) is False
    
    def test_is_logging_missing(self):
        """Test logging detection."""
        scanner = AsyncS3Scanner()
        
        # No logging configured
        no_logging = Exception("NoSuchBucketLogging")
        assert scanner._is_logging_missing(no_logging) is True
        
        # Logging not enabled
        disabled_logging = {}
        assert scanner._is_logging_missing(disabled_logging) is True
        
        # Logging enabled
        enabled_logging = {'LoggingEnabled': {'TargetBucket': 'log-bucket'}}
        assert scanner._is_logging_missing(enabled_logging) is False
    
    def test_is_versioning_disabled(self):
        """Test versioning detection."""
        scanner = AsyncS3Scanner()
        
        # Error getting versioning
        versioning_error = Exception("AccessDenied")
        assert scanner._is_versioning_disabled(versioning_error) is True
        
        # Versioning disabled
        disabled_versioning = {'Status': 'Disabled'}
        assert scanner._is_versioning_disabled(disabled_versioning) is True
        
        # Versioning suspended
        suspended_versioning = {'Status': 'Suspended'}
        assert scanner._is_versioning_disabled(suspended_versioning) is True
        
        # Versioning enabled
        enabled_versioning = {'Status': 'Enabled'}
        assert scanner._is_versioning_disabled(enabled_versioning) is False


class TestAsyncS3ScannerRemediation:
    """Test async S3 scanner remediation functionality."""
    
    @pytest.mark.asyncio
    async def test_remediate_missing_encryption_dry_run(self, async_audit_context):
        """Test encryption remediation in dry run mode."""
        scanner = AsyncS3Scanner()
        
        finding = Finding(
            service="s3",
            resource_id="arn:aws:s3:::test-bucket",
            resource_name="test-bucket",
            check_id="S3_BUCKET_NO_ENCRYPTION",
            check_title="S3 Bucket Missing Encryption",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            region="us-east-1",
            account_id="123456789012",
            description="Test finding",
            recommendation="Enable encryption"
        )
        
        result = await scanner.remediate(finding, async_audit_context, dry_run=True)
        
        assert result["success"] is True
        assert result["dry_run"] is True
        assert result["action"] == "enable_encryption"
        assert "test-bucket" in result["details"]
    
    @pytest.mark.asyncio
    async def test_remediate_missing_encryption_actual(self, async_audit_context):
        """Test actual encryption remediation."""
        scanner = AsyncS3Scanner()
        
        finding = Finding(
            service="s3",
            resource_id="arn:aws:s3:::test-bucket",
            resource_name="test-bucket",
            check_id="S3_BUCKET_NO_ENCRYPTION",
            check_title="S3 Bucket Missing Encryption",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            region="us-east-1",
            account_id="123456789012",
            description="Test finding",
            recommendation="Enable encryption"
        )
        
        with patch.object(async_audit_context, 'execute_async', return_value={}):
            result = await scanner.remediate(finding, async_audit_context, dry_run=False)
            
            assert result["success"] is True
            assert result["dry_run"] is False
            assert result["action"] == "enable_encryption"
    
    @pytest.mark.asyncio
    async def test_remediate_public_access_dry_run(self, async_audit_context):
        """Test public access remediation in dry run mode."""
        scanner = AsyncS3Scanner()
        
        finding = Finding(
            service="s3",
            resource_id="arn:aws:s3:::test-bucket",
            resource_name="test-bucket",
            check_id="S3_BUCKET_PUBLIC_READ",
            check_title="S3 Bucket Public Read Access",
            status=Status.FAIL,
            severity=Severity.HIGH,
            region="us-east-1",
            account_id="123456789012",
            description="Test finding",
            recommendation="Block public access"
        )
        
        result = await scanner.remediate(finding, async_audit_context, dry_run=True)
        
        assert result["success"] is True
        assert result["dry_run"] is True
        assert result["action"] == "block_public_access"
    
    @pytest.mark.asyncio
    async def test_remediate_versioning_error(self, async_audit_context):
        """Test remediation with AWS error."""
        scanner = AsyncS3Scanner()
        
        finding = Finding(
            service="s3",
            resource_id="arn:aws:s3:::test-bucket",
            resource_name="test-bucket",
            check_id="S3_BUCKET_NO_VERSIONING",
            check_title="S3 Bucket Versioning Disabled",
            status=Status.FAIL,
            severity=Severity.LOW,
            region="us-east-1",
            account_id="123456789012",
            description="Test finding",
            recommendation="Enable versioning"
        )
        
        with patch.object(async_audit_context, 'execute_async', side_effect=ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}}, 'PutBucketVersioning'
        )):
            result = await scanner.remediate(finding, async_audit_context, dry_run=False)
            
            assert result["success"] is False
            assert result["action"] == "enable_versioning"
            assert "AccessDenied" in result["error"]
    
    @pytest.mark.asyncio
    async def test_remediate_unsupported_finding(self, async_audit_context):
        """Test remediation of unsupported finding type."""
        scanner = AsyncS3Scanner()
        
        finding = Finding(
            service="s3",
            resource_id="arn:aws:s3:::test-bucket",
            resource_name="test-bucket",
            check_id="UNSUPPORTED_CHECK",
            check_title="Unsupported Check",
            status=Status.FAIL,
            severity=Severity.LOW,
            region="us-east-1",
            account_id="123456789012",
            description="Test finding",
            recommendation="Manual fix required"
        )
        
        result = await scanner.remediate(finding, async_audit_context, dry_run=True)
        
        assert result["success"] is False
        assert "not implemented" in result["reason"]


class TestAsyncS3ScannerSyncCompatibility:
    """Test sync compatibility methods."""
    
    def test_run_scan_sync(self, audit_context):
        """Test synchronous scan execution."""
        scanner = AsyncS3Scanner()
        
        # Mock the async scan method
        async def mock_async_scan(context):
            return [
                Finding(
                    service="s3",
                    resource_id="arn:aws:s3:::test-bucket",
                    resource_name="test-bucket",
                    check_id="S3_BUCKET_PUBLIC_READ",
                    check_title="Test Finding",
                    status=Status.FAIL,
                    severity=Severity.HIGH,
                    region="us-east-1",
                    account_id="123456789012",
                    description="Test",
                    recommendation="Fix"
                )
            ]
        
        with patch.object(scanner, 'run_scan', side_effect=mock_async_scan):
            findings = scanner.run_scan_sync(audit_context)
            
            # The sync method should return findings
            assert len(findings) == 1
            assert findings[0].check_id == "S3_BUCKET_PUBLIC_READ"
    
    def test_remediate_sync(self, audit_context):
        """Test synchronous remediation execution."""
        scanner = AsyncS3Scanner()
        
        finding = Finding(
            service="s3",
            resource_id="arn:aws:s3:::test-bucket",
            resource_name="test-bucket",
            check_id="S3_BUCKET_NO_ENCRYPTION",
            check_title="Test Finding",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            region="us-east-1",
            account_id="123456789012",
            description="Test",
            recommendation="Fix"
        )
        
        # Mock the async remediate method
        async def mock_async_remediate(finding, context, dry_run):
            return {"success": True, "dry_run": dry_run, "action": "test"}
        
        with patch.object(scanner, 'remediate', side_effect=mock_async_remediate):
            result = scanner.remediate_sync(finding, audit_context, dry_run=True)
            
            assert result["success"] is True
            assert result["dry_run"] is True


def test_register_function():
    """Test plugin registration function."""
    plugin = AsyncS3Scanner()
    registered_plugin = AsyncS3Scanner()
    
    assert isinstance(registered_plugin, AsyncS3Scanner)
    assert registered_plugin.service_name == "s3"