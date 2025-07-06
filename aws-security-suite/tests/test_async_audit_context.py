"""
Tests for async-enabled audit context.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
import boto3

from core.audit_context import AuditContext
from core.async_client import AsyncClientManager, ClientConfig


class TestAsyncAuditContext:
    """Test async capabilities of AuditContext."""
    
    def test_audit_context_initialization_with_async_manager(self, mock_aws_credentials):
        """Test that audit context initializes with async client manager."""
        context = AuditContext(
            region="us-east-1",
            services=["s3", "ec2"]
        )
        
        assert context._async_client_manager is not None
        assert isinstance(context.async_client_manager, AsyncClientManager)
    
    def test_async_client_manager_configuration(self, mock_aws_credentials):
        """Test that async client manager is configured with context settings."""
        context = AuditContext(
            region="us-west-2",
            profile_name="test_profile",
            role_arn="arn:aws:iam::123456789012:role/test-role",
            external_id="test_external_id"
        )
        
        manager = context.async_client_manager
        config = manager._default_config
        
        assert config.region_name == "us-west-2"
        assert config.profile_name == "test_profile"
        assert config.role_arn == "arn:aws:iam::123456789012:role/test-role"
        assert config.external_id == "test_external_id"
    
    @pytest.mark.asyncio
    async def test_get_async_client(self, mock_aws_credentials):
        """Test getting async client from audit context."""
        context = AuditContext(region="us-east-1")
        
        with patch.object(context.async_client_manager, 'get_client') as mock_get_client:
            mock_client_wrapper = Mock()
            mock_context_manager = Mock()
            mock_client_wrapper.get_async_client.return_value = mock_context_manager
            mock_get_client.return_value = mock_client_wrapper
            
            result = await context.get_async_client("s3", "us-east-1")
            
            assert result == mock_context_manager
            mock_get_client.assert_called_once_with("s3", "us-east-1")
    
    @pytest.mark.asyncio
    async def test_execute_async_with_rate_limiting(self, mock_aws_credentials):
        """Test async execution with rate limiting."""
        context = AuditContext(
            region="us-east-1",
            enable_rate_limiting=True
        )
        
        # Mock rate limiter
        mock_rate_limiter = Mock()
        mock_rate_limiter.acquire_tokens = AsyncMock()
        context._rate_limiter = mock_rate_limiter
        
        # Mock async client manager
        with patch.object(context.async_client_manager, 'execute_async') as mock_execute:
            mock_execute.return_value = {'test': 'response'}
            
            result = await context.execute_async("s3", "list_buckets")
            
            assert result == {'test': 'response'}
            mock_rate_limiter.acquire_tokens.assert_called_once_with("s3", 1)
            mock_execute.assert_called_once_with(
                service_name="s3",
                method_name="list_buckets",
                region_name="us-east-1"
            )
    
    @pytest.mark.asyncio
    async def test_execute_async_without_rate_limiting(self, mock_aws_credentials):
        """Test async execution without rate limiting."""
        context = AuditContext(
            region="us-east-1",
            enable_rate_limiting=False
        )
        
        with patch.object(context.async_client_manager, 'execute_async') as mock_execute:
            mock_execute.return_value = {'test': 'response'}
            
            result = await context.execute_async("s3", "list_buckets", region="us-west-2")
            
            assert result == {'test': 'response'}
            mock_execute.assert_called_once_with(
                service_name="s3",
                method_name="list_buckets",
                region_name="us-west-2"
            )
    
    @pytest.mark.asyncio
    async def test_batch_execute_async(self, mock_aws_credentials):
        """Test batch async execution."""
        context = AuditContext(
            region="us-east-1",
            enable_rate_limiting=True
        )
        
        operations = [
            {'service': 's3', 'method': 'list_buckets'},
            {'service': 'ec2', 'method': 'describe_instances'}
        ]
        
        # Mock rate limiter
        mock_rate_limiter = Mock()
        mock_rate_limiter.acquire_tokens = AsyncMock()
        context._rate_limiter = mock_rate_limiter
        
        with patch.object(context.async_client_manager, 'batch_execute_async') as mock_batch:
            mock_batch.return_value = [{'buckets': []}, {'instances': []}]
            
            results = await context.batch_execute_async(operations)
            
            assert len(results) == 2
            assert results[0] == {'buckets': []}
            assert results[1] == {'instances': []}
            
            # Check rate limiting was applied for each operation
            assert mock_rate_limiter.acquire_tokens.call_count == 2
            mock_batch.assert_called_once_with(operations)
    
    @pytest.mark.asyncio
    async def test_get_rate_limited_client_legacy_compatibility(self, mock_aws_credentials):
        """Test that legacy get_rate_limited_client still works."""
        context = AuditContext(
            region="us-east-1",
            enable_rate_limiting=True
        )
        
        # Mock rate limiter
        mock_rate_limiter = Mock()
        mock_rate_limiter.acquire_tokens = AsyncMock()
        context._rate_limiter = mock_rate_limiter
        
        with patch.object(context, 'get_client') as mock_get_client:
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            
            result = await context.get_rate_limited_client("s3", tokens=2)
            
            assert result == mock_client
            mock_rate_limiter.acquire_tokens.assert_called_once_with("s3", 2)
            mock_get_client.assert_called_once_with("s3", None)
    
    def test_backward_compatibility_sync_methods(self, mock_aws_credentials):
        """Test that existing synchronous methods still work."""
        context = AuditContext(region="us-east-1")
        
        # Test that sync methods are not affected
        with patch('boto3.Session') as mock_session:
            mock_session_instance = Mock()
            mock_client = Mock()
            mock_session_instance.client.return_value = mock_client
            mock_session.return_value = mock_session_instance
            
            client = context.get_client("s3")
            assert client == mock_client
    
    def test_async_manager_recreation_on_config_change(self, mock_aws_credentials):
        """Test that async manager is recreated when context changes."""
        context = AuditContext(region="us-east-1")
        
        # Get initial manager
        manager1 = context.async_client_manager
        
        # Clear the manager to simulate recreation
        context._async_client_manager = None
        
        # Change configuration
        context.profile_name = "new_profile"
        
        # Get manager again - should be recreated with new config
        manager2 = context.async_client_manager
        
        assert manager1 is not manager2
        assert manager2._default_config.profile_name == "new_profile"


class TestAsyncContextIntegration:
    """Integration tests for async context with real AWS operations."""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_concurrent_region_scanning(self, mock_aws_credentials):
        """Test scanning multiple regions concurrently."""
        context = AuditContext(
            regions=["us-east-1", "us-west-2", "eu-west-1"],
            enable_rate_limiting=False
        )
        
        # Mock the async operations
        async def mock_list_buckets_for_region(region):
            # Simulate different responses per region
            return {
                'Buckets': [
                    {'Name': f'bucket-in-{region}', 'CreationDate': '2023-01-01'}
                ]
            }
        
        operations = []
        for region in context.regions:
            operations.append({
                'service': 's3',
                'method': 'list_buckets',
                'region': region
            })
        
        with patch.object(context.async_client_manager, 'batch_execute_async') as mock_batch:
            mock_batch.return_value = [
                await mock_list_buckets_for_region(region) 
                for region in context.regions
            ]
            
            results = await context.batch_execute_async(operations)
            
            assert len(results) == 3
            for i, region in enumerate(context.regions):
                assert f'bucket-in-{region}' in str(results[i])
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_error_handling_in_batch_operations(self, mock_aws_credentials):
        """Test error handling in batch async operations."""
        context = AuditContext(
            region="us-east-1",
            enable_rate_limiting=False
        )
        
        operations = [
            {'service': 's3', 'method': 'list_buckets'},
            {'service': 'invalid_service', 'method': 'invalid_method'}
        ]
        
        with patch.object(context.async_client_manager, 'batch_execute_async') as mock_batch:
            # Simulate one success and one error
            mock_batch.return_value = [
                {'Buckets': []},
                Exception("Service not found")
            ]
            
            results = await context.batch_execute_async(operations)
            
            assert len(results) == 2
            assert isinstance(results[0], dict)
            assert isinstance(results[1], Exception)
    
    @pytest.mark.asyncio
    async def test_async_context_with_custom_rate_limits(self, mock_aws_credentials):
        """Test async context with custom rate limits."""
        context = AuditContext(
            region="us-east-1",
            enable_rate_limiting=True,
            custom_rate_limits={
                's3': 10.0,
                'ec2': 5.0
            }
        )
        
        # Mock rate limiter to verify custom rates are applied
        mock_rate_limiter = Mock()
        mock_rate_limiter.acquire_tokens = AsyncMock()
        mock_rate_limiter.set_service_rate = Mock()
        
        with patch('core.audit_context.get_rate_limiter', return_value=mock_rate_limiter):
            # Access rate_limiter property to trigger setup
            _ = context.rate_limiter
            
            # Verify custom rates were set
            mock_rate_limiter.set_service_rate.assert_any_call('s3', 10.0)
            mock_rate_limiter.set_service_rate.assert_any_call('ec2', 5.0)


class TestAsyncContextWithAssumedRoles:
    """Test async context with assumed role functionality."""
    
    @pytest.mark.asyncio
    async def test_async_client_with_assumed_role(self, mock_aws_credentials):
        """Test async client creation with assumed roles."""
        context = AuditContext(
            region="us-east-1",
            role_arn="arn:aws:iam::123456789012:role/test-role",
            external_id="test_external_id"
        )
        
        # Verify the async client manager is configured with role info
        manager = context.async_client_manager
        config = manager._default_config
        
        assert config.role_arn == "arn:aws:iam::123456789012:role/test-role"
        assert config.external_id == "test_external_id"
    
    @pytest.mark.asyncio
    async def test_cross_account_async_operations(self, mock_aws_credentials):
        """Test cross-account operations with async context."""
        context = AuditContext(
            region="us-east-1",
            delegated_admin_account="123456789012",
            organization_role_name="CustomOrgRole"
        )
        
        # Mock the role assumption for cross-account access
        with patch.object(context, '_create_cross_account_client') as mock_cross_account:
            mock_client = Mock()
            mock_cross_account.return_value = mock_client
            
            # Test that sync client creation uses cross-account logic
            client = context.get_client("s3")
            
            # The cross-account logic should be triggered in _create_service_client
            assert context.delegated_admin_account == "123456789012"
            assert context.organization_role_name == "CustomOrgRole"