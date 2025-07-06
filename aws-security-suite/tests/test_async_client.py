"""
Tests for async AWS client abstraction.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import boto3
import aioboto3
from moto import mock_aws

from core.async_client import (
    AsyncAWSClient, 
    AsyncClientManager, 
    ClientConfig,
    configure_default_client,
    get_client_manager
)


class TestClientConfig:
    """Test ClientConfig dataclass."""
    
    def test_basic_config_creation(self):
        """Test basic client configuration creation."""
        config = ClientConfig(
            service_name="s3",
            region_name="us-east-1"
        )
        
        assert config.service_name == "s3"
        assert config.region_name == "us-east-1"
        assert config.aws_access_key_id is None
        assert config.profile_name is None
    
    def test_full_config_creation(self):
        """Test client configuration with all parameters."""
        config = ClientConfig(
            service_name="s3",
            region_name="us-west-2",
            aws_access_key_id="test_key",
            aws_secret_access_key="test_secret",
            aws_session_token="test_token",
            profile_name="test_profile",
            role_arn="arn:aws:iam::123456789012:role/test-role",
            external_id="test_external_id"
        )
        
        assert config.service_name == "s3"
        assert config.region_name == "us-west-2"
        assert config.aws_access_key_id == "test_key"
        assert config.aws_secret_access_key == "test_secret"
        assert config.aws_session_token == "test_token"
        assert config.profile_name == "test_profile"
        assert config.role_arn == "arn:aws:iam::123456789012:role/test-role"
        assert config.external_id == "test_external_id"


class TestAsyncAWSClient:
    """Test AsyncAWSClient functionality."""
    
    def test_client_initialization(self, client_config):
        """Test async AWS client initialization."""
        client = AsyncAWSClient(client_config)
        assert client.config == client_config
        assert client._session is None
        assert client._async_session is None
    
    @patch('boto3.Session')
    def test_sync_session_creation(self, mock_session, client_config):
        """Test synchronous session creation."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        client = AsyncAWSClient(client_config)
        session = client.session
        
        assert session == mock_session_instance
        mock_session.assert_called_once_with(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            aws_session_token=None,
            region_name="us-east-1"
        )
    
    @patch('boto3.Session')
    def test_sync_session_with_profile(self, mock_session):
        """Test synchronous session creation with profile."""
        config = ClientConfig(
            service_name="s3",
            region_name="us-east-1",
            profile_name="test_profile"
        )
        
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        client = AsyncAWSClient(config)
        session = client.session
        
        assert session == mock_session_instance
        mock_session.assert_called_once_with(profile_name="test_profile")
    
    @patch('aioboto3.Session')
    def test_async_session_creation(self, mock_session, client_config):
        """Test asynchronous session creation."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        client = AsyncAWSClient(client_config)
        session = client.async_session
        
        assert session == mock_session_instance
        mock_session.assert_called_once_with(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            aws_session_token=None,
            region_name="us-east-1"
        )
    
    @patch('boto3.Session')
    def test_sync_client_creation(self, mock_session, client_config):
        """Test synchronous client creation."""
        mock_session_instance = Mock()
        mock_client = Mock()
        mock_session_instance.client.return_value = mock_client
        mock_session.return_value = mock_session_instance
        
        client = AsyncAWSClient(client_config)
        sync_client = client.get_sync_client()
        
        assert sync_client == mock_client
        mock_session_instance.client.assert_called_once_with(
            "s3",
            region_name="us-east-1"
        )
    
    @pytest.mark.asyncio
    async def test_async_client_creation(self, client_config):
        """Test asynchronous client creation."""
        with patch('aioboto3.Session') as mock_session:
            mock_session_instance = Mock()
            mock_client = AsyncMock()
            mock_session_instance.client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_session_instance.client.return_value.__aexit__ = AsyncMock(return_value=None)
            mock_session.return_value = mock_session_instance
            
            client = AsyncAWSClient(client_config)
            
            async with client.get_async_client() as async_client:
                assert async_client == mock_client


class TestAsyncClientManager:
    """Test AsyncClientManager functionality."""
    
    def test_manager_initialization(self):
        """Test client manager initialization."""
        manager = AsyncClientManager()
        assert len(manager._clients) == 0
        assert manager._default_config is None
    
    def test_set_default_config(self, client_config):
        """Test setting default configuration."""
        manager = AsyncClientManager()
        manager.set_default_config(client_config)
        assert manager._default_config == client_config
    
    def test_get_client_with_config(self, client_config):
        """Test getting client with explicit configuration."""
        manager = AsyncClientManager()
        client = manager.get_client("s3", "us-east-1", client_config)
        
        assert isinstance(client, AsyncAWSClient)
        assert client.config.service_name == "s3"
        assert client.config.region_name == "us-east-1"
    
    def test_get_client_with_default_config(self, client_config):
        """Test getting client with default configuration."""
        manager = AsyncClientManager()
        manager.set_default_config(client_config)
        
        client = manager.get_client("ec2", "us-west-2")
        
        assert isinstance(client, AsyncAWSClient)
        assert client.config.service_name == "ec2"
        assert client.config.region_name == "us-west-2"
    
    def test_get_client_without_config_raises_error(self):
        """Test that getting client without config raises error."""
        manager = AsyncClientManager()
        
        with pytest.raises(ValueError, match="No default config set"):
            manager.get_client("s3")
    
    def test_client_caching(self, client_config):
        """Test that clients are cached properly."""
        manager = AsyncClientManager()
        
        client1 = manager.get_client("s3", "us-east-1", client_config)
        client2 = manager.get_client("s3", "us-east-1", client_config)
        
        assert client1 is client2
    
    def test_different_regions_different_clients(self, client_config):
        """Test that different regions create different clients."""
        manager = AsyncClientManager()
        
        client1 = manager.get_client("s3", "us-east-1", client_config)
        client2 = manager.get_client("s3", "us-west-2", client_config)
        
        assert client1 is not client2
    
    @patch('boto3.client')
    def test_execute_sync(self, mock_client, client_config):
        """Test synchronous execution."""
        mock_service_client = Mock()
        mock_method = Mock(return_value={'test': 'response'})
        mock_service_client.list_buckets = mock_method
        mock_client.return_value = mock_service_client
        
        manager = AsyncClientManager()
        manager.set_default_config(client_config)
        
        with patch.object(manager, 'get_client') as mock_get_client:
            mock_aws_client = Mock()
            mock_aws_client.get_sync_client.return_value = mock_service_client
            mock_get_client.return_value = mock_aws_client
            
            result = manager.execute_sync("s3", "list_buckets")
            
            assert result == {'test': 'response'}
            mock_method.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_execute_async(self, client_config):
        """Test asynchronous execution."""
        manager = AsyncClientManager()
        manager.set_default_config(client_config)
        
        with patch.object(manager, 'get_client') as mock_get_client:
            mock_aws_client = Mock()
            mock_async_client = AsyncMock()
            mock_async_client.list_buckets = AsyncMock(return_value={'test': 'response'})
            
            # Create a mock context manager
            mock_context_manager = Mock()
            mock_context_manager.__aenter__ = AsyncMock(return_value=mock_async_client)
            mock_context_manager.__aexit__ = AsyncMock(return_value=None)
            
            mock_aws_client.get_async_client.return_value = mock_context_manager
            mock_get_client.return_value = mock_aws_client
            
            result = await manager.execute_async("s3", "list_buckets")
            
            assert result == {'test': 'response'}
    
    @pytest.mark.asyncio
    async def test_batch_execute_async(self, client_config):
        """Test batch asynchronous execution."""
        operations = [
            {'service': 's3', 'method': 'list_buckets'},
            {'service': 'ec2', 'method': 'describe_instances'}
        ]
        
        manager = AsyncClientManager()
        
        with patch.object(manager, 'execute_async') as mock_execute:
            mock_execute.side_effect = [
                {'buckets': []},
                {'instances': []}
            ]
            
            results = await manager.batch_execute_async(operations)
            
            assert len(results) == 2
            assert results[0] == {'buckets': []}
            assert results[1] == {'instances': []}
    
    def test_clear_cache(self, client_config):
        """Test cache clearing."""
        manager = AsyncClientManager()
        manager.set_default_config(client_config)
        
        # Create some clients
        manager.get_client("s3", "us-east-1")
        manager.get_client("ec2", "us-west-2")
        
        assert len(manager._clients) == 2
        
        manager.clear_cache()
        assert len(manager._clients) == 0


class TestGlobalClientManager:
    """Test global client manager functions."""
    
    def test_get_client_manager(self):
        """Test getting global client manager."""
        manager1 = get_client_manager()
        manager2 = get_client_manager()
        
        assert manager1 is manager2
        assert isinstance(manager1, AsyncClientManager)
    
    def test_configure_default_client(self):
        """Test configuring default client globally."""
        configure_default_client(
            region_name="us-west-2",
            profile_name="test_profile"
        )
        
        manager = get_client_manager()
        config = manager._default_config
        
        assert config.region_name == "us-west-2"
        assert config.profile_name == "test_profile"


@pytest.mark.integration
class TestAsyncClientIntegration:
    """Integration tests with mocked AWS services."""
    
    @pytest.mark.asyncio
    @mock_aws
    async def test_real_s3_async_operations(self, mock_aws_credentials):
        """Test real S3 operations with moto mocking."""
        config = ClientConfig(
            service_name="s3",
            region_name="us-east-1"
        )
        
        client = AsyncAWSClient(config)
        
        async with client.get_async_client() as s3_client:
            # This should work with moto mocking
            response = await s3_client.list_buckets()
            assert 'Buckets' in response
    
    @mock_aws
    def test_real_s3_sync_operations(self, mock_aws_credentials):
        """Test real S3 operations synchronously with moto mocking."""
        config = ClientConfig(
            service_name="s3",
            region_name="us-east-1"
        )
        
        client = AsyncAWSClient(config)
        s3_client = client.get_sync_client()
        
        # This should work with moto mocking
        response = s3_client.list_buckets()
        assert 'Buckets' in response
    
    @pytest.mark.asyncio
    @mock_aws
    async def test_assumed_role_client_creation(self, mock_aws_credentials):
        """Test creating client with assumed role."""
        config = ClientConfig(
            service_name="s3",
            region_name="us-east-1",
            role_arn="arn:aws:iam::123456789012:role/test-role"
        )
        
        # Mock STS assume_role response
        with patch('boto3.Session') as mock_session:
            mock_sts_client = Mock()
            mock_sts_client.assume_role.return_value = {
                'Credentials': {
                    'AccessKeyId': 'test_key',
                    'SecretAccessKey': 'test_secret',
                    'SessionToken': 'test_token'
                }
            }
            mock_session_instance = Mock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session.return_value = mock_session_instance
            
            with patch('boto3.client') as mock_client:
                mock_s3_client = Mock()
                mock_client.return_value = mock_s3_client
                
                client = AsyncAWSClient(config)
                result_client = client.get_sync_client()
                
                assert result_client == mock_s3_client
                mock_sts_client.assume_role.assert_called_once()