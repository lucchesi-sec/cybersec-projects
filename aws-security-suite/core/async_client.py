"""
Async AWS client abstraction for unified sync/async operations.
Provides compatibility layer between boto3 and aioboto3.
"""

import asyncio
import aioboto3
import boto3
from typing import Optional, Dict, Any, Union, List
from dataclasses import dataclass
import logging
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


@dataclass
class ClientConfig:
    """Configuration for AWS clients."""
    service_name: str
    region_name: str
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    profile_name: Optional[str] = None
    role_arn: Optional[str] = None
    external_id: Optional[str] = None


class AsyncAWSClient:
    """
    Unified AWS client that provides both sync and async interfaces.
    
    This class abstracts the differences between boto3 and aioboto3,
    allowing plugins to work with either synchronous or asynchronous
    patterns seamlessly.
    """
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self._session = None
        self._async_session = None
        self._sync_client = None
        self._async_client = None
        
    @property
    def session(self) -> boto3.Session:
        """Get or create synchronous boto3 session."""
        if self._session is None:
            if self.config.profile_name:
                self._session = boto3.Session(profile_name=self.config.profile_name)
            else:
                self._session = boto3.Session(
                    aws_access_key_id=self.config.aws_access_key_id,
                    aws_secret_access_key=self.config.aws_secret_access_key,
                    aws_session_token=self.config.aws_session_token,
                    region_name=self.config.region_name
                )
        return self._session
    
    @property
    def async_session(self) -> aioboto3.Session:
        """Get or create asynchronous aioboto3 session."""
        if self._async_session is None:
            if self.config.profile_name:
                self._async_session = aioboto3.Session(profile_name=self.config.profile_name)
            else:
                self._async_session = aioboto3.Session(
                    aws_access_key_id=self.config.aws_access_key_id,
                    aws_secret_access_key=self.config.aws_secret_access_key,
                    aws_session_token=self.config.aws_session_token,
                    region_name=self.config.region_name
                )
        return self._async_session
    
    def get_sync_client(self) -> Any:
        """Get synchronous AWS service client."""
        if self._sync_client is None:
            if self.config.role_arn:
                self._sync_client = self._create_assumed_role_sync_client()
            else:
                self._sync_client = self.session.client(
                    self.config.service_name,
                    region_name=self.config.region_name
                )
        return self._sync_client
    
    @asynccontextmanager
    async def get_async_client(self):
        """Get asynchronous AWS service client as context manager."""
        if self.config.role_arn:
            async with self._create_assumed_role_async_client() as client:
                yield client
        else:
            async with self.async_session.client(
                self.config.service_name,
                region_name=self.config.region_name
            ) as client:
                yield client
    
    def _create_assumed_role_sync_client(self):
        """Create synchronous client with assumed role credentials."""
        sts_client = self.session.client('sts', region_name=self.config.region_name)
        
        assume_role_params = {
            'RoleArn': self.config.role_arn,
            'RoleSessionName': 'aws-security-suite-sync'
        }
        
        if self.config.external_id:
            assume_role_params['ExternalId'] = self.config.external_id
        
        try:
            assumed_role = sts_client.assume_role(**assume_role_params)
            credentials = assumed_role['Credentials']
            
            return boto3.client(
                self.config.service_name,
                region_name=self.config.region_name,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        except Exception as e:
            logger.error(f"Failed to assume role {self.config.role_arn}: {e}")
            raise
    
    @asynccontextmanager
    async def _create_assumed_role_async_client(self):
        """Create asynchronous client with assumed role credentials."""
        async with self.async_session.client('sts', region_name=self.config.region_name) as sts_client:
            assume_role_params = {
                'RoleArn': self.config.role_arn,
                'RoleSessionName': 'aws-security-suite-async'
            }
            
            if self.config.external_id:
                assume_role_params['ExternalId'] = self.config.external_id
            
            try:
                assumed_role = await sts_client.assume_role(**assume_role_params)
                credentials = assumed_role['Credentials']
                
                # Create temporary session with assumed role credentials
                temp_session = aioboto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken'],
                    region_name=self.config.region_name
                )
                
                async with temp_session.client(self.config.service_name) as client:
                    yield client
                    
            except Exception as e:
                logger.error(f"Failed to assume role {self.config.role_arn}: {e}")
                raise


class AsyncClientManager:
    """
    Manager for multiple AWS service clients with unified async/sync interface.
    
    This class manages a pool of AWS clients and provides methods to execute
    operations either synchronously or asynchronously depending on the context.
    """
    
    def __init__(self):
        self._clients: Dict[str, AsyncAWSClient] = {}
        self._default_config: Optional[ClientConfig] = None
    
    def set_default_config(self, config: ClientConfig) -> None:
        """Set default configuration for new clients."""
        self._default_config = config
    
    def get_client(self, service_name: str, region_name: str = None, 
                   config: ClientConfig = None) -> AsyncAWSClient:
        """Get or create a client for the specified service and region."""
        region = region_name or (self._default_config.region_name if self._default_config else 'us-east-1')
        client_key = f"{service_name}:{region}"
        
        if client_key not in self._clients:
            if config is None:
                if self._default_config is None:
                    raise ValueError("No default config set and no config provided")
                client_config = ClientConfig(
                    service_name=service_name,
                    region_name=region,
                    aws_access_key_id=self._default_config.aws_access_key_id,
                    aws_secret_access_key=self._default_config.aws_secret_access_key,
                    aws_session_token=self._default_config.aws_session_token,
                    profile_name=self._default_config.profile_name,
                    role_arn=self._default_config.role_arn,
                    external_id=self._default_config.external_id
                )
            else:
                client_config = config
            
            self._clients[client_key] = AsyncAWSClient(client_config)
        
        return self._clients[client_key]
    
    async def execute_async(self, service_name: str, method_name: str, 
                          region_name: str = None, **kwargs) -> Dict[str, Any]:
        """Execute an AWS API call asynchronously."""
        client_wrapper = self.get_client(service_name, region_name)
        
        async with client_wrapper.get_async_client() as client:
            method = getattr(client, method_name)
            response = await method(**kwargs)
            return response
    
    def execute_sync(self, service_name: str, method_name: str, 
                    region_name: str = None, **kwargs) -> Dict[str, Any]:
        """Execute an AWS API call synchronously."""
        client_wrapper = self.get_client(service_name, region_name)
        client = client_wrapper.get_sync_client()
        method = getattr(client, method_name)
        response = method(**kwargs)
        return response
    
    async def batch_execute_async(self, operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute multiple AWS API calls concurrently."""
        tasks = []
        for op in operations:
            task = self.execute_async(
                service_name=op['service'],
                method_name=op['method'],
                region_name=op.get('region'),
                **op.get('kwargs', {})
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    
    def clear_cache(self) -> None:
        """Clear all cached clients."""
        self._clients.clear()


# Global client manager instance
_client_manager = AsyncClientManager()


def get_client_manager() -> AsyncClientManager:
    """Get the global client manager instance."""
    return _client_manager


def configure_default_client(
    region_name: str = 'us-east-1',
    profile_name: Optional[str] = None,
    role_arn: Optional[str] = None,
    external_id: Optional[str] = None,
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None
) -> None:
    """Configure default client settings."""
    config = ClientConfig(
        service_name='',  # Will be set per service
        region_name=region_name,
        profile_name=profile_name,
        role_arn=role_arn,
        external_id=external_id,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token
    )
    _client_manager.set_default_config(config)