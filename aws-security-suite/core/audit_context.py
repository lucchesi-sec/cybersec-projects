"""
AWS audit context for managing credentials and sessions.
Enhanced for enterprise environments with cross-account support.
"""

import boto3
import asyncio
import re
import os
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass, field
import logging
from .rate_limiter import get_rate_limiter
from .async_client import AsyncClientManager, ClientConfig, configure_default_client

logger = logging.getLogger(__name__)


# SECURITY: Define validation patterns for AWS resources
ARN_PATTERN = re.compile(r'^arn:(aws|aws-cn|aws-us-gov):.*')
ACCOUNT_ID_PATTERN = re.compile(r'^\d{12}$')
REGION_PATTERN = re.compile(r'^[a-z]{2}-[a-z]+-\d{1}$')
PARTITION_PATTERN = re.compile(r'^(aws|aws-cn|aws-us-gov)$')


@dataclass
class AuditContext:
    """Manages AWS credentials, sessions, and audit metadata for enterprise environments."""
    
    # AWS Configuration
    profile_name: Optional[str] = None
    region: str = "us-east-1"
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    partition: str = "aws"  # Support for aws-gov, aws-cn
    
    def __post_init__(self):
        """SECURITY: Validate all inputs after initialization."""
        self._validate_inputs()
    
    # Enterprise features
    delegated_admin_account: Optional[str] = None
    organization_role_name: Optional[str] = None
    max_concurrent_regions: int = 5
    
    # Scan Configuration
    regions: List[str] = None
    services: List[str] = None
    
    # Rate limiting
    enable_rate_limiting: bool = True
    custom_rate_limits: Dict[str, float] = field(default_factory=dict)
    
    # Audit trail
    request_tracking: bool = True
    evidence_collection: bool = True
    
    # Internal state
    _session: Optional[boto3.Session] = None
    _account_id: Optional[str] = None
    _partition_info: Optional[Dict[str, str]] = None
    _rate_limiter = None
    _async_client_manager: Optional[AsyncClientManager] = None
    
    def _validate_inputs(self):
        """SECURITY: Validate all input parameters to prevent injection attacks."""
        # Validate region format
        if self.region and not REGION_PATTERN.match(self.region):
            raise ValueError(f"Invalid region format: {self.region}")
        
        # Validate partition
        if self.partition and not PARTITION_PATTERN.match(self.partition):
            raise ValueError(f"Invalid partition: {self.partition}")
        
        # Validate role ARN if provided
        if self.role_arn and not ARN_PATTERN.match(self.role_arn):
            raise ValueError(f"Invalid role ARN format: {self.role_arn}")
        
        # Validate external ID (if provided, should be alphanumeric)
        if self.external_id and not re.match(r'^[A-Za-z0-9_-]+$', self.external_id):
            raise ValueError("External ID contains invalid characters")
        
        # Validate delegated admin account ID
        if self.delegated_admin_account and not ACCOUNT_ID_PATTERN.match(self.delegated_admin_account):
            raise ValueError(f"Invalid account ID format: {self.delegated_admin_account}")
        
        # Validate organization role name
        if self.organization_role_name and not re.match(r'^[A-Za-z0-9_+=,.@-]+$', self.organization_role_name):
            raise ValueError("Organization role name contains invalid characters")
        
        # Validate regions list
        if self.regions:
            for region in self.regions:
                if not REGION_PATTERN.match(region):
                    raise ValueError(f"Invalid region in list: {region}")
        
        # Validate max concurrent regions
        if not isinstance(self.max_concurrent_regions, int) or self.max_concurrent_regions < 1 or self.max_concurrent_regions > 20:
            raise ValueError("max_concurrent_regions must be between 1 and 20")
        
        # Ensure profile name doesn't contain path traversal
        if self.profile_name and ('/' in self.profile_name or '\\' in self.profile_name):
            raise ValueError("Profile name contains invalid path characters")
    
    def _sanitize_environment(self):
        """SECURITY: Remove sensitive environment variables from logs."""
        sensitive_env_vars = [
            'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
            'AWS_SECURITY_TOKEN', 'AWS_PROFILE'
        ]
        return {k: v for k, v in os.environ.items() if k not in sensitive_env_vars}
    
    def __post_init__(self):
        if self.regions is None:
            self.regions = [self.region]
        if self.services is None:
            self.services = []
        
        # Initialize async client manager
        self._setup_async_client_manager()
    
    @property
    def session(self) -> boto3.Session:
        """Get or create boto3 session."""
        if self._session is None:
            if self.profile_name:
                self._session = boto3.Session(profile_name=self.profile_name)
            else:
                self._session = boto3.Session()
        return self._session
    
    @property
    def account_id(self) -> str:
        """Get AWS account ID."""
        if self._account_id is None:
            try:
                sts = self.session.client('sts', region_name=self.region)
                identity = sts.get_caller_identity()
                self._account_id = identity['Account']
            except Exception as e:
                logging.error(f"Failed to get account ID: {e}")
                self._account_id = "unknown"
        return self._account_id
    
    @property
    def rate_limiter(self):
        """Get rate limiter instance."""
        if self._rate_limiter is None and self.enable_rate_limiting:
            self._rate_limiter = get_rate_limiter()
            # Apply custom rate limits
            for service, rate in self.custom_rate_limits.items():
                self._rate_limiter.set_service_rate(service, rate)
        return self._rate_limiter
    
    @property
    def async_client_manager(self) -> AsyncClientManager:
        """Get async client manager instance."""
        if self._async_client_manager is None:
            self._setup_async_client_manager()
        return self._async_client_manager
    
    def _setup_async_client_manager(self):
        """Initialize async client manager with current context settings."""
        self._async_client_manager = AsyncClientManager()
        
        # Configure default client settings based on current context
        config = ClientConfig(
            service_name='',  # Will be set per service
            region_name=self.region,
            profile_name=self.profile_name,
            role_arn=self.role_arn,
            external_id=self.external_id
        )
        self._async_client_manager.set_default_config(config)
    
    def get_client(self, service: str, region: str = None):
        """Get AWS service client for specific region with enterprise features."""
        target_region = region or self.region
        
        # Handle different authentication paths
        client = self._create_service_client(service, target_region)
        
        # Add request tracking if enabled
        if self.request_tracking:
            self._add_request_tracking(client, service, target_region)
        
        return client
    
    def _create_service_client(self, service: str, region: str):
        """Create AWS service client with appropriate credentials."""
        if self.role_arn:
            return self._create_assumed_role_client(service, region)
        elif self.delegated_admin_account:
            return self._create_cross_account_client(service, region)
        else:
            return self.session.client(service, region_name=region)
    
    def _create_assumed_role_client(self, service: str, region: str):
        """Create client using assumed role credentials."""
        sts = self.session.client('sts', region_name=region)
        
        assume_role_params = {
            'RoleArn': self.role_arn,
            'RoleSessionName': 'aws-security-suite'
        }
        
        if self.external_id:
            assume_role_params['ExternalId'] = self.external_id
        
        try:
            assumed_role = sts.assume_role(**assume_role_params)
            credentials = assumed_role['Credentials']
            
            return boto3.client(
                service,
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        except Exception as e:
            logger.error(f"Failed to assume role {self.role_arn}: {e}")
            raise
    
    def _create_cross_account_client(self, service: str, region: str):
        """Create client for cross-account access via Organizations."""
        if not self.organization_role_name:
            self.organization_role_name = "OrganizationAccountAccessRole"
        
        role_arn = f"arn:{self.partition}:iam::{self.delegated_admin_account}:role/{self.organization_role_name}"
        
        # Temporarily set role_arn for cross-account access
        original_role = self.role_arn
        self.role_arn = role_arn
        
        try:
            client = self._create_assumed_role_client(service, region)
            return client
        finally:
            self.role_arn = original_role
    
    def _add_request_tracking(self, client, service: str, region: str):
        """Add request tracking for audit trail."""
        if hasattr(client, 'meta') and hasattr(client.meta, 'events'):
            def log_request(event_name=None, **kwargs):
                if self.evidence_collection:
                    logger.debug(
                        f"AWS API Call: {service}.{event_name} in {region}",
                        extra={
                            'service': service,
                            'region': region,
                            'account_id': self.account_id,
                            'operation': event_name,
                            'request_id': kwargs.get('ResponseMetadata', {}).get('RequestId')
                        }
                    )
            
            client.meta.events.register('after-call.*', log_request)
    
    async def get_rate_limited_client(self, service: str, region: str = None, tokens: int = 1):
        """Get client with rate limiting applied."""
        if self.enable_rate_limiting and self.rate_limiter:
            await self.rate_limiter.acquire_tokens(service, tokens)
        
        return self.get_client(service, region)
    
    async def get_async_client(self, service: str, region: str = None):
        """Get async AWS service client."""
        target_region = region or self.region
        client_wrapper = self.async_client_manager.get_client(service, target_region)
        return client_wrapper.get_async_client()
    
    async def execute_async(self, service: str, method: str, region: str = None, **kwargs):
        """Execute AWS API call asynchronously with rate limiting."""
        if self.enable_rate_limiting and self.rate_limiter:
            await self.rate_limiter.acquire_tokens(service, 1)
        
        target_region = region or self.region
        return await self.async_client_manager.execute_async(
            service_name=service,
            method_name=method,
            region_name=target_region,
            **kwargs
        )
    
    async def batch_execute_async(self, operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute multiple AWS API calls concurrently with rate limiting."""
        # Apply rate limiting per operation
        if self.enable_rate_limiting and self.rate_limiter:
            for op in operations:
                await self.rate_limiter.acquire_tokens(op['service'], 1)
        
        return await self.async_client_manager.batch_execute_async(operations)
    
    def get_partition_info(self) -> Dict[str, str]:
        """Get AWS partition information."""
        if self._partition_info is None:
            self._partition_info = {
                "partition": self.partition,
                "dns_suffix": "amazonaws.com" if self.partition == "aws" else f"amazonaws.com.{self.partition}",
                "service_prefix": "" if self.partition == "aws" else f"{self.partition}-"
            }
        return self._partition_info
    
    def supports_service_in_region(self, service: str, region: str) -> bool:
        """Check if service is available in specific region/partition."""
        # Basic service availability check - can be enhanced with actual AWS API
        unavailable_combinations = {
            "aws-gov": ["organizations", "trustedadvisor"],
            "aws-cn": ["organizations", "inspector", "macie"]
        }
        
        if self.partition in unavailable_combinations:
            return service not in unavailable_combinations[self.partition]
        
        return True
    
    def get_available_regions(self, service: str = "ec2") -> List[str]:
        """Get list of available regions for the partition."""
        try:
            client = self.get_client(service)
            response = client.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except Exception as e:
            logger.warning(f"Could not determine available regions: {e}")
            # Return common regions as fallback
            if self.partition == "aws-gov":
                return ["us-gov-east-1", "us-gov-west-1"]
            elif self.partition == "aws-cn":
                return ["cn-north-1", "cn-northwest-1"]
            else:
                return [
                    "us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
                    "ap-southeast-1", "ap-northeast-1"
                ]