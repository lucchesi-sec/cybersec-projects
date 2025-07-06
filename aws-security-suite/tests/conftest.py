"""
Pytest configuration and fixtures for AWS Security Suite tests.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any, Optional
import boto3
from moto import mock_aws
import sys
import os

# SECURITY: Validate path before insertion to prevent path traversal
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.isdir(parent_dir) and 'aws-security-suite' in parent_dir:
    sys.path.insert(0, parent_dir)
else:
    raise ValueError("Invalid project directory structure")

from core.audit_context import AuditContext
from core.async_client import AsyncClientManager, ClientConfig


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials to prevent accidental real API calls."""
    # SECURITY: Use environment variables or mock credentials - never hardcode
    test_env = {
        'AWS_ACCESS_KEY_ID': os.getenv('TEST_AWS_ACCESS_KEY_ID', 'mock-access-key'),
        'AWS_SECRET_ACCESS_KEY': os.getenv('TEST_AWS_SECRET_ACCESS_KEY', 'mock-secret-key'),
        'AWS_SECURITY_TOKEN': os.getenv('TEST_AWS_SECURITY_TOKEN', 'mock-token'),
        'AWS_SESSION_TOKEN': os.getenv('TEST_AWS_SESSION_TOKEN', 'mock-session-token'),
        'AWS_DEFAULT_REGION': 'us-east-1'
    }
    with patch.dict(os.environ, test_env):
        yield


@pytest.fixture
def audit_context(mock_aws_credentials):
    """Create a basic audit context for testing."""
    return AuditContext(
        region="us-east-1",
        regions=["us-east-1", "us-west-2"],
        services=["s3", "ec2", "iam"],
        enable_rate_limiting=False,  # Disable for tests
        request_tracking=False  # Disable for tests
    )


@pytest.fixture
def async_audit_context(mock_aws_credentials):
    """Create an audit context with async capabilities."""
    context = AuditContext(
        region="us-east-1",
        regions=["us-east-1", "us-west-2"],
        services=["s3", "ec2", "iam"],
        enable_rate_limiting=False,
        request_tracking=False
    )
    return context


@pytest.fixture
def client_config():
    """Create a basic client configuration."""
    # SECURITY: Use mock credentials from environment
    return ClientConfig(
        service_name="s3",
        region_name="us-east-1",
        aws_access_key_id=os.getenv('TEST_AWS_ACCESS_KEY_ID', 'mock-access-key'),
        aws_secret_access_key=os.getenv('TEST_AWS_SECRET_ACCESS_KEY', 'mock-secret-key')
    )


@pytest.fixture
def async_client_manager():
    """Create an async client manager for testing."""
    return AsyncClientManager()


@pytest.fixture
def mock_s3_client():
    """Mock S3 client with common methods."""
    client = Mock()
    client.list_buckets.return_value = {
        'Buckets': [
            {'Name': 'test-bucket-1', 'CreationDate': '2023-01-01'},
            {'Name': 'test-bucket-2', 'CreationDate': '2023-01-02'}
        ]
    }
    client.get_bucket_acl.return_value = {
        'Grants': [
            {
                'Grantee': {'Type': 'CanonicalUser', 'ID': 'test-id'},
                'Permission': 'FULL_CONTROL'
            }
        ]
    }
    return client


@pytest.fixture
def mock_async_s3_client():
    """Mock async S3 client with common methods."""
    client = AsyncMock()
    client.list_buckets.return_value = {
        'Buckets': [
            {'Name': 'test-bucket-1', 'CreationDate': '2023-01-01'},
            {'Name': 'test-bucket-2', 'CreationDate': '2023-01-02'}
        ]
    }
    client.get_bucket_acl.return_value = {
        'Grants': [
            {
                'Grantee': {'Type': 'CanonicalUser', 'ID': 'test-id'},
                'Permission': 'FULL_CONTROL'
            }
        ]
    }
    return client


@pytest.fixture
def mock_ec2_resources():
    """Create mock EC2 resources for testing."""
    return {
        'Instances': [
            {
                'InstanceId': 'i-1234567890abcdef0',
                'InstanceType': 't2.micro',
                'State': {'Name': 'running'},
                'PublicIpAddress': '1.2.3.4',
                'SecurityGroups': [
                    {'GroupId': 'sg-12345678', 'GroupName': 'default'}
                ]
            }
        ],
        'SecurityGroups': [
            {
                'GroupId': 'sg-12345678',
                'GroupName': 'default',
                'Description': 'Default security group',
                'IpPermissions': [
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            }
        ]
    }


@pytest.fixture
def mock_iam_resources():
    """Create mock IAM resources for testing."""
    return {
        'Users': [
            {
                'UserName': 'test-user',
                'UserId': 'AIDACKCEVSQ6C2EXAMPLE',
                'Arn': 'arn:aws:iam::123456789012:user/test-user',
                'CreateDate': '2023-01-01T00:00:00Z'
            }
        ],
        'Roles': [
            {
                'RoleName': 'test-role',
                'RoleId': 'AROADBQP57FF2AEXAMPLE',
                'Arn': 'arn:aws:iam::123456789012:role/test-role',
                'CreateDate': '2023-01-01T00:00:00Z'
            }
        ]
    }


@pytest.fixture
def moto_aws_services():
    """Mock all AWS services used in tests."""
    with mock_aws():
        yield


class MockAsyncResponse:
    """Mock async response for testing."""
    
    def __init__(self, data: Dict[str, Any]):
        self.data = data
    
    async def __aenter__(self):
        return self.data
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture
def mock_async_response():
    """Factory for creating mock async responses."""
    def _create_response(data: Dict[str, Any]):
        return MockAsyncResponse(data)
    return _create_response


# Test utilities
def create_test_finding(service="s3", check_id="TEST_CHECK", severity="HIGH"):
    """Create a test finding for validation."""
    from core.finding import Finding, Severity, Status
    
    return Finding(
        service=service,
        resource_id=f"arn:aws:{service}:::test-resource",
        resource_name="test-resource",
        check_id=check_id,
        check_title=f"Test {check_id}",
        status=Status.FAIL,
        severity=getattr(Severity, severity),
        region="us-east-1",
        account_id="123456789012",
        description="Test finding description",
        recommendation="Test recommendation"
    )


# Markers for different test types
pytestmark = [
    pytest.mark.asyncio
]