"""
Plugin system for AWS service scanners.
Provides stable enterprise-grade plugin interface with versioning support.
Enhanced with unified sync/async execution patterns.
"""

import asyncio
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Any, AsyncGenerator, Optional, Protocol, Union, Awaitable
from .finding import Finding
from .audit_context import AuditContext
import logging

# Plugin API version for compatibility tracking
PLUGIN_API_VERSION = "2.1.0"  # Incremented for async enhancements


def ensure_async(func_or_coro: Union[Callable, Awaitable]) -> Awaitable:
    """
    Ensure a function or coroutine is awaitable.
    Wraps sync functions to be compatible with async execution patterns.
    """
    if inspect.iscoroutine(func_or_coro):
        return func_or_coro
    elif inspect.iscoroutinefunction(func_or_coro):
        return func_or_coro()
    elif callable(func_or_coro):
        # Run sync function in thread pool to avoid blocking
        return asyncio.get_event_loop().run_in_executor(None, func_or_coro)
    else:
        # Already a result, wrap in completed future
        async def _immediate():
            return func_or_coro
        return _immediate()


def ensure_sync(func_or_coro: Union[Callable, Awaitable]) -> Any:
    """
    Ensure a function or coroutine returns a synchronous result.
    Runs async functions in event loop if needed.
    """
    if inspect.iscoroutine(func_or_coro):
        try:
            loop = asyncio.get_running_loop()
            # If we're already in an event loop, create a task
            return asyncio.create_task(func_or_coro)
        except RuntimeError:
            # No running loop, run in new loop
            return asyncio.run(func_or_coro)
    elif inspect.iscoroutinefunction(func_or_coro):
        return ensure_sync(func_or_coro())
    elif callable(func_or_coro):
        return func_or_coro()
    else:
        return func_or_coro


class ScannerPluginProtocol(Protocol):
    """Stable protocol interface for scanner plugins."""
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return plugin metadata including API version."""
        ...
    
    async def run_scan(self, context: AuditContext) -> List[Finding]:
        """Execute the security scan and return findings."""
        ...
    
    async def remediate(self, finding: Finding, context: AuditContext, dry_run: bool = True) -> Dict[str, Any]:
        """Attempt to remediate a specific finding."""
        ...


class PluginBase(ABC):
    """Abstract base class for all scanner plugins with stable interface."""
    
    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)
    
    @property
    @abstractmethod
    def service_name(self) -> str:
        """Return the AWS service name this plugin scans."""
        pass
    
    @property
    @abstractmethod
    def required_permissions(self) -> List[str]:
        """Return list of required AWS IAM permissions."""
        pass
    
    @property
    def plugin_api_version(self) -> str:
        """Return the plugin API version this plugin implements."""
        return PLUGIN_API_VERSION
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return comprehensive plugin metadata."""
        return {
            "service": self.service_name,
            "plugin_api_version": self.plugin_api_version,
            "required_permissions": self.required_permissions,
            "capabilities": self.get_capabilities(),
            "supported_regions": self.get_supported_regions(),
            "remediation_support": self.supports_remediation()
        }
    
    def get_capabilities(self) -> List[str]:
        """Return list of plugin capabilities."""
        capabilities = ["scan"]
        if self.supports_remediation():
            capabilities.append("remediate")
        return capabilities
    
    def get_supported_regions(self) -> List[str]:
        """Return list of supported AWS regions."""
        return []  # Empty means all regions
    
    def supports_remediation(self) -> bool:
        """Return True if plugin supports automated remediation."""
        return False
    
    @abstractmethod
    async def run_scan(self, context: AuditContext) -> List[Finding]:
        """Execute the security scan and return findings."""
        pass
    
    def run_scan_sync(self, context: AuditContext) -> List[Finding]:
        """Execute the security scan synchronously."""
        return ensure_sync(self.run_scan(context))
    
    async def remediate(self, finding: Finding, context: AuditContext, dry_run: bool = True) -> Dict[str, Any]:
        """Attempt to remediate a specific finding."""
        return {
            "success": False,
            "reason": "Remediation not implemented for this plugin",
            "dry_run": dry_run
        }
    
    def remediate_sync(self, finding: Finding, context: AuditContext, dry_run: bool = True) -> Dict[str, Any]:
        """Attempt to remediate a specific finding synchronously."""
        return ensure_sync(self.remediate(finding, context, dry_run))
    
    async def get_async_client(self, context: AuditContext, service: str = None, region: str = None):
        """
        Get async AWS client for the plugin's service.
        Convenience method that uses the context's async client manager.
        """
        target_service = service or self.service_name
        async with context.get_async_client(target_service, region) as client:
            yield client
    
    def get_sync_client(self, context: AuditContext, service: str = None, region: str = None):
        """
        Get synchronous AWS client for the plugin's service.
        Convenience method that uses the context's sync client methods.
        """
        target_service = service or self.service_name
        return context.get_client(target_service, region)
    
    async def execute_async_operations(self, context: AuditContext, operations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute multiple AWS operations concurrently.
        
        Args:
            context: Audit context with client management
            operations: List of operations with format:
                [{'method': 'list_buckets', 'kwargs': {...}, 'region': 'us-east-1'}, ...]
        
        Returns:
            List of operation results
        """
        formatted_operations = []
        for op in operations:
            formatted_op = {
                'service': self.service_name,
                'method': op['method'],
                'kwargs': op.get('kwargs', {}),
                'region': op.get('region')
            }
            formatted_operations.append(formatted_op)
        
        return await context.batch_execute_async(formatted_operations)


@dataclass
class ScannerPlugin:
    """Legacy plugin metadata and interface - DEPRECATED in favor of PluginBase."""
    service: str
    required_permissions: List[str]
    scan_function: Callable
    remediation_map: Dict[str, Callable] = None
    plugin_api_version: str = field(default=PLUGIN_API_VERSION)
    
    def __post_init__(self):
        if self.remediation_map is None:
            self.remediation_map = {}
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return plugin metadata for compatibility."""
        return {
            "service": self.service,
            "plugin_api_version": self.plugin_api_version,
            "required_permissions": self.required_permissions,
            "remediation_support": len(self.remediation_map) > 0,
            "capabilities": ["scan"] + (["remediate"] if self.remediation_map else [])
        }


class PluginRegistry:
    """Registry for managing scanner plugins."""
    
    def __init__(self):
        self._plugins: Dict[str, ScannerPlugin] = {}
        self.logger = logging.getLogger(__name__)
    
    def register(self, plugin: ScannerPlugin) -> None:
        """Register a scanner plugin."""
        self._plugins[plugin.service] = plugin
        self.logger.info(f"Registered plugin for service: {plugin.service}")
    
    def get_plugin(self, service: str) -> ScannerPlugin:
        """Get plugin for specific service."""
        if service not in self._plugins:
            raise ValueError(f"No plugin registered for service: {service}")
        return self._plugins[service]
    
    def list_services(self) -> List[str]:
        """List all registered services."""
        return list(self._plugins.keys())
    
    def get_required_permissions(self, services: List[str] = None) -> List[str]:
        """Get all required permissions for specified services."""
        if services is None:
            services = self.list_services()
        
        permissions = set()
        for service in services:
            if service in self._plugins:
                permissions.update(self._plugins[service].required_permissions)
        
        return sorted(list(permissions))