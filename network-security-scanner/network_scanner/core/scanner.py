"""
Network Security Scanner Core Engine

Main scanning engine with plugin architecture for extensible security assessments.
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import socket

try:
    import nmap
except ImportError:
    nmap = None

from .config import ScannerConfig
from ..utils.network_utils import NetworkUtils
from ..utils.validation import SecurityValidator


@dataclass
class ScanResult:
    """Container for scan results."""
    
    target: str
    scan_type: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Port scan results
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    filtered_ports: List[int] = field(default_factory=list)
    
    # Service information
    services: Dict[int, Dict[str, str]] = field(default_factory=dict)
    
    # Host information
    host_status: str = "unknown"
    operating_system: Optional[str] = None
    mac_address: Optional[str] = None
    
    # Vulnerability information
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    
    # SSL/TLS information
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    
    # Scan metadata
    scan_duration: float = 0.0
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    
    # Error information
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class NetworkScanner:
    """
    Main network security scanner with plugin architecture.
    
    Provides comprehensive network security assessment capabilities including
    port scanning, vulnerability detection, and security configuration analysis.
    """
    
    def __init__(self, config: ScannerConfig):
        """Initialize scanner with configuration."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.network_utils = NetworkUtils()
        self.validator = SecurityValidator()
        
        # Initialize nmap if available
        self.nm = None
        if nmap:
            self.nm = nmap.PortScanner()
        else:
            self.logger.warning("python-nmap not available, using basic scanning")
        
        # Plugin registry
        self._plugins = {}
        self._load_plugins()
        
        # Statistics
        self.scan_stats = {
            'hosts_scanned': 0,
            'ports_scanned': 0,
            'vulnerabilities_found': 0,
            'scan_start_time': None,
            'scan_end_time': None
        }
    
    def _load_plugins(self):
        """Load available scanner plugins."""
        # This would dynamically load plugins from the plugins directory
        # For now, we'll register built-in capabilities
        self._plugins = {
            'port_scan': self._port_scan,
            'service_detection': self._service_detection,
            'vulnerability_scan': self._vulnerability_scan,
            'ssl_scan': self._ssl_scan
        }
    
    async def scan_targets(self, targets: Optional[List[str]] = None) -> List[ScanResult]:
        """
        Scan multiple targets concurrently.
        
        Args:
            targets: List of targets to scan. If None, uses config targets.
            
        Returns:
            List of scan results for all targets.
        """
        if targets is None:
            targets = self.config.targets
            if self.config.target_file:
                targets.extend(self.config.load_targets_from_file())
        
        if not targets:
            raise ValueError("No targets specified for scanning")
        
        self.scan_stats['scan_start_time'] = datetime.now()
        self.logger.info(f"Starting scan of {len(targets)} targets")
        
        # Validate and filter targets
        valid_targets = []
        for target in targets:
            if not self.config.is_target_excluded(target):
                if self.validator.is_safe_target(target):
                    valid_targets.append(target)
                else:
                    self.logger.warning(f"Skipping potentially unsafe target: {target}")
            else:
                self.logger.info(f"Target excluded by configuration: {target}")
        
        # Create semaphore for concurrent scanning
        semaphore = asyncio.Semaphore(self.config.max_parallel)
        
        # Scan targets concurrently
        tasks = []
        for target in valid_targets:
            task = asyncio.create_task(
                self._scan_single_target(target, semaphore)
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and handle exceptions
        scan_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Scan failed for {valid_targets[i]}: {result}")
                # Create error result
                error_result = ScanResult(
                    target=valid_targets[i],
                    scan_type="error",
                    host_status="error"
                )
                error_result.errors.append(str(result))
                scan_results.append(error_result)
            else:
                scan_results.append(result)
        
        self.scan_stats['scan_end_time'] = datetime.now()
        self.scan_stats['hosts_scanned'] = len(scan_results)
        
        self.logger.info(f"Scan completed. Scanned {len(scan_results)} targets")
        return scan_results
    
    async def _scan_single_target(self, target: str, semaphore: asyncio.Semaphore) -> ScanResult:
        """
        Scan a single target with rate limiting.
        
        Args:
            target: Target to scan
            semaphore: Concurrency control semaphore
            
        Returns:
            Scan result for the target
        """
        async with semaphore:
            start_time = time.time()
            
            result = ScanResult(
                target=target,
                scan_type=self.config.scan_type,
                scan_start=datetime.now()
            )
            
            try:
                # Apply scan delay for rate limiting
                if self.config.scan_delay > 0:
                    await asyncio.sleep(self.config.scan_delay)
                
                # Check if host is up
                if await self._is_host_up(target):
                    result.host_status = "up"
                    
                    # Perform port scan
                    await self._execute_port_scan(target, result)
                    
                    # Perform service detection if enabled
                    if self.config.service_detection:
                        await self._execute_service_detection(target, result)
                    
                    # Perform vulnerability scan if enabled
                    if self.config.vuln_scan:
                        await self._execute_vulnerability_scan(target, result)
                    
                    # Perform SSL scan if enabled
                    if self.config.ssl_scan:
                        await self._execute_ssl_scan(target, result)
                
                else:
                    result.host_status = "down"
                    self.logger.debug(f"Host {target} appears to be down")
            
            except Exception as e:
                self.logger.error(f"Error scanning {target}: {e}")
                result.errors.append(str(e))
                result.host_status = "error"
            
            finally:
                result.scan_end = datetime.now()
                result.scan_duration = time.time() - start_time
            
            return result
    
    async def _is_host_up(self, target: str) -> bool:
        """
        Check if host is reachable.
        
        Args:
            target: Target to check
            
        Returns:
            True if host appears to be up
        """
        try:
            # Try to resolve hostname first
            loop = asyncio.get_event_loop()
            await loop.getaddrinfo(target, None)
            
            # Simple connectivity check
            return await self.network_utils.ping_host(target, timeout=self.config.timeout)
            
        except Exception as e:
            self.logger.debug(f"Host reachability check failed for {target}: {e}")
            return False
    
    async def _execute_port_scan(self, target: str, result: ScanResult):
        """Execute port scan on target."""
        if 'port_scan' in self._plugins:
            await self._plugins['port_scan'](target, result)
    
    async def _execute_service_detection(self, target: str, result: ScanResult):
        """Execute service detection on target."""
        if 'service_detection' in self._plugins:
            await self._plugins['service_detection'](target, result)
    
    async def _execute_vulnerability_scan(self, target: str, result: ScanResult):
        """Execute vulnerability scan on target."""
        if 'vulnerability_scan' in self._plugins:
            await self._plugins['vulnerability_scan'](target, result)
    
    async def _execute_ssl_scan(self, target: str, result: ScanResult):
        """Execute SSL/TLS scan on target."""
        if 'ssl_scan' in self._plugins:
            await self._plugins['ssl_scan'](target, result)
    
    # Plugin implementations
    
    async def _port_scan(self, target: str, result: ScanResult):
        """Basic port scanning implementation."""
        ports = self.config.get_port_list()
        self.scan_stats['ports_scanned'] += len(ports)
        
        if self.nm:
            # Use nmap for scanning
            await self._nmap_port_scan(target, result)
        else:
            # Use basic socket scanning
            await self._socket_port_scan(target, result, ports)
    
    async def _nmap_port_scan(self, target: str, result: ScanResult):
        """Port scan using nmap."""
        try:
            scan_args = self.config.get_scan_arguments()
            
            # Execute nmap scan in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            nmap_result = await loop.run_in_executor(
                None,
                lambda: self.nm.scan(
                    target,
                    ports=scan_args['ports'],
                    arguments=' '.join(scan_args['arguments'])
                )
            )
            
            # Process nmap results
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                
                # Extract port information
                for protocol in host_info.all_protocols():
                    ports = host_info[protocol].keys()
                    
                    for port in ports:
                        port_info = host_info[protocol][port]
                        port_data = {
                            'port': port,
                            'protocol': protocol,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                        }
                        
                        if port_info['state'] == 'open':
                            result.open_ports.append(port_data)
                            result.services[port] = {
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                            }
                        elif port_info['state'] == 'closed':
                            result.closed_ports.append(port)
                        elif port_info['state'] == 'filtered':
                            result.filtered_ports.append(port)
                
                # Extract OS information if available
                if 'osmatch' in host_info:
                    if host_info['osmatch']:
                        result.operating_system = host_info['osmatch'][0]['name']
        
        except Exception as e:
            self.logger.error(f"Nmap scan failed for {target}: {e}")
            result.errors.append(f"Nmap scan failed: {str(e)}")
    
    async def _socket_port_scan(self, target: str, result: ScanResult, ports: List[int]):
        """Basic socket-based port scan."""
        try:
            # Resolve target to IP
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(target, None)
            target_ip = addr_info[0][4][0]
            
            # Scan ports concurrently
            semaphore = asyncio.Semaphore(50)  # Limit concurrent connections
            tasks = []
            
            for port in ports:
                task = asyncio.create_task(
                    self._check_port(target_ip, port, semaphore)
                )
                tasks.append(task)
            
            port_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, port_result in enumerate(port_results):
                port = ports[i]
                
                if isinstance(port_result, Exception):
                    result.filtered_ports.append(port)
                elif port_result:
                    result.open_ports.append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': self._guess_service(port),
                        'version': '',
                        'product': '',
                    })
                else:
                    result.closed_ports.append(port)
        
        except Exception as e:
            self.logger.error(f"Socket scan failed for {target}: {e}")
            result.errors.append(f"Socket scan failed: {str(e)}")
    
    async def _check_port(self, target_ip: str, port: int, semaphore: asyncio.Semaphore) -> bool:
        """Check if a specific port is open."""
        async with semaphore:
            try:
                # Create connection with timeout
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port),
                    timeout=self.config.timeout
                )
                
                writer.close()
                await writer.wait_closed()
                return True
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return False
    
    def _guess_service(self, port: int) -> str:
        """Guess service based on well-known port numbers."""
        well_known_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            3389: 'rdp', 5432: 'postgresql', 3306: 'mysql',
            1433: 'mssql', 6379: 'redis', 27017: 'mongodb'
        }
        
        return well_known_ports.get(port, 'unknown')
    
    async def _service_detection(self, target: str, result: ScanResult):
        """Enhanced service detection for open ports."""
        # This would implement banner grabbing and service fingerprinting
        # For now, just placeholder
        pass
    
    async def _vulnerability_scan(self, target: str, result: ScanResult):
        """Basic vulnerability detection."""
        # This would implement vulnerability detection logic
        # For now, just placeholder
        pass
    
    async def _ssl_scan(self, target: str, result: ScanResult):
        """SSL/TLS configuration analysis."""
        # This would implement SSL/TLS analysis
        # For now, just placeholder
        pass
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan statistics."""
        return self.scan_stats.copy()