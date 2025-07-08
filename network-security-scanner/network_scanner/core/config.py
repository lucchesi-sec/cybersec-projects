"""
Network Scanner Configuration Management

Centralized configuration for all scanner operations with security validation.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union
import re
import ipaddress
from pathlib import Path


@dataclass
class ScannerConfig:
    """Configuration for network scanner operations."""
    
    # Target configuration
    targets: List[str] = field(default_factory=list)
    target_file: Optional[Path] = None
    exclude_targets: List[str] = field(default_factory=list)
    
    # Scan parameters
    port_range: str = "1-1000"
    scan_type: str = "tcp"  # tcp, udp, syn, connect
    scan_speed: int = 3  # 1-5 (paranoid to insane)
    max_parallel: int = 50
    
    # Timing and rate limiting
    scan_delay: float = 0.0
    max_rate: int = 1000  # packets per second
    timeout: int = 30
    max_retries: int = 3
    
    # Detection and stealth
    stealth_mode: bool = False
    randomize_hosts: bool = False
    fragment_packets: bool = False
    decoy_addresses: List[str] = field(default_factory=list)
    
    # Service detection
    service_detection: bool = True
    version_detection: bool = False
    os_detection: bool = False
    
    # Vulnerability scanning
    vuln_scan: bool = False
    vuln_scripts: List[str] = field(default_factory=list)
    
    # SSL/TLS configuration
    ssl_scan: bool = False
    check_certificates: bool = True
    check_weak_ciphers: bool = True
    
    # Output configuration
    output_format: str = "json"  # json, xml, csv, html
    output_file: Optional[Path] = None
    verbose: bool = False
    debug: bool = False
    
    # Compliance and reporting
    compliance_framework: str = "nist"  # nist, owasp, cis, pci
    generate_report: bool = True
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate_targets()
        self._validate_ports()
        self._validate_timing()
        self._validate_paths()
    
    def _validate_targets(self):
        """Validate target specifications."""
        validated_targets = []
        
        for target in self.targets:
            if self._is_valid_target(target):
                validated_targets.append(target)
            else:
                raise ValueError(f"Invalid target specification: {target}")
        
        self.targets = validated_targets
    
    def _is_valid_target(self, target: str) -> bool:
        """Check if target is a valid IP, CIDR, or hostname."""
        # Remove protocol if present
        target = re.sub(r'^https?://', '', target)
        target = target.split('/')[0]  # Remove path
        target = target.split(':')[0]  # Remove port
        
        # Check if it's a valid IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Check if it's a valid CIDR notation
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
        
        # Check if it's a valid hostname
        hostname_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        )
        
        return bool(hostname_pattern.match(target))
    
    def _validate_ports(self):
        """Validate port range specification."""
        if '-' in self.port_range:
            start, end = self.port_range.split('-', 1)
            try:
                start_port = int(start)
                end_port = int(end)
                
                if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                    raise ValueError("Port numbers must be between 1 and 65535")
                
                if start_port > end_port:
                    raise ValueError("Start port must be less than or equal to end port")
                    
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Invalid port range format: {self.port_range}")
                raise
        else:
            # Single port or comma-separated ports
            ports = self.port_range.split(',')
            for port in ports:
                try:
                    port_num = int(port.strip())
                    if not (1 <= port_num <= 65535):
                        raise ValueError(f"Port {port_num} is out of valid range (1-65535)")
                except ValueError:
                    raise ValueError(f"Invalid port specification: {port}")
    
    def _validate_timing(self):
        """Validate timing and rate limiting parameters."""
        if not (1 <= self.scan_speed <= 5):
            raise ValueError("Scan speed must be between 1 (paranoid) and 5 (insane)")
        
        if self.scan_delay < 0:
            raise ValueError("Scan delay cannot be negative")
        
        if self.max_rate <= 0:
            raise ValueError("Max rate must be positive")
        
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")
        
        if self.max_retries < 0:
            raise ValueError("Max retries cannot be negative")
        
        if self.max_parallel <= 0:
            raise ValueError("Max parallel connections must be positive")
    
    def _validate_paths(self):
        """Validate file paths."""
        if self.target_file and not self.target_file.exists():
            raise ValueError(f"Target file does not exist: {self.target_file}")
        
        if self.output_file:
            # Ensure parent directory exists
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
    
    def get_port_list(self) -> List[int]:
        """Convert port range specification to list of ports."""
        ports = []
        
        if '-' in self.port_range:
            start, end = map(int, self.port_range.split('-', 1))
            ports.extend(range(start, end + 1))
        else:
            # Handle comma-separated ports
            for port_spec in self.port_range.split(','):
                ports.append(int(port_spec.strip()))
        
        return sorted(set(ports))  # Remove duplicates and sort
    
    def load_targets_from_file(self) -> List[str]:
        """Load targets from file."""
        if not self.target_file:
            return []
        
        targets = []
        with open(self.target_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if self._is_valid_target(line):
                        targets.append(line)
                    else:
                        print(f"Warning: Skipping invalid target: {line}")
        
        return targets
    
    def is_target_excluded(self, target: str) -> bool:
        """Check if target should be excluded from scanning."""
        for exclude in self.exclude_targets:
            if target == exclude:
                return True
            
            # Check if exclude is a network and target is in it
            try:
                network = ipaddress.ip_network(exclude, strict=False)
                target_ip = ipaddress.ip_address(target)
                if target_ip in network:
                    return True
            except ValueError:
                # Not IP/network, do string comparison
                continue
        
        return False
    
    def get_scan_arguments(self) -> Dict[str, any]:
        """Get nmap-compatible scan arguments."""
        args = {
            'ports': self.port_range,
            'arguments': []
        }
        
        # Scan type
        if self.scan_type == 'syn':
            args['arguments'].append('-sS')
        elif self.scan_type == 'connect':
            args['arguments'].append('-sT')
        elif self.scan_type == 'udp':
            args['arguments'].append('-sU')
        
        # Timing
        args['arguments'].append(f'-T{self.scan_speed}')
        
        # Service detection
        if self.service_detection:
            args['arguments'].append('-sV')
        
        # OS detection
        if self.os_detection:
            args['arguments'].append('-O')
        
        # Stealth options
        if self.stealth_mode:
            args['arguments'].append('-f')  # Fragment packets
            if self.decoy_addresses:
                decoys = ','.join(self.decoy_addresses)
                args['arguments'].append(f'-D {decoys}')
        
        # Rate limiting
        if self.max_rate < 1000:
            args['arguments'].append(f'--max-rate {self.max_rate}')
        
        return args