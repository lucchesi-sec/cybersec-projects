"""
Security validation utilities for safe scanning operations.
"""

import re
import ipaddress
from typing import List, Set
import logging


class SecurityValidator:
    """Security validation for scanning targets and operations."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Define forbidden networks and addresses
        self.forbidden_networks = [
            # Loopback
            ipaddress.ip_network('127.0.0.0/8'),
            
            # Link-local
            ipaddress.ip_network('169.254.0.0/16'),
            
            # Multicast
            ipaddress.ip_network('224.0.0.0/4'),
            
            # Reserved/Special use
            ipaddress.ip_network('0.0.0.0/8'),
            ipaddress.ip_network('240.0.0.0/4'),
        ]
        
        # Critical infrastructure networks (examples - would be more comprehensive)
        self.critical_networks = [
            # DNS root servers (example ranges)
            ipaddress.ip_network('198.41.0.0/24'),  # a.root-servers.net
            ipaddress.ip_network('199.9.14.0/24'),  # b.root-servers.net
            
            # Known critical infrastructure (would be expanded)
            # These are examples and should be configured based on organization
        ]
        
        # Domains that should never be scanned
        self.forbidden_domains = {
            'localhost',
            '*.gov',  # Government domains
            '*.mil',  # Military domains
            '*.edu',  # Educational institutions (be careful)
        }
    
    def is_safe_target(self, target: str) -> bool:
        """
        Validate that target is safe to scan.
        
        Args:
            target: Target hostname or IP address
            
        Returns:
            True if target is considered safe to scan
        """
        try:
            # Remove protocol and path if present
            clean_target = self._clean_target(target)
            
            # Check if it's an IP address
            try:
                ip = ipaddress.ip_address(clean_target)
                return self._is_safe_ip(ip)
            except ValueError:
                # It's a hostname
                return self._is_safe_hostname(clean_target)
                
        except Exception as e:
            self.logger.warning(f"Error validating target {target}: {e}")
            return False
    
    def _clean_target(self, target: str) -> str:
        """Clean target specification to extract hostname/IP."""
        # Remove protocol
        target = re.sub(r'^https?://', '', target)
        
        # Remove path
        target = target.split('/')[0]
        
        # Remove port
        if ':' in target and not target.count(':') > 1:  # Not IPv6
            target = target.split(':')[0]
        
        return target.strip()
    
    def _is_safe_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Check if IP address is safe to scan."""
        # Check against forbidden networks
        for network in self.forbidden_networks:
            if ip in network:
                self.logger.warning(f"IP {ip} is in forbidden network {network}")
                return False
        
        # Check against critical infrastructure
        for network in self.critical_networks:
            if ip in network:
                self.logger.warning(f"IP {ip} is in critical infrastructure network {network}")
                return False
        
        # Check for public IP addresses (additional safety check)
        if not ip.is_private and not ip.is_loopback:
            # For public IPs, add extra validation
            return self._validate_public_ip(ip)
        
        return True
    
    def _validate_public_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Additional validation for public IP addresses."""
        # Add any organization-specific rules for public IP scanning
        # For example, checking against threat intelligence feeds,
        # honeypot networks, or other restricted ranges
        
        # Placeholder for additional public IP validation
        return True
    
    def _is_safe_hostname(self, hostname: str) -> bool:
        """Check if hostname is safe to scan."""
        hostname_lower = hostname.lower()
        
        # Check against forbidden domains
        for forbidden in self.forbidden_domains:
            if forbidden.startswith('*'):
                domain_suffix = forbidden[1:]  # Remove *
                if hostname_lower.endswith(domain_suffix):
                    self.logger.warning(f"Hostname {hostname} matches forbidden pattern {forbidden}")
                    return False
            else:
                if hostname_lower == forbidden:
                    self.logger.warning(f"Hostname {hostname} is in forbidden list")
                    return False
        
        # Additional hostname validation
        return self._validate_hostname_pattern(hostname)
    
    def _validate_hostname_pattern(self, hostname: str) -> bool:
        """Validate hostname against suspicious patterns."""
        suspicious_patterns = [
            r'.*\.internal$',
            r'.*\.local$',
            r'.*\.corp$',
            r'.*\.intranet$',
            r'localhost.*',
            r'.*admin.*',
            r'.*test.*\.gov$',
            r'.*staging.*\.gov$',
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, hostname, re.IGNORECASE):
                self.logger.warning(f"Hostname {hostname} matches suspicious pattern {pattern}")
                # Return False for critical patterns, True for warnings
                if any(critical in pattern for critical in ['gov', 'internal', 'localhost']):
                    return False
        
        return True
    
    def validate_port_range(self, ports: List[int]) -> List[int]:
        """
        Validate and filter port range for safe scanning.
        
        Args:
            ports: List of ports to validate
            
        Returns:
            Filtered list of safe ports
        """
        # Define potentially sensitive ports
        sensitive_ports = {
            # System/privileged ports
            7, 9, 13, 17, 19,  # Echo, discard, daytime, qotd, chargen
            
            # Database ports (scan with caution)
            1433, 1521, 3306, 5432, 27017,
            
            # Management interfaces
            161, 623, 8080, 8443, 9090,
            
            # Industrial control systems
            102, 502, 2404, 44818, 47808,
        }
        
        safe_ports = []
        for port in ports:
            if 1 <= port <= 65535:
                if port in sensitive_ports:
                    self.logger.info(f"Including sensitive port {port} - ensure you have permission")
                safe_ports.append(port)
            else:
                self.logger.warning(f"Invalid port number: {port}")
        
        return safe_ports
    
    def check_scan_permissions(self, target: str) -> dict:
        """
        Check if scanning target requires special permissions.
        
        Args:
            target: Target to check
            
        Returns:
            Dictionary with permission requirements and warnings
        """
        result = {
            'safe_to_scan': True,
            'requires_permission': False,
            'warnings': [],
            'recommendations': []
        }
        
        try:
            # Check if target is external
            clean_target = self._clean_target(target)
            
            try:
                ip = ipaddress.ip_address(clean_target)
                if not ip.is_private:
                    result['requires_permission'] = True
                    result['warnings'].append("Target is on public internet")
                    result['recommendations'].append("Ensure you have explicit permission to scan this target")
                    
            except ValueError:
                # Hostname - check domain
                if not any(private in clean_target for private in ['.local', '.internal', '.corp']):
                    result['requires_permission'] = True
                    result['warnings'].append("Target appears to be external domain")
                    result['recommendations'].append("Verify you own this domain or have permission to scan")
            
            # Additional checks based on target characteristics
            if any(keyword in clean_target.lower() for keyword in ['bank', 'gov', 'mil', 'critical', 'infrastructure']):
                result['safe_to_scan'] = False
                result['warnings'].append("Target appears to be critical infrastructure")
                result['recommendations'].append("Do not scan - likely protected by law")
        
        except Exception as e:
            result['safe_to_scan'] = False
            result['warnings'].append(f"Error analyzing target: {e}")
        
        return result
    
    def get_safe_scanning_guidelines(self) -> List[str]:
        """Get guidelines for safe and ethical scanning."""
        return [
            "Only scan networks and systems you own or have explicit written permission to test",
            "Be mindful of scan timing and intensity to avoid disrupting services",
            "Document all scanning activities for audit purposes",
            "Respect rate limits and implement delays between requests",
            "Never attempt to exploit vulnerabilities found during scanning",
            "Report security issues through proper responsible disclosure channels",
            "Comply with local laws and regulations regarding security testing",
            "Consider the impact on target systems and users",
            "Use stealth options when testing detection capabilities",
            "Maintain confidentiality of any sensitive information discovered"
        ]