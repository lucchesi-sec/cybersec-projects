"""
Network utility functions for scanning operations.
"""

import asyncio
import socket
import struct
import subprocess
import platform
from typing import Optional, List, Tuple
import ipaddress


class NetworkUtils:
    """Utility functions for network operations."""
    
    def __init__(self):
        self.system = platform.system().lower()
    
    async def ping_host(self, host: str, timeout: int = 5) -> bool:
        """
        Ping a host to check connectivity.
        
        Args:
            host: Hostname or IP address
            timeout: Timeout in seconds
            
        Returns:
            True if host responds to ping
        """
        try:
            # Determine ping command based on OS
            if self.system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), host]
            
            # Execute ping command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            return_code = await process.wait()
            return return_code == 0
            
        except Exception:
            return False
    
    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """
        Resolve hostname to IP address.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            IP address or None if resolution fails
        """
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(hostname, None)
            return addr_info[0][4][0]
        except Exception:
            return None
    
    async def reverse_dns_lookup(self, ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Hostname or None if lookup fails
        """
        try:
            loop = asyncio.get_event_loop()
            hostname, _ = await loop.getnameinfo((ip_address, 0), 0)
            return hostname
        except Exception:
            return None
    
    def is_private_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is in private range.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is private
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except ValueError:
            return False
    
    def is_loopback_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is loopback.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is loopback
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_loopback
        except ValueError:
            return False
    
    def expand_cidr(self, cidr: str) -> List[str]:
        """
        Expand CIDR notation to list of IP addresses.
        
        Args:
            cidr: CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            List of IP addresses in the network
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []
    
    def get_network_interfaces(self) -> List[Tuple[str, str]]:
        """
        Get network interfaces and their IP addresses.
        
        Returns:
            List of (interface_name, ip_address) tuples
        """
        interfaces = []
        
        try:
            # This is a simplified implementation
            # In practice, you'd use libraries like psutil or netifaces
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            interfaces.append(("local", ip_address))
        except Exception:
            pass
        
        return interfaces
    
    async def check_tcp_port(self, host: str, port: int, timeout: int = 5) -> bool:
        """
        Check if TCP port is open.
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            
        Returns:
            True if port is open
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    async def grab_banner(self, host: str, port: int, timeout: int = 5) -> Optional[str]:
        """
        Grab service banner from open port.
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            
        Returns:
            Service banner or None
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Read banner (first few bytes)
            banner = await asyncio.wait_for(
                reader.read(1024),
                timeout=timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
            
        except Exception:
            return None
    
    def calculate_subnet_info(self, cidr: str) -> dict:
        """
        Calculate subnet information.
        
        Args:
            cidr: CIDR notation
            
        Returns:
            Dictionary with subnet information
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            return {
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'netmask': str(network.netmask),
                'num_addresses': network.num_addresses,
                'num_hosts': len(list(network.hosts())),
                'is_private': network.is_private,
                'is_multicast': network.is_multicast,
                'prefix_length': network.prefixlen
            }
        except ValueError:
            return {}
    
    def generate_port_ranges(self, port_spec: str) -> List[int]:
        """
        Generate list of ports from specification.
        
        Args:
            port_spec: Port specification (e.g., "80,443,8000-8010")
            
        Returns:
            List of port numbers
        """
        ports = []
        
        for part in port_spec.split(','):
            part = part.strip()
            
            if '-' in part:
                start, end = map(int, part.split('-', 1))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))  # Remove duplicates and sort