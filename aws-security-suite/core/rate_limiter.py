"""
Enterprise-grade rate limiting and throttling coordination for AWS API calls.
Implements token bucket algorithm with per-service rate limiting.
"""

import asyncio
import time
import logging
from typing import Dict, Optional
from dataclasses import dataclass, field
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


@dataclass
class TokenBucket:
    """Token bucket for rate limiting with burst capacity."""
    capacity: int = 100
    refill_rate: float = 10.0  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    
    def __post_init__(self):
        self.tokens = float(self.capacity)
        self.last_refill = time.time()
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
    
    async def acquire(self, tokens: int = 1) -> bool:
        """Acquire tokens from bucket. Returns True if successful."""
        self._refill()
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        
        # Calculate wait time for required tokens
        deficit = tokens - self.tokens
        wait_time = deficit / self.refill_rate
        
        logger.debug(f"Rate limit hit, waiting {wait_time:.2f}s for {tokens} tokens")
        await asyncio.sleep(wait_time)
        
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        
        return False


class RateLimiter:
    """Central rate limiting coordinator for AWS services."""
    
    # AWS service rate limits (tokens per second)
    DEFAULT_RATES = {
        "ec2": 20.0,
        "s3": 30.0,
        "iam": 10.0,
        "rds": 15.0,
        "lambda": 25.0,
        "cloudtrail": 5.0,
        "config": 5.0,
        "dynamodb": 40.0,
        "ecs": 20.0,
        "eks": 10.0,
        "elasticloadbalancing": 15.0,
        "elasticfilesystem": 10.0,
        "redshift": 5.0,
        "sns": 30.0,
        "sqs": 30.0
    }
    
    def __init__(self):
        self._buckets: Dict[str, TokenBucket] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
    
    def _get_bucket(self, service: str) -> TokenBucket:
        """Get or create token bucket for service."""
        if service not in self._buckets:
            rate = self.DEFAULT_RATES.get(service, 10.0)
            capacity = int(rate * 10)  # 10 seconds of burst capacity
            
            self._buckets[service] = TokenBucket(
                capacity=capacity,
                refill_rate=rate
            )
            self._locks[service] = asyncio.Lock()
            
            logger.info(f"Created rate limiter for {service}: {rate} req/s, burst {capacity}")
        
        return self._buckets[service]
    
    @asynccontextmanager
    async def acquire(self, service: str, tokens: int = 1):
        """Acquire rate limit tokens for service with context manager."""
        bucket = self._get_bucket(service)
        lock = self._locks[service]
        
        async with lock:
            success = await bucket.acquire(tokens)
            if not success:
                logger.warning(f"Failed to acquire {tokens} tokens for {service}")
                raise RuntimeError(f"Rate limit acquisition failed for {service}")
        
        try:
            yield
        finally:
            # Token already consumed, nothing to release
            pass
    
    async def acquire_tokens(self, service: str, tokens: int = 1) -> bool:
        """Acquire tokens without context manager."""
        bucket = self._get_bucket(service)
        lock = self._locks[service]
        
        async with lock:
            return await bucket.acquire(tokens)
    
    def set_service_rate(self, service: str, rate: float, capacity: Optional[int] = None) -> None:
        """Configure custom rate limit for service."""
        if capacity is None:
            capacity = int(rate * 10)
        
        self._buckets[service] = TokenBucket(
            capacity=capacity,
            refill_rate=rate
        )
        
        if service not in self._locks:
            self._locks[service] = asyncio.Lock()
        
        logger.info(f"Set custom rate for {service}: {rate} req/s, burst {capacity}")
    
    def get_bucket_status(self, service: str) -> Dict[str, float]:
        """Get current bucket status for monitoring."""
        if service not in self._buckets:
            return {"available_tokens": 0, "capacity": 0, "refill_rate": 0}
        
        bucket = self._buckets[service]
        bucket._refill()
        
        return {
            "available_tokens": bucket.tokens,
            "capacity": bucket.capacity,
            "refill_rate": bucket.refill_rate
        }
    
    def get_all_status(self) -> Dict[str, Dict[str, float]]:
        """Get status for all configured services."""
        return {
            service: self.get_bucket_status(service)
            for service in self._buckets.keys()
        }


# Global rate limiter instance
_global_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter()
    return _global_limiter


async def rate_limited_call(service: str, func, *args, tokens: int = 1, **kwargs):
    """Execute function with rate limiting."""
    limiter = get_rate_limiter()
    
    async with limiter.acquire(service, tokens):
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return func(*args, **kwargs)


# Convenience decorator for rate limiting
def rate_limit(service: str, tokens: int = 1):
    """Decorator for rate limiting async functions."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            return await rate_limited_call(service, func, *args, tokens=tokens, **kwargs)
        return wrapper
    return decorator