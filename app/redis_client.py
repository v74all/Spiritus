"""
Redis module for V7LTHRONYX VPN Panel.

Provides caching, rate limiting, and session management.
"""

import redis.asyncio as aioredis
from typing import Optional, Any
import json
import logging

from .config import settings

logger = logging.getLogger(__name__)

# Redis connection pool
_redis_pool: Optional[aioredis.Redis] = None

async def get_redis() -> aioredis.Redis:
    """Get Redis connection."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            str(settings.redis_url),
            encoding="utf-8",
            decode_responses=True,
            max_connections=settings.redis_pool_size
        )
    return _redis_pool

async def close_redis():
    """Close Redis connection pool."""
    global _redis_pool
    if _redis_pool:
        await _redis_pool.close()
        _redis_pool = None
        logger.info("Redis connection pool closed")

class CacheManager:
    """Redis-based cache manager."""
    
    def __init__(self, prefix: str = "vpn:cache"):
        self.prefix = prefix
    
    async def _get_conn(self) -> aioredis.Redis:
        return await get_redis()
    
    async def get(self, key: str) -> Optional[Any]:
        """Get a cached value."""
        conn = await self._get_conn()
        value = await conn.get(f"{self.prefix}:{key}")
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return None
    
    async def set(self, key: str, value: Any, expire: int = 300):
        """Set a cached value with expiration (default 5 minutes)."""
        conn = await self._get_conn()
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        await conn.set(f"{self.prefix}:{key}", value, ex=expire)
    
    async def delete(self, key: str):
        """Delete a cached value."""
        conn = await self._get_conn()
        await conn.delete(f"{self.prefix}:{key}")
    
    async def exists(self, key: str) -> bool:
        """Check if a key exists."""
        conn = await self._get_conn()
        return bool(await conn.exists(f"{self.prefix}:{key}"))

class RateLimiter:
    """Redis-based rate limiter."""
    
    def __init__(self, prefix: str = "vpn:ratelimit"):
        self.prefix = prefix
    
    async def _get_conn(self) -> aioredis.Redis:
        return await get_redis()
    
    async def is_rate_limited(
        self,
        key: str,
        max_requests: int = 10,
        window_seconds: int = 60
    ) -> bool:
        """Check if a key has exceeded rate limit."""
        conn = await self._get_conn()
        redis_key = f"{self.prefix}:{key}"
        
        # Increment counter
        current = await conn.incr(redis_key)
        
        # Set expiration on first request
        if current == 1:
            await conn.expire(redis_key, window_seconds)
        
        return current > max_requests
    
    async def get_remaining(
        self,
        key: str,
        max_requests: int = 10
    ) -> int:
        """Get remaining requests for a key."""
        conn = await self._get_conn()
        redis_key = f"{self.prefix}:{key}"
        current = await conn.get(redis_key)
        if current is None:
            return max_requests
        return max(0, max_requests - int(current))

# Global instances
cache = CacheManager()
rate_limiter = RateLimiter()