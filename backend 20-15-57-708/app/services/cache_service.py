"""
Caching service for email analysis results
Implements intelligent caching with content hashing and TTL management
"""

import hashlib
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import OrderedDict
import threading

from ..models.analysis_models import AnalysisResult
from ..utils.logging import get_secure_logger
from ..core.config import settings

logger = get_secure_logger(__name__)


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    result: AnalysisResult
    created_at: datetime
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    content_hash: str = ""
    email_size: int = 0


class EmailAnalysisCache:
    """
    Intelligent caching system for email analysis results
    Uses content hashing to identify similar emails and caches results with TTL
    """
    
    def __init__(self, max_size: int = 1000, ttl_hours: int = 24):
        self.max_size = max_size
        self.ttl_hours = ttl_hours
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        
        # Cache statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        
        # Start cleanup task
        self._cleanup_task = None
        self._start_cleanup_task()
    
    def _start_cleanup_task(self):
        """Start background cleanup task"""
        if self._cleanup_task is None:
            # This will be started by the application lifespan
            logger.info("Cache cleanup task initialized")
    
    async def start_background_cleanup(self):
        """Start the background cleanup task"""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_expired_entries())
            logger.info("Background cache cleanup started")
    
    async def stop_background_cleanup(self):
        """Stop the background cleanup task"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
            logger.info("Background cache cleanup stopped")
    
    async def _cleanup_expired_entries(self):
        """Background task to clean up expired cache entries"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error during cache cleanup", error=e)
                await asyncio.sleep(300)  # Wait 5 minutes before retrying
    
    async def _cleanup_expired(self):
        """Remove expired entries from cache"""
        now = datetime.utcnow()
        expired_keys = []
        
        with self.lock:
            for key, entry in self.cache.items():
                if (now - entry.created_at).total_seconds() > (self.ttl_hours * 3600):
                    expired_keys.append(key)
        
        if expired_keys:
            with self.lock:
                for key in expired_keys:
                    if key in self.cache:
                        del self.cache[key]
                        self.evictions += 1
            
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def _generate_content_hash(self, email_content: str, email_headers: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a hash for email content to identify similar emails
        Uses normalized content to catch minor variations
        """
        # Normalize email content for better cache hits
        normalized_content = self._normalize_email_content(email_content)
        
        # Include relevant headers in hash if available
        header_data = ""
        if email_headers:
            # Only include headers that affect analysis
            relevant_headers = ['from', 'to', 'subject', 'reply-to', 'return-path']
            header_parts = []
            for header in relevant_headers:
                if header in email_headers:
                    header_parts.append(f"{header}:{email_headers[header]}")
            header_data = "|".join(sorted(header_parts))
        
        # Combine content and headers
        hash_input = f"{normalized_content}|{header_data}"
        
        # Generate SHA-256 hash
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    
    def _normalize_email_content(self, content: str) -> str:
        """
        Normalize email content for better cache matching
        Removes timestamps, session IDs, and other variable elements
        """
        import re
        
        # Convert to lowercase for case-insensitive matching
        normalized = content.lower()
        
        # Remove common variable elements that don't affect analysis
        patterns_to_remove = [
            r'\d{4}-\d{2}-\d{2}[\s\t]+\d{2}:\d{2}:\d{2}',  # Timestamps
            r'message-id:\s*<[^>]+>',  # Message IDs
            r'date:\s*[^\r\n]+',  # Date headers
            r'received:\s*[^\r\n]+',  # Received headers
            r'x-[^:]+:[^\r\n]+',  # X- headers
            r'session[_-]?id[:\s=]+[a-zA-Z0-9]+',  # Session IDs
            r'token[:\s=]+[a-zA-Z0-9]+',  # Tokens
            r'nonce[:\s=]+[a-zA-Z0-9]+',  # Nonces
        ]
        
        for pattern in patterns_to_remove:
            normalized = re.sub(pattern, '', normalized, flags=re.IGNORECASE | re.MULTILINE)
        
        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized)
        normalized = normalized.strip()
        
        return normalized
    
    async def get(
        self, 
        email_content: str, 
        email_headers: Optional[Dict[str, Any]] = None
    ) -> Optional[AnalysisResult]:
        """
        Get cached analysis result for email content
        
        Args:
            email_content: Raw email content
            email_headers: Parsed email headers
            
        Returns:
            Cached analysis result if found, None otherwise
        """
        content_hash = self._generate_content_hash(email_content, email_headers)
        
        with self.lock:
            if content_hash in self.cache:
                entry = self.cache[content_hash]
                
                # Check if entry is still valid
                age_hours = (datetime.utcnow() - entry.created_at).total_seconds() / 3600
                if age_hours <= self.ttl_hours:
                    # Update access statistics
                    entry.access_count += 1
                    entry.last_accessed = datetime.utcnow()
                    
                    # Move to end (LRU)
                    self.cache.move_to_end(content_hash)
                    
                    self.hits += 1
                    
                    logger.debug(
                        "Cache hit",
                        content_hash=content_hash[:16],
                        age_hours=age_hours,
                        access_count=entry.access_count
                    )
                    
                    return entry.result
                else:
                    # Entry expired, remove it
                    del self.cache[content_hash]
                    self.evictions += 1
        
        self.misses += 1
        logger.debug("Cache miss", content_hash=content_hash[:16])
        return None
    
    async def set(
        self, 
        email_content: str, 
        result: AnalysisResult,
        email_headers: Optional[Dict[str, Any]] = None
    ):
        """
        Cache analysis result for email content
        
        Args:
            email_content: Raw email content
            result: Analysis result to cache
            email_headers: Parsed email headers
        """
        content_hash = self._generate_content_hash(email_content, email_headers)
        
        entry = CacheEntry(
            result=result,
            created_at=datetime.utcnow(),
            content_hash=content_hash,
            email_size=len(email_content)
        )
        
        with self.lock:
            # Add to cache
            self.cache[content_hash] = entry
            
            # Enforce size limit (LRU eviction)
            while len(self.cache) > self.max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                self.evictions += 1
        
        logger.debug(
            "Cache entry added",
            content_hash=content_hash[:16],
            email_size=len(email_content),
            cache_size=len(self.cache)
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests) if total_requests > 0 else 0.0
            
            # Calculate cache size and memory usage estimate
            cache_size = len(self.cache)
            total_email_size = sum(entry.email_size for entry in self.cache.values())
            
            # Estimate memory usage (rough calculation)
            estimated_memory_mb = total_email_size / (1024 * 1024)
            
            return {
                'cache_size': cache_size,
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'evictions': self.evictions,
                'hit_rate': hit_rate,
                'ttl_hours': self.ttl_hours,
                'estimated_memory_mb': estimated_memory_mb,
                'total_email_size_bytes': total_email_size
            }
    
    async def clear(self):
        """Clear all cache entries"""
        with self.lock:
            cleared_count = len(self.cache)
            self.cache.clear()
            
        logger.info(f"Cache cleared, removed {cleared_count} entries")
    
    async def remove_expired(self):
        """Manually trigger cleanup of expired entries"""
        await self._cleanup_expired()


# Global cache instance
analysis_cache = EmailAnalysisCache(
    max_size=getattr(settings, 'cache_max_size', 1000),
    ttl_hours=getattr(settings, 'cache_ttl_hours', 24)
)