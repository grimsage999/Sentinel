"""
Security utilities for PhishContext AI
Provides input sanitization, XSS prevention, and security validation
"""

import re
import html
import gc
import weakref
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
import hashlib
import secrets
import logging

from ..utils.logging import get_secure_logger

logger = get_secure_logger(__name__)

# XSS prevention patterns
XSS_PATTERNS = [
    re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'javascript:', re.IGNORECASE),
    re.compile(r'vbscript:', re.IGNORECASE),
    re.compile(r'onload\s*=', re.IGNORECASE),
    re.compile(r'onerror\s*=', re.IGNORECASE),
    re.compile(r'onclick\s*=', re.IGNORECASE),
    re.compile(r'onmouseover\s*=', re.IGNORECASE),
    re.compile(r'onfocus\s*=', re.IGNORECASE),
    re.compile(r'onblur\s*=', re.IGNORECASE),
    re.compile(r'<iframe[^>]*>', re.IGNORECASE),
    re.compile(r'<object[^>]*>', re.IGNORECASE),
    re.compile(r'<embed[^>]*>', re.IGNORECASE),
    re.compile(r'<form[^>]*>', re.IGNORECASE),
    re.compile(r'<input[^>]*>', re.IGNORECASE),
    re.compile(r'data:(?!image/)[^;,]+[;,]', re.IGNORECASE),
]

# Malicious file extensions
DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar',
    '.app', '.deb', '.pkg', '.dmg', '.msi', '.run', '.bin', '.sh', '.ps1'
}

# Memory management for email content
class EmailContentManager:
    """Manages email content lifecycle with automatic cleanup"""
    
    def __init__(self):
        self._content_refs: Dict[str, str] = {}
        self._cleanup_times: Dict[str, datetime] = {}
        self._max_retention_minutes = 5  # Maximum time to keep content in memory
    
    def store_content(self, content_id: str, content: str) -> str:
        """Store email content with automatic cleanup"""
        # Store content directly (strings can't use weakref)
        # We'll rely on explicit cleanup and garbage collection
        self._content_refs[content_id] = content
        self._cleanup_times[content_id] = datetime.utcnow() + timedelta(minutes=self._max_retention_minutes)
        
        logger.debug(
            "Email content stored for processing",
            content_id=content_id,
            content_length=len(content)
        )
        
        return content_id
    
    def get_content(self, content_id: str) -> Optional[str]:
        """Retrieve stored content if still available"""
        if content_id not in self._content_refs:
            return None
        
        return self._content_refs[content_id]
    
    def clear_content(self, content_id: str) -> None:
        """Explicitly clear content from memory"""
        if content_id in self._content_refs:
            self._cleanup_content(content_id)
            logger.debug("Email content explicitly cleared", content_id=content_id)
    
    def _cleanup_content(self, content_id: str) -> None:
        """Remove content references and trigger garbage collection"""
        self._content_refs.pop(content_id, None)
        self._cleanup_times.pop(content_id, None)
        
        # Force garbage collection to ensure memory is freed
        gc.collect()
    
    def cleanup_expired(self) -> int:
        """Clean up expired content and return count of cleaned items"""
        now = datetime.utcnow()
        expired_ids = [
            content_id for content_id, cleanup_time in self._cleanup_times.items()
            if now > cleanup_time
        ]
        
        for content_id in expired_ids:
            self._cleanup_content(content_id)
        
        if expired_ids:
            logger.info(f"Cleaned up {len(expired_ids)} expired email content items")
        
        return len(expired_ids)

# Global content manager instance
email_content_manager = EmailContentManager()


def sanitize_email_content(content: str) -> str:
    """
    Sanitize email content to prevent XSS and other security issues
    
    Args:
        content: Raw email content
        
    Returns:
        Sanitized email content
    """
    if not content:
        return ""
    
    # Start with the original content
    sanitized = content
    
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
    
    # Apply XSS prevention patterns
    for pattern in XSS_PATTERNS:
        sanitized = pattern.sub('[POTENTIALLY_MALICIOUS_CONTENT_REMOVED]', sanitized)
    
    # HTML encode any remaining HTML entities
    sanitized = html.escape(sanitized, quote=False)
    
    # Normalize line endings
    sanitized = re.sub(r'\r\n|\r|\n', '\n', sanitized)
    
    # Limit line length to prevent buffer overflow attacks
    lines = sanitized.split('\n')
    sanitized_lines = []
    
    for line in lines:
        if len(line) > 2000:  # Reasonable line length limit
            line = line[:2000] + '...[LINE_TRUNCATED_FOR_SECURITY]'
        sanitized_lines.append(line)
    
    sanitized = '\n'.join(sanitized_lines)
    
    # Log sanitization if changes were made
    if sanitized != content:
        logger.log_security_event(
            event_type="content_sanitization",
            client_ip="system",
            details="Email content was sanitized for security",
            original_length=len(content),
            sanitized_length=len(sanitized)
        )
    
    return sanitized


def validate_content_size(content: str, max_size_mb: int = 1) -> Tuple[bool, Optional[str]]:
    """
    Validate content size limits
    
    Args:
        content: Content to validate
        max_size_mb: Maximum size in megabytes
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not content:
        return False, "Content cannot be empty"
    
    content_size = len(content.encode('utf-8'))
    max_size_bytes = max_size_mb * 1024 * 1024
    
    if content_size > max_size_bytes:
        logger.log_security_event(
            event_type="size_limit_exceeded",
            client_ip="system",
            details=f"Content size {content_size} exceeds limit {max_size_bytes}",
            content_size=content_size,
            max_size=max_size_bytes
        )
        return False, f"Content exceeds maximum size of {max_size_mb}MB"
    
    return True, None


def detect_malicious_patterns(content: str) -> List[Dict[str, Any]]:
    """
    Detect potentially malicious patterns in content
    
    Args:
        content: Content to analyze
        
    Returns:
        List of detected threats with details
    """
    threats = []
    
    if not content:
        return threats
    
    content_lower = content.lower()
    
    # Check for script injection
    if re.search(r'<script[^>]*>', content_lower):
        threats.append({
            'type': 'script_injection',
            'severity': 'high',
            'description': 'JavaScript code detected in content'
        })
    
    # Check for suspicious file attachments
    for ext in DANGEROUS_EXTENSIONS:
        if ext in content_lower:
            # More specific check to avoid false positives
            pattern = r'[\w\-_]+' + re.escape(ext) + r'(?:\s|$|[^\w\.])'
            if re.search(pattern, content_lower):
                threats.append({
                    'type': 'dangerous_attachment',
                    'severity': 'high',
                    'description': f'Potentially dangerous file extension: {ext}'
                })
    
    # Check for base64 encoded content (potential malware)
    base64_matches = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', content)
    if base64_matches:
        threats.append({
            'type': 'base64_content',
            'severity': 'medium',
            'description': f'Large base64 encoded content detected ({len(base64_matches)} instances)'
        })
    
    # Check for suspicious URLs with IP addresses
    ip_urls = re.findall(r'https?://\d+\.\d+\.\d+\.\d+', content)
    if ip_urls:
        threats.append({
            'type': 'ip_based_urls',
            'severity': 'medium',
            'description': f'URLs with IP addresses detected ({len(ip_urls)} instances)'
        })
    
    # Check for URL shorteners (common in phishing)
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'tiny.cc']
    for shortener in shorteners:
        if shortener in content_lower:
            threats.append({
                'type': 'url_shortener',
                'severity': 'low',
                'description': f'URL shortener detected: {shortener}'
            })
    
    # Check for suspicious form elements
    if re.search(r'<form[^>]*>', content_lower):
        threats.append({
            'type': 'form_element',
            'severity': 'medium',
            'description': 'HTML form detected in email content'
        })
    
    # Log detected threats
    if threats:
        logger.log_security_event(
            event_type="malicious_patterns_detected",
            client_ip="system",
            details=f"Detected {len(threats)} potential threats",
            threat_count=len(threats),
            threat_types=[t['type'] for t in threats]
        )
    
    return threats


def validate_url_safety(url: str) -> Dict[str, Any]:
    """
    Validate URL safety and extract security information
    
    Args:
        url: URL to validate
        
    Returns:
        Dictionary with safety information
    """
    result = {
        'is_safe': True,
        'warnings': [],
        'parsed_url': None,
        'domain': None,
        'scheme': None
    }
    
    try:
        parsed = urlparse(url)
        result['parsed_url'] = parsed
        result['domain'] = parsed.netloc
        result['scheme'] = parsed.scheme
        
        # Check for suspicious schemes
        if parsed.scheme not in ['http', 'https', 'ftp', 'ftps']:
            result['is_safe'] = False
            result['warnings'].append(f"Suspicious URL scheme: {parsed.scheme}")
        
        # Check for IP-based URLs
        if re.match(r'^\d+\.\d+\.\d+\.\d+', parsed.netloc):
            result['is_safe'] = False
            result['warnings'].append("URL uses IP address instead of domain name")
        
        # Check for suspicious ports
        if parsed.port and parsed.port not in [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]:
            result['warnings'].append(f"Unusual port number: {parsed.port}")
        
        # Check for suspicious query parameters
        if parsed.query:
            query_params = parse_qs(parsed.query)
            suspicious_params = ['redirect', 'url', 'goto', 'next', 'return', 'continue']
            for param in suspicious_params:
                if param in query_params:
                    result['warnings'].append(f"Suspicious query parameter: {param}")
        
        # Check for extremely long URLs (potential buffer overflow)
        if len(url) > 2000:
            result['warnings'].append("Extremely long URL detected")
        
    except Exception as e:
        result['is_safe'] = False
        result['warnings'].append(f"Failed to parse URL: {str(e)}")
    
    return result


def generate_content_hash(content: str) -> str:
    """
    Generate a secure hash of content for tracking and deduplication
    
    Args:
        content: Content to hash
        
    Returns:
        SHA-256 hash of the content
    """
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def generate_request_id() -> str:
    """
    Generate a secure random request ID for tracking
    
    Returns:
        Secure random request ID
    """
    return secrets.token_urlsafe(16)


def sanitize_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize email headers to remove potentially dangerous content
    
    Args:
        headers: Dictionary of email headers
        
    Returns:
        Sanitized headers dictionary
    """
    sanitized = {}
    
    for key, value in headers.items():
        if not key or not value:
            continue
        
        # Convert to string if not already
        key_str = str(key).strip()
        value_str = str(value).strip()
        
        # Skip headers that might contain malicious content
        if key_str.lower() in ['content-type', 'content-disposition']:
            # Sanitize these headers more carefully
            value_str = re.sub(r'[<>"\']', '', value_str)
        
        # Remove control characters
        key_str = re.sub(r'[\x00-\x1F\x7F]', '', key_str)
        value_str = re.sub(r'[\x00-\x1F\x7F]', '', value_str)
        
        # Limit header length
        if len(key_str) > 100:
            key_str = key_str[:100] + '...[TRUNCATED]'
        if len(value_str) > 1000:
            value_str = value_str[:1000] + '...[TRUNCATED]'
        
        sanitized[key_str] = value_str
    
    return sanitized


def clear_sensitive_memory():
    """
    Force garbage collection to clear sensitive data from memory
    """
    # Clean up expired content
    email_content_manager.cleanup_expired()
    
    # Force garbage collection
    gc.collect()
    
    logger.debug("Sensitive memory cleanup completed")


class SecurityMetrics:
    """Track security-related metrics"""
    
    def __init__(self):
        self.threat_counts: Dict[str, int] = {}
        self.sanitization_counts: int = 0
        self.blocked_requests: int = 0
        self.last_reset = datetime.utcnow()
    
    def record_threat(self, threat_type: str):
        """Record a detected threat"""
        self.threat_counts[threat_type] = self.threat_counts.get(threat_type, 0) + 1
    
    def record_sanitization(self):
        """Record a content sanitization event"""
        self.sanitization_counts += 1
    
    def record_blocked_request(self):
        """Record a blocked request"""
        self.blocked_requests += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current security metrics"""
        return {
            'threat_counts': self.threat_counts.copy(),
            'sanitization_counts': self.sanitization_counts,
            'blocked_requests': self.blocked_requests,
            'metrics_period_start': self.last_reset.isoformat(),
            'active_content_items': len(email_content_manager._content_refs)
        }
    
    def reset_metrics(self):
        """Reset metrics counters"""
        self.threat_counts.clear()
        self.sanitization_counts = 0
        self.blocked_requests = 0
        self.last_reset = datetime.utcnow()

# Global security metrics instance
security_metrics = SecurityMetrics()