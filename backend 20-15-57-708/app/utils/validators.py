"""
Validation utilities for Sentinel backend
"""

import re
from typing import List, Optional, Tuple
from email.utils import parseaddr
from urllib.parse import urlparse

from ..core.exceptions import ValidationException


# Constants for validation
MAX_EMAIL_SIZE = 1024 * 1024  # 1MB
MIN_EMAIL_LENGTH = 10
MAX_BODY_SIZE = 500 * 1024  # 500KB
MAX_SUBJECT_LENGTH = 998  # RFC 5322 limit
MAX_HEADER_LENGTH = 998  # RFC 5322 limit

# Regex patterns
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
URL_PATTERN = re.compile(
    r'https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?',
    re.IGNORECASE
)
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)


def validate_email_content(content: str) -> Tuple[bool, List[str]]:
    """
    Validate email content for basic requirements
    
    Args:
        content: Raw email content string
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    if not content:
        errors.append("Email content cannot be empty")
        return False, errors
    
    if len(content) < MIN_EMAIL_LENGTH:
        errors.append(f"Email content too short (minimum {MIN_EMAIL_LENGTH} characters)")
    
    if len(content) > MAX_EMAIL_SIZE:
        errors.append(f"Email content too large (maximum {MAX_EMAIL_SIZE} bytes)")
    
    # Check for basic email structure
    if not any(header in content.lower() for header in ['from:', 'to:', 'subject:']):
        errors.append("Email content appears to be missing basic headers")
    
    return len(errors) == 0, errors


def validate_email_address(email: str) -> bool:
    """
    Validate email address format
    
    Args:
        email: Email address string
        
    Returns:
        True if valid, False otherwise
    """
    if not email:
        return False
    
    # Use email.utils.parseaddr for basic parsing
    name, addr = parseaddr(email)
    
    if not addr:
        return False
    
    return bool(EMAIL_PATTERN.match(addr))


def validate_confidence_threshold(threshold: float) -> bool:
    """
    Validate confidence threshold value
    
    Args:
        threshold: Confidence threshold (0.0 to 1.0)
        
    Returns:
        True if valid, False otherwise
    """
    return 0.0 <= threshold <= 1.0


def validate_risk_score(score: int) -> bool:
    """
    Validate risk score value
    
    Args:
        score: Risk score (1 to 10)
        
    Returns:
        True if valid, False otherwise
    """
    return 1 <= score <= 10


def sanitize_email_content(content: str) -> str:
    """
    Sanitize email content for safe processing
    
    Args:
        content: Raw email content
        
    Returns:
        Sanitized content string
    """
    if not content:
        return ""
    
    # Remove null bytes and other control characters
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', content)
    
    # Normalize line endings
    sanitized = re.sub(r'\r\n|\r|\n', '\n', sanitized)
    
    # Limit line length to prevent issues
    lines = sanitized.split('\n')
    sanitized_lines = []
    
    for line in lines:
        if len(line) > 1000:  # Reasonable line length limit
            line = line[:1000] + '...[truncated]'
        sanitized_lines.append(line)
    
    return '\n'.join(sanitized_lines)


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract URLs from text content
    
    Args:
        text: Text content to search
        
    Returns:
        List of found URLs
    """
    if not text:
        return []
    
    urls = URL_PATTERN.findall(text)
    return list(set(urls))  # Remove duplicates


def extract_ips_from_text(text: str) -> List[str]:
    """
    Extract IP addresses from text content
    
    Args:
        text: Text content to search
        
    Returns:
        List of found IP addresses
    """
    if not text:
        return []
    
    ips = IP_PATTERN.findall(text)
    return list(set(ips))  # Remove duplicates


def extract_domains_from_text(text: str) -> List[str]:
    """
    Extract domain names from text content
    
    Args:
        text: Text content to search
        
    Returns:
        List of found domain names
    """
    if not text:
        return []
    
    domains = DOMAIN_PATTERN.findall(text)
    # Filter out common false positives
    filtered_domains = []
    for domain in domains:
        if '.' in domain and len(domain.split('.')[-1]) >= 2:
            filtered_domains.append(domain)
    
    return list(set(filtered_domains))  # Remove duplicates


def validate_url(url: str) -> bool:
    """
    Validate URL format
    
    Args:
        url: URL string to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_email_size(content: str) -> Tuple[bool, Optional[str]]:
    """
    Validate email content size limits
    
    Args:
        content: Email content to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not content:
        return False, "Email content cannot be empty"
    
    content_size = len(content.encode('utf-8'))
    
    if content_size < MIN_EMAIL_LENGTH:
        return False, f"Email content too short (minimum {MIN_EMAIL_LENGTH} characters)"
    
    if content_size > MAX_EMAIL_SIZE:
        return False, f"Email content too large (maximum {MAX_EMAIL_SIZE} bytes)"
    
    return True, None


def validate_email_headers(content: str) -> Tuple[bool, List[str]]:
    """
    Validate that email content contains required headers
    
    Args:
        content: Email content to validate
        
    Returns:
        Tuple of (is_valid, list_of_missing_headers)
    """
    required_headers = ['from:', 'subject:']
    recommended_headers = ['to:', 'date:']
    
    content_lower = content.lower()
    missing_required = []
    missing_recommended = []
    
    for header in required_headers:
        if header not in content_lower:
            missing_required.append(header.rstrip(':').title())
    
    for header in recommended_headers:
        if header not in content_lower:
            missing_recommended.append(header.rstrip(':').title())
    
    # Required headers must be present
    is_valid = len(missing_required) == 0
    
    # Combine all missing headers for reporting
    all_missing = missing_required + missing_recommended
    
    return is_valid, all_missing


def detect_malicious_patterns(content: str) -> List[str]:
    """
    Detect potentially malicious patterns in email content
    
    Args:
        content: Email content to analyze
        
    Returns:
        List of detected malicious patterns
    """
    patterns = []
    
    if not content:
        return patterns
    
    content_lower = content.lower()
    
    # Check for suspicious script tags
    if re.search(r'<script[^>]*>', content_lower):
        patterns.append("JavaScript code detected")
    
    # Check for suspicious executable attachments (look for filename patterns)
    # Note: .com excluded due to high false positive rate with email domains
    suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js']
    for ext in suspicious_extensions:
        # Look for filename patterns, not just the extension in any context
        pattern = r'[\w\-_]+' + re.escape(ext) + r'(?:\s|$|[^\w\.])'
        if re.search(pattern, content_lower):
            patterns.append(f"Suspicious file extension detected: {ext}")
    
    # Check for base64 encoded content (potential malware)
    if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', content):
        patterns.append("Base64 encoded content detected")
    
    # Check for suspicious URLs with IP addresses
    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', content):
        patterns.append("URL with IP address detected")
    
    # Check for URL shorteners (common in phishing)
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link']
    for shortener in shorteners:
        if shortener in content_lower:
            patterns.append(f"URL shortener detected: {shortener}")
    
    return patterns


def sanitize_malicious_content(content: str) -> str:
    """
    Sanitize potentially malicious content from email
    
    Args:
        content: Raw email content
        
    Returns:
        Sanitized content with malicious patterns removed/neutralized
    """
    if not content:
        return ""
    
    sanitized = content
    
    # Remove script tags
    sanitized = re.sub(r'<script[^>]*>.*?</script>', '[SCRIPT_REMOVED]', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    # Remove iframe tags
    sanitized = re.sub(r'<iframe[^>]*>.*?</iframe>', '[IFRAME_REMOVED]', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    # Remove object/embed tags
    sanitized = re.sub(r'<(object|embed)[^>]*>.*?</\1>', '[OBJECT_REMOVED]', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    # Neutralize javascript: URLs
    sanitized = re.sub(r'javascript:', 'javascript_NEUTRALIZED:', sanitized, flags=re.IGNORECASE)
    
    # Neutralize data: URLs with suspicious content
    sanitized = re.sub(r'data:(?!image/)[^;,]+[;,]', 'data_NEUTRALIZED:', sanitized, flags=re.IGNORECASE)
    
    return sanitized


def validate_header_format(header_name: str, header_value: str) -> Tuple[bool, Optional[str]]:
    """
    Validate specific email header format
    
    Args:
        header_name: Name of the header
        header_value: Value of the header
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not header_value:
        return False, f"{header_name} header cannot be empty"
    
    # Check header length limits (RFC 5322)
    if len(header_value) > MAX_HEADER_LENGTH:
        return False, f"{header_name} header exceeds maximum length ({MAX_HEADER_LENGTH} characters)"
    
    header_lower = header_name.lower()
    
    # Validate specific header formats
    if header_lower in ['from', 'to', 'cc', 'bcc', 'reply-to']:
        # Email address headers
        if not re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', header_value):
            return False, f"{header_name} header does not contain valid email address"
    
    elif header_lower == 'subject':
        # Subject header validation
        if len(header_value) > MAX_SUBJECT_LENGTH:
            return False, f"Subject header exceeds maximum length ({MAX_SUBJECT_LENGTH} characters)"
    
    elif header_lower == 'date':
        # Basic date format check
        if not re.search(r'\w+,?\s+\d+\s+\w+\s+\d{4}', header_value):
            return False, "Date header format appears invalid"
    
    return True, None