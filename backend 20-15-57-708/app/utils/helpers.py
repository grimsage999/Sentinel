"""
Helper utilities for Sentinel backend
"""

import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote

from ..models.analysis_models import (
    ConfidenceLevel, IntentType, DeceptionIndicatorType, 
    IOCType, SeverityLevel
)


def generate_virustotal_url(ioc_value: str, ioc_type: IOCType) -> str:
    """
    Generate VirusTotal URL for an IOC
    
    Args:
        ioc_value: The IOC value (URL, IP, domain)
        ioc_type: Type of IOC
        
    Returns:
        VirusTotal URL string
    """
    base_url = "https://www.virustotal.com/gui"
    
    if ioc_type == IOCType.URL:
        # For URLs, use base64 encoding (VirusTotal official method)
        import base64
        url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
        return f"{base_url}/url/{url_id}"
    elif ioc_type == IOCType.IP:
        return f"{base_url}/ip-address/{ioc_value}"
    elif ioc_type == IOCType.DOMAIN:
        return f"{base_url}/domain/{ioc_value}"
    else:
        # Fallback to search
        return f"{base_url}/search/{quote(ioc_value)}"


def calculate_processing_time(start_time: datetime, end_time: Optional[datetime] = None) -> float:
    """
    Calculate processing time in seconds
    
    Args:
        start_time: Start timestamp
        end_time: End timestamp (defaults to now)
        
    Returns:
        Processing time in seconds
    """
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    
    return (end_time - start_time).total_seconds()


def get_current_timestamp() -> datetime:
    """
    Get current UTC timestamp
    
    Returns:
        Current datetime in UTC
    """
    return datetime.now(timezone.utc)


def normalize_confidence_level(confidence: Union[str, float]) -> ConfidenceLevel:
    """
    Normalize confidence level from various inputs
    
    Args:
        confidence: Confidence as string or float (0.0-1.0)
        
    Returns:
        ConfidenceLevel enum value
    """
    if isinstance(confidence, str):
        confidence_lower = confidence.lower()
        if confidence_lower in ['high', 'h']:
            return ConfidenceLevel.HIGH
        elif confidence_lower in ['medium', 'med', 'm']:
            return ConfidenceLevel.MEDIUM
        elif confidence_lower in ['low', 'l']:
            return ConfidenceLevel.LOW
    
    elif isinstance(confidence, (int, float)):
        if confidence >= 0.7:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.4:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW
    
    # Default fallback
    return ConfidenceLevel.MEDIUM


def normalize_severity_level(severity: Union[str, float, int]) -> SeverityLevel:
    """
    Normalize severity level from various inputs
    
    Args:
        severity: Severity as string, float, or int
        
    Returns:
        SeverityLevel enum value
    """
    if isinstance(severity, str):
        severity_lower = severity.lower()
        if severity_lower in ['high', 'critical', 'severe']:
            return SeverityLevel.HIGH
        elif severity_lower in ['medium', 'moderate', 'med']:
            return SeverityLevel.MEDIUM
        elif severity_lower in ['low', 'minor']:
            return SeverityLevel.LOW
    
    elif isinstance(severity, (int, float)):
        if severity >= 7:
            return SeverityLevel.HIGH
        elif severity >= 4:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    # Default fallback
    return SeverityLevel.MEDIUM


def clean_email_address(email: str) -> str:
    """
    Clean and normalize email address
    
    Args:
        email: Raw email address
        
    Returns:
        Cleaned email address
    """
    if not email:
        return ""
    
    # Remove angle brackets and whitespace
    cleaned = email.strip().strip('<>')
    
    # Extract just the email part if there's a display name
    if '<' in cleaned and '>' in cleaned:
        start = cleaned.find('<')
        end = cleaned.find('>')
        cleaned = cleaned[start+1:end]
    
    return cleaned.lower()


def extract_domain_from_email(email: str) -> Optional[str]:
    """
    Extract domain from email address
    
    Args:
        email: Email address
        
    Returns:
        Domain name or None if invalid
    """
    cleaned_email = clean_email_address(email)
    if '@' in cleaned_email:
        return cleaned_email.split('@')[-1]
    return None


def generate_request_id() -> str:
    """
    Generate a unique request ID
    
    Returns:
        Unique request ID string
    """
    timestamp = str(time.time())
    return hashlib.md5(timestamp.encode()).hexdigest()[:12]


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate text to specified length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated
        
    Returns:
        Truncated text
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def safe_get_nested_value(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    """
    Safely get nested dictionary value
    
    Args:
        data: Dictionary to search
        keys: List of keys for nested access
        default: Default value if not found
        
    Returns:
        Found value or default
    """
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def format_processing_metrics(metrics: Dict[str, float]) -> Dict[str, str]:
    """
    Format processing metrics for display
    
    Args:
        metrics: Dictionary of metric names to values (in seconds)
        
    Returns:
        Formatted metrics dictionary
    """
    formatted = {}
    for key, value in metrics.items():
        if value < 1:
            formatted[key] = f"{value * 1000:.1f}ms"
        else:
            formatted[key] = f"{value:.2f}s"
    return formatted