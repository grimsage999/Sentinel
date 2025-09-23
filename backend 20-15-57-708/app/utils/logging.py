"""
Secure logging utilities that exclude sensitive email content
"""

import logging
import re
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from email.utils import parseaddr


class SensitiveDataFilter(logging.Filter):
    """
    Logging filter that removes or masks sensitive information from log records
    """
    
    # Patterns for sensitive data
    EMAIL_PATTERNS = [
        re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE),
        re.compile(r'(?i)from:\s*[^\r\n]+'),
        re.compile(r'(?i)to:\s*[^\r\n]+'),
        re.compile(r'(?i)cc:\s*[^\r\n]+'),
        re.compile(r'(?i)bcc:\s*[^\r\n]+'),
        re.compile(r'(?i)reply-to:\s*[^\r\n]+'),
    ]
    
    # Patterns for potentially sensitive content
    CONTENT_PATTERNS = [
        re.compile(r'(?i)password[:\s]*[^\s\r\n]+'),
        re.compile(r'(?i)token[:\s]*[^\s\r\n]+'),
        re.compile(r'(?i)api[_-]?key[:\s]*[^\s\r\n]+'),
        re.compile(r'(?i)secret[:\s]*[^\s\r\n]+'),
        re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),  # Credit card numbers
        re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # SSN pattern
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log record to remove sensitive information
        """
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = self._sanitize_message(record.msg)
        
        if hasattr(record, 'args') and record.args:
            record.args = tuple(
                self._sanitize_message(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )
        
        return True
    
    def _sanitize_message(self, message: str) -> str:
        """
        Remove or mask sensitive information from a message
        """
        # Mask email addresses
        for pattern in self.EMAIL_PATTERNS:
            message = pattern.sub('[EMAIL_REDACTED]', message)
        
        # Mask other sensitive content
        for pattern in self.CONTENT_PATTERNS:
            message = pattern.sub('[SENSITIVE_DATA_REDACTED]', message)
        
        return message


class SecureLogger:
    """
    Secure logger that provides structured logging while protecting sensitive data
    """
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        
        # Add sensitive data filter if not already present
        if not any(isinstance(f, SensitiveDataFilter) for f in self.logger.filters):
            self.logger.addFilter(SensitiveDataFilter())
    
    def _create_log_context(self, **kwargs) -> Dict[str, Any]:
        """
        Create structured log context with timestamp and sanitized data
        """
        context = {
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'phishcontext-ai'
        }
        
        # Add sanitized context data
        for key, value in kwargs.items():
            if key in ['email_content', 'raw_email', 'email_body', 'email_headers']:
                # Don't log email content directly
                context[f'{key}_length'] = len(str(value)) if value else 0
                context[f'{key}_present'] = value is not None
            elif key in ['sender', 'recipient', 'from_address', 'to_address']:
                # Mask email addresses
                context[key] = '[EMAIL_REDACTED]' if value else None
            elif isinstance(value, dict):
                # Recursively sanitize dictionary values
                context[key] = self._sanitize_dict(value)
            else:
                context[key] = value
        
        return context
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitize dictionary data
        """
        sanitized = {}
        for key, value in data.items():
            if key.lower() in ['email', 'sender', 'recipient', 'from', 'to', 'cc', 'bcc']:
                sanitized[key] = '[EMAIL_REDACTED]' if value else None
            elif key.lower() in ['content', 'body', 'message', 'text']:
                sanitized[f'{key}_length'] = len(str(value)) if value else 0
                sanitized[f'{key}_present'] = value is not None
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    def info(self, message: str, **kwargs):
        """Log info message with structured context"""
        context = self._create_log_context(**kwargs)
        self.logger.info(f"{message} | Context: {json.dumps(context)}")
    
    def warning(self, message: str, **kwargs):
        """Log warning message with structured context"""
        context = self._create_log_context(**kwargs)
        self.logger.warning(f"{message} | Context: {json.dumps(context)}")
    
    def error(self, message: str, error: Optional[Exception] = None, **kwargs):
        """Log error message with structured context"""
        context = self._create_log_context(**kwargs)
        if error:
            context['error_type'] = type(error).__name__
            context['error_message'] = str(error)
        
        self.logger.error(f"{message} | Context: {json.dumps(context)}", exc_info=error)
    
    def debug(self, message: str, **kwargs):
        """Log debug message with structured context"""
        context = self._create_log_context(**kwargs)
        self.logger.debug(f"{message} | Context: {json.dumps(context)}")
    
    def log_analysis_start(self, request_id: str, email_length: int, client_ip: str):
        """Log the start of an email analysis"""
        self.info(
            "Email analysis started",
            request_id=request_id,
            email_content_length=email_length,
            client_ip=client_ip
        )
    
    def log_analysis_complete(
        self,
        request_id: str,
        processing_time: float,
        llm_provider: str,
        success: bool,
        ioc_count: int = 0
    ):
        """Log the completion of an email analysis"""
        self.info(
            "Email analysis completed",
            request_id=request_id,
            processing_time_seconds=processing_time,
            llm_provider=llm_provider,
            success=success,
            ioc_count=ioc_count
        )
    
    def log_llm_request(
        self,
        request_id: str,
        provider: str,
        prompt_length: int,
        attempt: int = 1
    ):
        """Log LLM API request"""
        self.info(
            "LLM request initiated",
            request_id=request_id,
            provider=provider,
            prompt_length=prompt_length,
            attempt=attempt
        )
    
    def log_llm_response(
        self,
        request_id: str,
        provider: str,
        response_length: int,
        processing_time: float,
        success: bool
    ):
        """Log LLM API response"""
        self.info(
            "LLM response received",
            request_id=request_id,
            provider=provider,
            response_length=response_length,
            processing_time_seconds=processing_time,
            success=success
        )
    
    def log_error_with_context(
        self,
        error: Exception,
        request_id: Optional[str] = None,
        operation: Optional[str] = None,
        **context
    ):
        """Log error with additional context"""
        self.error(
            f"Error in {operation or 'operation'}",
            error=error,
            request_id=request_id,
            **context
        )
    
    def log_security_event(
        self,
        event_type: str,
        client_ip: str,
        details: Optional[str] = None,
        **context
    ):
        """Log security-related events"""
        self.warning(
            f"Security event: {event_type}",
            event_type=event_type,
            client_ip=client_ip,
            details=details,
            **context
        )


def get_secure_logger(name: str) -> SecureLogger:
    """
    Get a secure logger instance for the given name
    """
    return SecureLogger(name)


def extract_safe_email_metadata(raw_email: str) -> Dict[str, Any]:
    """
    Extract safe metadata from email content for logging purposes
    """
    metadata = {
        'content_length': len(raw_email),
        'line_count': raw_email.count('\n'),
        'has_headers': 'From:' in raw_email or 'Subject:' in raw_email,
        'has_html': '<html>' in raw_email.lower() or '<body>' in raw_email.lower(),
        'has_attachments': 'Content-Disposition: attachment' in raw_email,
    }
    
    # Extract safe header information (without actual email addresses)
    try:
        lines = raw_email.split('\n')
        for line in lines[:50]:  # Only check first 50 lines for headers
            if line.startswith('Subject:'):
                metadata['has_subject'] = True
                metadata['subject_length'] = len(line) - 8  # Length without "Subject:"
            elif line.startswith('Date:'):
                metadata['has_date'] = True
            elif line.startswith('Message-ID:'):
                metadata['has_message_id'] = True
            elif line.startswith('Content-Type:'):
                metadata['content_type'] = line.split(':')[1].strip().split(';')[0]
    except Exception:
        # If parsing fails, just continue with basic metadata
        pass
    
    return metadata