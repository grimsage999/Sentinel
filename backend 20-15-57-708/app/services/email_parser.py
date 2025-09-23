"""
Email parsing service for PhishContext AI
Handles parsing of raw email content including headers and body extraction
"""

import re
import email
from email.message import EmailMessage
from email.parser import Parser
from email.policy import default
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import logging

from ..core.exceptions import ValidationException
from ..utils.validators import (
    validate_email_content, 
    sanitize_email_content,
    MAX_EMAIL_SIZE,
    MIN_EMAIL_LENGTH
)

logger = logging.getLogger(__name__)


class EmailHeaders:
    """Data class for parsed email headers"""
    
    def __init__(self):
        self.from_address: Optional[str] = None
        self.to_addresses: List[str] = []
        self.cc_addresses: List[str] = []
        self.bcc_addresses: List[str] = []
        self.subject: Optional[str] = None
        self.date: Optional[str] = None
        self.message_id: Optional[str] = None
        self.reply_to: Optional[str] = None
        self.return_path: Optional[str] = None
        self.received_headers: List[str] = []
        self.x_headers: Dict[str, str] = {}
        self.content_type: Optional[str] = None
        self.raw_headers: Dict[str, str] = {}


class EmailParser:
    """
    Email parser for extracting headers and body content from raw email text
    """
    
    def __init__(self):
        self.parser = Parser(policy=default)
    
    def parse_email(self, raw_email: str) -> Tuple[EmailHeaders, str]:
        """
        Parse raw email content into headers and body
        
        Args:
            raw_email: Raw email content as string
            
        Returns:
            Tuple of (EmailHeaders object, body content as string)
            
        Raises:
            ValidationException: If email content is invalid
        """
        # Validate input
        is_valid, errors = validate_email_content(raw_email)
        if not is_valid:
            raise ValidationException(f"Invalid email content: {'; '.join(errors)}")
        
        # Sanitize content
        sanitized_email = sanitize_email_content(raw_email)
        
        try:
            # Parse email using Python's email library
            msg = self.parser.parsestr(sanitized_email)
            
            # Extract headers
            headers = self._extract_headers(msg)
            
            # Extract body
            body = self._extract_body(msg)
            
            return headers, body
            
        except Exception as e:
            logger.error(f"Failed to parse email: {str(e)}")
            raise ValidationException(f"Email parsing failed: {str(e)}")
    
    def parse_headers(self, raw_email: str) -> EmailHeaders:
        """
        Extract and parse email headers from raw email content
        
        Args:
            raw_email: Raw email content as string
            
        Returns:
            EmailHeaders object with parsed header information
        """
        headers, _ = self.parse_email(raw_email)
        return headers
    
    def extract_body(self, raw_email: str) -> str:
        """
        Extract email body content from raw email
        
        Args:
            raw_email: Raw email content as string
            
        Returns:
            Email body content as string
        """
        _, body = self.parse_email(raw_email)
        return body
    
    def validate_email_format(self, raw_email: str) -> bool:
        """
        Validate if the provided content appears to be a valid email format
        
        Args:
            raw_email: Raw email content to validate
            
        Returns:
            True if valid email format, False otherwise
        """
        try:
            is_valid, _ = validate_email_content(raw_email)
            if not is_valid:
                return False
            
            # Try to parse - if it succeeds, format is valid
            self.parse_email(raw_email)
            return True
            
        except Exception:
            return False
    
    def _extract_headers(self, msg: EmailMessage) -> EmailHeaders:
        """
        Extract headers from parsed email message
        
        Args:
            msg: Parsed EmailMessage object
            
        Returns:
            EmailHeaders object with extracted header data
        """
        headers = EmailHeaders()
        
        # Basic headers
        headers.from_address = self._clean_header_value(msg.get('From'))
        headers.subject = self._clean_header_value(msg.get('Subject'))
        headers.date = self._clean_header_value(msg.get('Date'))
        headers.message_id = self._clean_header_value(msg.get('Message-ID'))
        headers.reply_to = self._clean_header_value(msg.get('Reply-To'))
        headers.return_path = self._clean_header_value(msg.get('Return-Path'))
        headers.content_type = self._clean_header_value(msg.get('Content-Type'))
        
        # Address lists
        headers.to_addresses = self._parse_address_list(msg.get('To', ''))
        headers.cc_addresses = self._parse_address_list(msg.get('Cc', ''))
        headers.bcc_addresses = self._parse_address_list(msg.get('Bcc', ''))
        
        # Received headers (multiple)
        headers.received_headers = [
            self._clean_header_value(received) 
            for received in msg.get_all('Received', [])
        ]
        
        # X-headers (custom headers starting with X-)
        for key, value in msg.items():
            if key.lower().startswith('x-'):
                headers.x_headers[key] = self._clean_header_value(value)
        
        # Store all raw headers
        for key, value in msg.items():
            headers.raw_headers[key] = self._clean_header_value(value)
        
        return headers
    
    def _extract_body(self, msg: EmailMessage) -> str:
        """
        Extract body content from parsed email message
        
        Args:
            msg: Parsed EmailMessage object
            
        Returns:
            Email body content as string
        """
        body_parts = []
        
        if msg.is_multipart():
            # Handle multipart messages
            for part in msg.walk():
                content_type = part.get_content_type()
                
                # Focus on text content
                if content_type in ['text/plain', 'text/html']:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            if isinstance(payload, bytes):
                                # Try to decode bytes to string
                                charset = part.get_content_charset() or 'utf-8'
                                try:
                                    text = payload.decode(charset)
                                except UnicodeDecodeError:
                                    # Fallback to utf-8 with error handling
                                    text = payload.decode('utf-8', errors='replace')
                            else:
                                text = str(payload)
                            
                            body_parts.append(f"--- {content_type.upper()} CONTENT ---\n{text}")
                    except Exception as e:
                        logger.warning(f"Failed to extract part content: {str(e)}")
                        continue
        else:
            # Handle single-part messages
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    if isinstance(payload, bytes):
                        charset = msg.get_content_charset() or 'utf-8'
                        try:
                            body_parts.append(payload.decode(charset))
                        except UnicodeDecodeError:
                            body_parts.append(payload.decode('utf-8', errors='replace'))
                    else:
                        body_parts.append(str(payload))
            except Exception as e:
                logger.warning(f"Failed to extract message content: {str(e)}")
                # Fallback to raw payload
                payload = msg.get_payload()
                if payload:
                    body_parts.append(str(payload))
        
        return '\n\n'.join(body_parts) if body_parts else ""
    
    def _clean_header_value(self, value: Optional[str]) -> Optional[str]:
        """
        Clean and sanitize header values
        
        Args:
            value: Raw header value
            
        Returns:
            Cleaned header value or None
        """
        if not value:
            return None
        
        # Remove control characters and normalize whitespace
        cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', str(value))
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        
        return cleaned if cleaned else None
    
    def _parse_address_list(self, address_string: str) -> List[str]:
        """
        Parse comma-separated email addresses
        
        Args:
            address_string: String containing email addresses
            
        Returns:
            List of parsed email addresses
        """
        if not address_string:
            return []
        
        addresses = []
        try:
            # Split by comma and clean each address
            for addr in address_string.split(','):
                cleaned = addr.strip()
                if cleaned:
                    addresses.append(cleaned)
        except Exception as e:
            logger.warning(f"Failed to parse address list: {str(e)}")
        
        return addresses