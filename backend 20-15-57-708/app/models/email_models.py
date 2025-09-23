"""
Email-related models for Sentinel backend
"""

from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator, EmailStr
import re


class EmailHeaders(BaseModel):
    """Parsed email headers"""
    sender: Optional[str] = Field(default=None, alias="from")
    reply_to: Optional[str] = Field(default=None, alias="reply-to")
    to: Optional[str] = Field(default=None)
    cc: Optional[str] = Field(default=None)
    bcc: Optional[str] = Field(default=None)
    subject: Optional[str] = Field(default=None)
    date: Optional[str] = Field(default=None)
    message_id: Optional[str] = Field(default=None, alias="message-id")
    received: Optional[List[str]] = Field(default_factory=list)
    x_originating_ip: Optional[str] = Field(default=None, alias="x-originating-ip")
    return_path: Optional[str] = Field(default=None, alias="return-path")
    authentication_results: Optional[str] = Field(default=None, alias="authentication-results")
    
    class Config:
        populate_by_name = True


class EmailBody(BaseModel):
    """Parsed email body content"""
    text_content: Optional[str] = Field(default=None)
    html_content: Optional[str] = Field(default=None)
    attachments: List[str] = Field(default_factory=list)
    
    @validator('text_content', 'html_content')
    def validate_content_length(cls, v):
        if v and len(v) > 500000:  # 500KB limit for body content
            raise ValueError("Email body content too large")
        return v


class ParsedEmail(BaseModel):
    """Complete parsed email structure"""
    headers: EmailHeaders
    body: EmailBody
    raw_content: str = Field(..., min_length=10)
    parsing_errors: List[str] = Field(default_factory=list)
    
    @validator('raw_content')
    def validate_raw_content(cls, v):
        if len(v) > 1024 * 1024:  # 1MB limit
            raise ValueError("Email content exceeds maximum size limit")
        return v


class EmailValidationResult(BaseModel):
    """Result of email validation"""
    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    
    
class EmailMetadata(BaseModel):
    """Metadata extracted from email analysis"""
    sender_domain: Optional[str] = Field(default=None)
    reply_to_domain: Optional[str] = Field(default=None)
    has_attachments: bool = Field(default=False)
    is_html: bool = Field(default=False)
    word_count: int = Field(default=0, ge=0)
    link_count: int = Field(default=0, ge=0)
    external_link_count: int = Field(default=0, ge=0)
    suspicious_patterns: List[str] = Field(default_factory=list)