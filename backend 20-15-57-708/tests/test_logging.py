"""
Tests for secure logging utilities
"""

import json
import logging
from unittest.mock import patch, MagicMock
import pytest

from app.utils.logging import (
    SensitiveDataFilter,
    SecureLogger,
    get_secure_logger,
    extract_safe_email_metadata
)


class TestSensitiveDataFilter:
    """Test the sensitive data filter"""
    
    def test_filter_email_addresses(self):
        """Test that email addresses are filtered"""
        filter_instance = SensitiveDataFilter()
        
        # Create a mock log record
        record = MagicMock()
        record.msg = "User email: john.doe@example.com sent message"
        record.args = ()
        
        filter_instance.filter(record)
        
        assert "[EMAIL_REDACTED]" in record.msg
        assert "john.doe@example.com" not in record.msg
    
    def test_filter_email_headers(self):
        """Test that email headers are filtered"""
        filter_instance = SensitiveDataFilter()
        
        record = MagicMock()
        record.msg = "From: sender@example.com\nTo: recipient@test.com"
        record.args = ()
        
        filter_instance.filter(record)
        
        assert "[EMAIL_REDACTED]" in record.msg
        assert "sender@example.com" not in record.msg
        assert "recipient@test.com" not in record.msg
    
    def test_filter_sensitive_content(self):
        """Test that sensitive content patterns are filtered"""
        filter_instance = SensitiveDataFilter()
        
        record = MagicMock()
        record.msg = "Password: secret123 and API_KEY: abc123xyz"
        record.args = ()
        
        filter_instance.filter(record)
        
        assert "[SENSITIVE_DATA_REDACTED]" in record.msg
        assert "secret123" not in record.msg
        assert "abc123xyz" not in record.msg
    
    def test_filter_credit_card_numbers(self):
        """Test that credit card numbers are filtered"""
        filter_instance = SensitiveDataFilter()
        
        record = MagicMock()
        record.msg = "Card number: 1234-5678-9012-3456"
        record.args = ()
        
        filter_instance.filter(record)
        
        assert "[SENSITIVE_DATA_REDACTED]" in record.msg
        assert "1234-5678-9012-3456" not in record.msg
    
    def test_filter_args_tuple(self):
        """Test that args tuple is also filtered"""
        filter_instance = SensitiveDataFilter()
        
        record = MagicMock()
        record.msg = "Processing request"
        record.args = ("user@example.com", "password123")
        
        filter_instance.filter(record)
        
        assert "[EMAIL_REDACTED]" in record.args[0]
        assert "[SENSITIVE_DATA_REDACTED]" in record.args[1]


class TestSecureLogger:
    """Test the secure logger"""
    
    @pytest.fixture
    def secure_logger(self):
        """Create a secure logger for testing"""
        return SecureLogger("test_logger")
    
    def test_logger_initialization(self, secure_logger):
        """Test that logger is properly initialized"""
        assert secure_logger.logger.name == "test_logger"
        
        # Check that sensitive data filter is added
        filters = secure_logger.logger.filters
        assert any(isinstance(f, SensitiveDataFilter) for f in filters)
    
    def test_info_logging(self, secure_logger):
        """Test info logging with context"""
        with patch.object(secure_logger.logger, 'info') as mock_info:
            secure_logger.info("Test message", request_id="123", email_content="test content")
            
            # Verify logger.info was called
            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            
            assert "Test message" in call_args
            assert "request_id" in call_args
            assert '"email_content":' not in call_args  # Should be sanitized (raw content not logged)
            assert "email_content_length" in call_args
            assert "email_content_present" in call_args
    
    def test_sanitize_dict(self, secure_logger):
        """Test dictionary sanitization"""
        data = {
            "email": "user@example.com",
            "content": "Email body content",
            "sender": "sender@test.com",
            "normal_field": "normal_value"
        }
        
        sanitized = secure_logger._sanitize_dict(data)
        
        assert sanitized["email"] == "[EMAIL_REDACTED]"
        assert sanitized["sender"] == "[EMAIL_REDACTED]"
        assert sanitized["content_length"] == len("Email body content")
        assert sanitized["content_present"] is True
        assert sanitized["normal_field"] == "normal_value"
    
    def test_log_analysis_start(self, secure_logger):
        """Test analysis start logging"""
        with patch.object(secure_logger, 'info') as mock_info:
            secure_logger.log_analysis_start("req123", 5000, "192.168.1.1")
            
            mock_info.assert_called_once_with(
                "Email analysis started",
                request_id="req123",
                email_content_length=5000,
                client_ip="192.168.1.1"
            )
    
    def test_log_analysis_complete(self, secure_logger):
        """Test analysis completion logging"""
        with patch.object(secure_logger, 'info') as mock_info:
            secure_logger.log_analysis_complete(
                "req123", 2.5, "openai", True, 3
            )
            
            mock_info.assert_called_once_with(
                "Email analysis completed",
                request_id="req123",
                processing_time_seconds=2.5,
                llm_provider="openai",
                success=True,
                ioc_count=3
            )
    
    def test_log_error_with_context(self, secure_logger):
        """Test error logging with context"""
        error = ValueError("Test error")
        
        with patch.object(secure_logger, 'error') as mock_error:
            secure_logger.log_error_with_context(
                error, "req123", "test_operation", extra_field="value"
            )
            
            mock_error.assert_called_once_with(
                "Error in test_operation",
                error=error,
                request_id="req123",
                extra_field="value"
            )
    
    def test_log_security_event(self, secure_logger):
        """Test security event logging"""
        with patch.object(secure_logger, 'warning') as mock_warning:
            secure_logger.log_security_event(
                "suspicious_activity", "192.168.1.1", "Multiple failed attempts"
            )
            
            mock_warning.assert_called_once_with(
                "Security event: suspicious_activity",
                event_type="suspicious_activity",
                client_ip="192.168.1.1",
                details="Multiple failed attempts"
            )


class TestExtractSafeEmailMetadata:
    """Test safe email metadata extraction"""
    
    def test_basic_metadata_extraction(self):
        """Test basic metadata extraction"""
        email_content = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000

This is the email body content.
"""
        
        metadata = extract_safe_email_metadata(email_content)
        
        assert metadata["content_length"] == len(email_content)
        assert metadata["line_count"] == email_content.count('\n')
        assert metadata["has_headers"] is True
        assert metadata["has_subject"] is True
        assert metadata["has_date"] is True
        assert metadata["subject_length"] == len(" Test Email")  # Includes space after :
    
    def test_html_email_detection(self):
        """Test HTML email detection"""
        html_email = """From: sender@example.com
Subject: HTML Email

<html>
<body>
<p>This is HTML content</p>
</body>
</html>
"""
        
        metadata = extract_safe_email_metadata(html_email)
        
        assert metadata["has_html"] is True
    
    def test_attachment_detection(self):
        """Test attachment detection"""
        email_with_attachment = """From: sender@example.com
Subject: Email with attachment
Content-Disposition: attachment; filename="document.pdf"

Email body
"""
        
        metadata = extract_safe_email_metadata(email_with_attachment)
        
        assert metadata["has_attachments"] is True
    
    def test_content_type_extraction(self):
        """Test content type extraction"""
        email_content = """From: sender@example.com
Subject: Test
Content-Type: text/html; charset=utf-8

Body content
"""
        
        metadata = extract_safe_email_metadata(email_content)
        
        assert metadata["content_type"] == "text/html"
    
    def test_malformed_email_handling(self):
        """Test handling of malformed email content"""
        malformed_email = "This is not a proper email format"
        
        # Should not raise an exception
        metadata = extract_safe_email_metadata(malformed_email)
        
        assert metadata["content_length"] == len(malformed_email)
        assert metadata["has_headers"] is False
    
    def test_empty_email_handling(self):
        """Test handling of empty email content"""
        metadata = extract_safe_email_metadata("")
        
        assert metadata["content_length"] == 0
        assert metadata["line_count"] == 0
        assert metadata["has_headers"] is False


def test_get_secure_logger():
    """Test secure logger factory function"""
    logger = get_secure_logger("test_module")
    
    assert isinstance(logger, SecureLogger)
    assert logger.logger.name == "test_module"