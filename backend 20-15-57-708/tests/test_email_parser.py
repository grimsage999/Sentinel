"""
Comprehensive unit tests for EmailParser service
Tests email parsing, validation, and sanitization functionality with extensive edge cases
"""

import pytest
from unittest.mock import patch, MagicMock
import email
from email.message import EmailMessage

from app.services.email_parser import EmailParser, EmailHeaders
from app.core.exceptions import ValidationException
from app.utils.validators import (
    validate_email_size,
    validate_email_headers,
    detect_malicious_patterns,
    sanitize_malicious_content,
    validate_header_format
)


class TestEmailParser:
    """Test cases for EmailParser class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.parser = EmailParser()
        
        # Sample valid email content
        self.valid_email = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>

This is a test email body.
It contains multiple lines.
"""
        
        # Sample multipart email
        self.multipart_email = """From: sender@example.com
To: recipient@example.com
Subject: Multipart Test
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=utf-8

Plain text content here.

--boundary123
Content-Type: text/html; charset=utf-8

<html><body>HTML content here.</body></html>

--boundary123--
"""
    
    def test_parse_valid_email(self):
        """Test parsing a valid email"""
        headers, body = self.parser.parse_email(self.valid_email)
        
        assert isinstance(headers, EmailHeaders)
        assert headers.from_address == "sender@example.com"
        assert headers.subject == "Test Email"
        assert "test email body" in body.lower()
    
    def test_parse_headers_only(self):
        """Test extracting headers only"""
        headers = self.parser.parse_headers(self.valid_email)
        
        assert headers.from_address == "sender@example.com"
        assert headers.to_addresses == ["recipient@example.com"]
        assert headers.subject == "Test Email"
        assert headers.message_id == "<test@example.com>"
    
    def test_extract_body_only(self):
        """Test extracting body only"""
        body = self.parser.extract_body(self.valid_email)
        
        assert "test email body" in body.lower()
        assert "multiple lines" in body.lower()
    
    def test_parse_multipart_email(self):
        """Test parsing multipart email"""
        headers, body = self.parser.parse_email(self.multipart_email)
        
        assert headers.from_address == "sender@example.com"
        assert "plain text content" in body.lower()
        assert "html content" in body.lower()
    
    def test_validate_email_format_valid(self):
        """Test email format validation with valid email"""
        assert self.parser.validate_email_format(self.valid_email) is True
    
    def test_validate_email_format_invalid(self):
        """Test email format validation with invalid email"""
        invalid_email = "This is not an email"
        assert self.parser.validate_email_format(invalid_email) is False
    
    def test_parse_empty_email(self):
        """Test parsing empty email content"""
        with pytest.raises(ValidationException):
            self.parser.parse_email("")
    
    def test_parse_too_large_email(self):
        """Test parsing email that exceeds size limit"""
        large_email = "From: test@example.com\nSubject: Test\n\n" + "x" * (1024 * 1024 + 1)
        with pytest.raises(ValidationException):
            self.parser.parse_email(large_email)
    
    def test_parse_malformed_email(self):
        """Test parsing malformed email content"""
        malformed_email = "From: invalid-email-format\nNo proper headers\n"
        
        # Should not raise exception but may have limited parsing
        headers, body = self.parser.parse_email(malformed_email)
        assert isinstance(headers, EmailHeaders)
    
    def test_parse_email_with_special_characters(self):
        """Test parsing email with special characters and encoding"""
        special_email = """From: sender@example.com
To: recipient@example.com
Subject: =?UTF-8?B?VGVzdCBTdWJqZWN0?=
Date: Mon, 1 Jan 2024 12:00:00 +0000

Email with special characters: àáâãäå
"""
        headers, body = self.parser.parse_email(special_email)
        assert headers.from_address == "sender@example.com"
        assert "special characters" in body
    
    def test_parse_email_with_multiple_recipients(self):
        """Test parsing email with multiple recipients"""
        multi_recipient_email = """From: sender@example.com
To: recipient1@example.com, recipient2@example.com
Cc: cc1@example.com, cc2@example.com
Subject: Multiple Recipients

Test body
"""
        headers, _ = self.parser.parse_email(multi_recipient_email)
        assert len(headers.to_addresses) == 2
        assert "recipient1@example.com" in headers.to_addresses[0]
        assert "recipient2@example.com" in headers.to_addresses[1]
    
    def test_parse_email_with_x_headers(self):
        """Test parsing email with custom X-headers"""
        x_header_email = """From: sender@example.com
To: recipient@example.com
Subject: X-Header Test
X-Spam-Score: 5.0
X-Custom-Header: Custom Value

Test body
"""
        headers, _ = self.parser.parse_email(x_header_email)
        assert "X-Spam-Score" in headers.x_headers
        assert headers.x_headers["X-Spam-Score"] == "5.0"
    
    def test_clean_header_value(self):
        """Test header value cleaning"""
        # Test with control characters
        dirty_value = "Test\x00Value\x0B\x0CClean"
        cleaned = self.parser._clean_header_value(dirty_value)
        assert cleaned == "TestValueClean"  # Control chars are removed, not replaced with spaces
        
        # Test with None
        assert self.parser._clean_header_value(None) is None
        
        # Test with empty string
        assert self.parser._clean_header_value("") is None
    
    def test_parse_address_list(self):
        """Test address list parsing"""
        address_string = "user1@example.com, user2@example.com, user3@example.com"
        addresses = self.parser._parse_address_list(address_string)
        
        assert len(addresses) == 3
        assert "user1@example.com" in addresses
        assert "user2@example.com" in addresses
        assert "user3@example.com" in addresses


class TestEmailValidation:
    """Test cases for email validation functions"""
    
    def test_validate_email_size_valid(self):
        """Test email size validation with valid content"""
        valid_content = "From: test@example.com\nSubject: Test\n\nBody content"
        is_valid, error = validate_email_size(valid_content)
        assert is_valid is True
        assert error is None
    
    def test_validate_email_size_empty(self):
        """Test email size validation with empty content"""
        is_valid, error = validate_email_size("")
        assert is_valid is False
        assert "cannot be empty" in error
    
    def test_validate_email_size_too_small(self):
        """Test email size validation with content too small"""
        small_content = "test"
        is_valid, error = validate_email_size(small_content)
        assert is_valid is False
        assert "too short" in error
    
    def test_validate_email_size_too_large(self):
        """Test email size validation with content too large"""
        large_content = "x" * (1024 * 1024 + 1)
        is_valid, error = validate_email_size(large_content)
        assert is_valid is False
        assert "too large" in error
    
    def test_validate_email_headers_valid(self):
        """Test email header validation with valid headers"""
        valid_email = "From: test@example.com\nSubject: Test\nTo: recipient@example.com\n\nBody"
        is_valid, missing = validate_email_headers(valid_email)
        assert is_valid is True
        assert len(missing) <= 2  # May be missing Date header (recommended)
    
    def test_validate_email_headers_missing_required(self):
        """Test email header validation with missing required headers"""
        invalid_email = "To: recipient@example.com\n\nBody without From or Subject"
        is_valid, missing = validate_email_headers(invalid_email)
        assert is_valid is False
        assert "From" in missing
        assert "Subject" in missing
    
    def test_detect_malicious_patterns_clean(self):
        """Test malicious pattern detection with clean content"""
        clean_content = "From: test@example.com\nSubject: Clean Email\n\nThis is a clean email."
        patterns = detect_malicious_patterns(clean_content)
        assert len(patterns) == 0
    
    def test_detect_malicious_patterns_script(self):
        """Test malicious pattern detection with script tags"""
        malicious_content = "From: test@example.com\n\n<script>alert('xss')</script>"
        patterns = detect_malicious_patterns(malicious_content)
        assert any("JavaScript" in pattern for pattern in patterns)
    
    def test_detect_malicious_patterns_suspicious_extensions(self):
        """Test malicious pattern detection with suspicious file extensions"""
        malicious_content = "From: test@example.com\n\nPlease run attachment.exe"
        patterns = detect_malicious_patterns(malicious_content)
        assert any(".exe" in pattern for pattern in patterns)
    
    def test_detect_malicious_patterns_ip_urls(self):
        """Test malicious pattern detection with IP-based URLs"""
        malicious_content = "From: test@example.com\n\nVisit http://192.168.1.1/malware"
        patterns = detect_malicious_patterns(malicious_content)
        assert any("IP address" in pattern for pattern in patterns)
    
    def test_detect_malicious_patterns_url_shorteners(self):
        """Test malicious pattern detection with URL shorteners"""
        malicious_content = "From: test@example.com\n\nClick here: http://bit.ly/suspicious"
        patterns = detect_malicious_patterns(malicious_content)
        assert any("shortener" in pattern for pattern in patterns)
    
    def test_detect_malicious_patterns_executable_files(self):
        """Test detection of various executable file types"""
        # Should detect .exe files
        exe_content = "From: test@example.com\n\nPlease run malware.exe"
        patterns = detect_malicious_patterns(exe_content)
        assert any(".exe" in pattern for pattern in patterns)
        
        # Should detect .bat files
        bat_content = "From: test@example.com\n\nRun this script.bat file"
        patterns = detect_malicious_patterns(bat_content)
        assert any(".bat" in pattern for pattern in patterns)
        
        # Should NOT detect extensions in normal email domains
        email_content = "From: user@company.com\nTo: admin@example.com\n\nNormal email"
        patterns = detect_malicious_patterns(email_content)
        extension_patterns = [p for p in patterns if any(ext in p for ext in ['.exe', '.bat', '.com'])]
        assert len(extension_patterns) == 0
    
    def test_sanitize_malicious_content_scripts(self):
        """Test sanitization of malicious script content"""
        malicious_content = "Email content <script>alert('xss')</script> more content"
        sanitized = sanitize_malicious_content(malicious_content)
        assert "<script>" not in sanitized
        assert "[SCRIPT_REMOVED]" in sanitized
    
    def test_sanitize_malicious_content_iframes(self):
        """Test sanitization of malicious iframe content"""
        malicious_content = "Email content <iframe src='evil.com'></iframe> more content"
        sanitized = sanitize_malicious_content(malicious_content)
        assert "<iframe>" not in sanitized
        assert "[IFRAME_REMOVED]" in sanitized
    
    def test_sanitize_malicious_content_javascript_urls(self):
        """Test sanitization of javascript: URLs"""
        malicious_content = "Click <a href='javascript:alert(1)'>here</a>"
        sanitized = sanitize_malicious_content(malicious_content)
        assert "javascript:" not in sanitized
        assert "javascript_NEUTRALIZED:" in sanitized
    
    def test_validate_header_format_valid_email(self):
        """Test header format validation with valid email header"""
        is_valid, error = validate_header_format("From", "user@example.com")
        assert is_valid is True
        assert error is None
    
    def test_validate_header_format_invalid_email(self):
        """Test header format validation with invalid email header"""
        is_valid, error = validate_header_format("From", "invalid-email")
        assert is_valid is False
        assert "valid email address" in error
    
    def test_validate_header_format_empty(self):
        """Test header format validation with empty header"""
        is_valid, error = validate_header_format("Subject", "")
        assert is_valid is False
        assert "cannot be empty" in error
    
    def test_validate_header_format_too_long(self):
        """Test header format validation with header too long"""
        long_value = "x" * 1000
        is_valid, error = validate_header_format("Subject", long_value)
        assert is_valid is False
        assert "exceeds maximum length" in error


class TestEmailParserEdgeCases:
    """Test edge cases and error conditions"""
    
    def setup_method(self):
        self.parser = EmailParser()
    
    def test_parse_email_with_no_body(self):
        """Test parsing email with headers only, no body"""
        headers_only = """From: sender@example.com
To: recipient@example.com
Subject: No Body Email
"""
        headers, body = self.parser.parse_email(headers_only)
        assert headers.from_address == "sender@example.com"
        assert body == "" or body.strip() == ""
    
    def test_parse_email_with_binary_content(self):
        """Test parsing email with binary/encoded content"""
        binary_email = """From: sender@example.com
Subject: Binary Content
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

VGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBjb250ZW50
"""
        # Should not crash, may have limited body extraction
        headers, body = self.parser.parse_email(binary_email)
        assert headers.from_address == "sender@example.com"
    
    def test_parse_email_with_unicode_errors(self):
        """Test parsing email with unicode decoding issues"""
        # This should be handled gracefully by the error handling
        unicode_email = """From: sender@example.com
Subject: Unicode Test

Content with unicode: café résumé naïve
"""
        headers, body = self.parser.parse_email(unicode_email)
        assert headers.from_address == "sender@example.com"
        assert "unicode" in body.lower()
    
    def test_parse_email_with_very_long_lines(self):
        """Test parsing email with extremely long lines"""
        long_line = "x" * 2000
        long_line_email = f"""From: sender@example.com
Subject: Long Line Test

{long_line}
"""
        # Should handle long lines gracefully
        headers, body = self.parser.parse_email(long_line_email)
        assert headers.from_address == "sender@example.com"
    
    def test_parse_email_with_malformed_headers(self):
        """Test parsing email with malformed headers"""
        malformed_email = """From sender@example.com
To: recipient@example.com
Subject Test Subject
Date: Invalid Date Format

Body content here
"""
        # Should handle malformed headers gracefully
        headers, body = self.parser.parse_email(malformed_email)
        assert "body content" in body.lower()
    
    def test_parse_email_with_missing_separators(self):
        """Test parsing email without proper header/body separator"""
        no_separator_email = """From: sender@example.com
To: recipient@example.com
Subject: No Separator
Body starts immediately without blank line"""
        
        headers, body = self.parser.parse_email(no_separator_email)
        assert headers.from_address == "sender@example.com"
    
    def test_parse_email_with_folded_headers(self):
        """Test parsing email with folded (multi-line) headers"""
        folded_email = """From: sender@example.com
To: recipient1@example.com,
 recipient2@example.com,
 recipient3@example.com
Subject: This is a very long subject line that
 continues on the next line
Date: Mon, 1 Jan 2024 12:00:00 +0000

Body content
"""
        headers, body = self.parser.parse_email(folded_email)
        assert headers.from_address == "sender@example.com"
        assert len(headers.to_addresses) >= 1  # Should parse folded addresses
    
    def test_parse_email_with_encoded_headers(self):
        """Test parsing email with encoded headers (RFC 2047)"""
        encoded_email = """From: =?UTF-8?B?VGVzdCBTZW5kZXI=?= <sender@example.com>
To: recipient@example.com
Subject: =?UTF-8?Q?Test_Subject_With_=C3=A9ncoding?=
Date: Mon, 1 Jan 2024 12:00:00 +0000

Body with encoded subject
"""
        headers, body = self.parser.parse_email(encoded_email)
        assert headers.from_address is not None
        assert headers.subject is not None
    
    def test_parse_email_with_attachment_indicators(self):
        """Test parsing email with attachment-related headers"""
        attachment_email = """From: sender@example.com
To: recipient@example.com
Subject: Email with Attachment
Content-Type: multipart/mixed; boundary="boundary123"
MIME-Version: 1.0

--boundary123
Content-Type: text/plain

This email has an attachment.

--boundary123
Content-Type: application/pdf
Content-Disposition: attachment; filename="document.pdf"

[Binary content would be here]

--boundary123--
"""
        headers, body = self.parser.parse_email(attachment_email)
        assert headers.from_address == "sender@example.com"
        assert "attachment" in body.lower()
    
    def test_parse_email_with_nested_multipart(self):
        """Test parsing email with nested multipart structure"""
        nested_email = """From: sender@example.com
To: recipient@example.com
Subject: Nested Multipart
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain

Plain text version

--inner
Content-Type: text/html

<html><body>HTML version</body></html>

--inner--

--outer
Content-Type: text/plain
Content-Disposition: attachment; filename="file.txt"

Attachment content

--outer--
"""
        headers, body = self.parser.parse_email(nested_email)
        assert headers.from_address == "sender@example.com"
        assert "plain text" in body.lower() or "html version" in body.lower()
    
    @patch('app.services.email_parser.logger')
    def test_parse_email_logging_on_error(self, mock_logger):
        """Test that parsing errors are logged appropriately"""
        # Force an error by mocking the parser
        with patch.object(self.parser, 'parser') as mock_parser:
            mock_parser.parsestr.side_effect = Exception("Parsing failed")
            
            with pytest.raises(ValidationException):
                self.parser.parse_email("From: test@example.com\n\nBody")
            
            mock_logger.error.assert_called_once()
    
    def test_parse_email_with_suspicious_content(self):
        """Test parsing email with potentially malicious content"""
        suspicious_email = """From: attacker@evil.com
To: victim@company.com
Subject: <script>alert('xss')</script>

Click here: http://malicious-site.com/phishing
Download: malware.exe
Visit: javascript:alert('evil')
"""
        # Should parse without crashing, content sanitization handled elsewhere
        headers, body = self.parser.parse_email(suspicious_email)
        assert headers.from_address == "attacker@evil.com"
        assert "malicious-site.com" in body
    
    def test_parse_email_memory_efficiency(self):
        """Test parsing large email for memory efficiency"""
        # Create a reasonably large email (but within limits)
        large_body = "This is a test line.\n" * 1000  # ~20KB
        large_email = f"""From: sender@example.com
To: recipient@example.com
Subject: Large Email Test

{large_body}
"""
        headers, body = self.parser.parse_email(large_email)
        assert headers.from_address == "sender@example.com"
        assert len(body) > 10000  # Should contain the large body
    
    def test_parse_email_with_null_bytes(self):
        """Test parsing email with null bytes and control characters"""
        null_byte_email = """From: sender@example.com\x00
To: recipient@example.com
Subject: Test\x0B\x0CSubject

Body with\x00null bytes and\x1Fcontrol chars
"""
        headers, body = self.parser.parse_email(null_byte_email)
        # Control characters should be cleaned
        assert "\x00" not in headers.from_address if headers.from_address else True
        assert "\x0B" not in headers.subject if headers.subject else True