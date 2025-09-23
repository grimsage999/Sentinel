"""
Tests for security and performance features
"""

import pytest
import asyncio
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime

from app.main import app
from app.core.security import (
    sanitize_email_content,
    validate_content_size,
    detect_malicious_patterns,
    generate_request_id,
    email_content_manager,
    security_metrics
)
from app.utils.performance import performance_monitor, RequestMetrics
from app.middleware.security import get_security_status


class TestSecurityFeatures:
    """Test security-related functionality"""
    
    def test_sanitize_email_content_removes_scripts(self):
        """Test that script tags are removed from email content"""
        malicious_content = """
        From: test@example.com
        Subject: Test Email
        
        <script>alert('xss')</script>
        This is the email body.
        <script src="malicious.js"></script>
        """
        
        sanitized = sanitize_email_content(malicious_content)
        
        assert "<script>" not in sanitized
        assert "alert('xss')" not in sanitized
        assert "This is the email body." in sanitized
        assert "[POTENTIALLY_MALICIOUS_CONTENT_REMOVED]" in sanitized
    
    def test_sanitize_email_content_removes_javascript_urls(self):
        """Test that javascript: URLs are neutralized"""
        malicious_content = """
        From: test@example.com
        Subject: Test Email
        
        Click here: <a href="javascript:alert('xss')">Link</a>
        """
        
        sanitized = sanitize_email_content(malicious_content)
        
        assert "javascript:" not in sanitized
        assert "javascript_NEUTRALIZED:" in sanitized or "[POTENTIALLY_MALICIOUS_CONTENT_REMOVED]" in sanitized
    
    def test_validate_content_size_accepts_valid_content(self):
        """Test that valid-sized content is accepted"""
        content = "From: test@example.com\nSubject: Test\n\nThis is a test email."
        
        is_valid, error_msg = validate_content_size(content, max_size_mb=1)
        
        assert is_valid is True
        assert error_msg is None
    
    def test_validate_content_size_rejects_oversized_content(self):
        """Test that oversized content is rejected"""
        # Create content larger than 1MB
        large_content = "A" * (1024 * 1024 + 1)
        
        is_valid, error_msg = validate_content_size(large_content, max_size_mb=1)
        
        assert is_valid is False
        assert "exceeds maximum size" in error_msg
    
    def test_detect_malicious_patterns_finds_scripts(self):
        """Test that malicious script patterns are detected"""
        malicious_content = """
        <script>alert('xss')</script>
        <iframe src="malicious.html"></iframe>
        """
        
        threats = detect_malicious_patterns(malicious_content)
        
        assert len(threats) > 0
        script_threats = [t for t in threats if t['type'] == 'script_injection']
        assert len(script_threats) > 0
        assert script_threats[0]['severity'] == 'high'
    
    def test_detect_malicious_patterns_finds_dangerous_attachments(self):
        """Test that dangerous file extensions are detected"""
        malicious_content = """
        From: test@example.com
        Subject: Important Document
        
        Please open the attached file: document.exe
        Also see: malware.scr
        """
        
        threats = detect_malicious_patterns(malicious_content)
        
        dangerous_threats = [t for t in threats if t['type'] == 'dangerous_attachment']
        assert len(dangerous_threats) >= 1
        assert any('.exe' in t['description'] for t in dangerous_threats)
    
    def test_detect_malicious_patterns_finds_ip_urls(self):
        """Test that IP-based URLs are detected"""
        malicious_content = """
        From: test@example.com
        Subject: Click Here
        
        Visit: http://192.168.1.1/malicious
        Also: https://10.0.0.1:8080/phishing
        """
        
        threats = detect_malicious_patterns(malicious_content)
        
        ip_threats = [t for t in threats if t['type'] == 'ip_based_urls']
        assert len(ip_threats) > 0
        assert ip_threats[0]['severity'] == 'medium'
    
    def test_generate_request_id_creates_unique_ids(self):
        """Test that request IDs are unique"""
        id1 = generate_request_id()
        id2 = generate_request_id()
        
        assert id1 != id2
        assert len(id1) > 10  # Should be reasonably long
        assert len(id2) > 10


class TestEmailContentManager:
    """Test email content memory management"""
    
    def test_store_and_retrieve_content(self):
        """Test storing and retrieving email content"""
        content = "Test email content"
        content_id = email_content_manager.store_content("test_id", content)
        
        retrieved = email_content_manager.get_content("test_id")
        
        assert retrieved == content
        
        # Cleanup
        email_content_manager.clear_content("test_id")
    
    def test_clear_content_removes_from_memory(self):
        """Test that clearing content removes it from memory"""
        content = "Test email content"
        email_content_manager.store_content("test_id", content)
        
        email_content_manager.clear_content("test_id")
        retrieved = email_content_manager.get_content("test_id")
        
        assert retrieved is None
    
    def test_cleanup_expired_removes_old_content(self):
        """Test that expired content is cleaned up"""
        # This test would need to mock datetime to test expiration
        # For now, just test that cleanup_expired runs without error
        cleaned_count = email_content_manager.cleanup_expired()
        assert isinstance(cleaned_count, int)


class TestPerformanceMonitoring:
    """Test performance monitoring functionality"""
    
    def test_start_and_complete_request_tracking(self):
        """Test request performance tracking lifecycle"""
        request_id = "test_request_123"
        
        # Start tracking
        metrics = performance_monitor.start_request(
            request_id=request_id,
            endpoint="/api/analyze",
            method="POST",
            email_size=1024
        )
        
        assert metrics.request_id == request_id
        assert metrics.endpoint == "/api/analyze"
        assert metrics.email_size == 1024
        
        # Update metrics
        performance_monitor.update_request(
            request_id=request_id,
            llm_provider="openai",
            llm_processing_time=2.5,
            ioc_count=5
        )
        
        # Complete tracking
        completed_metrics = performance_monitor.complete_request(
            request_id=request_id,
            status_code=200
        )
        
        assert completed_metrics is not None
        assert completed_metrics.status_code == 200
        assert completed_metrics.llm_provider == "openai"
        assert completed_metrics.processing_time is not None
    
    def test_get_current_metrics(self):
        """Test getting current performance metrics"""
        metrics = performance_monitor.get_current_metrics()
        
        assert 'active_requests' in metrics
        assert 'completed_requests' in metrics
        assert 'avg_response_time_seconds' in metrics
        assert 'error_rate' in metrics
        assert 'system_metrics' in metrics
    
    def test_check_capacity_when_available(self):
        """Test capacity check when system has capacity"""
        can_process, message = performance_monitor.check_capacity()
        
        # Should have capacity in test environment
        assert can_process is True
        assert "available" in message.lower()


class TestSecurityMetrics:
    """Test security metrics tracking"""
    
    def test_record_and_get_threat_metrics(self):
        """Test recording and retrieving threat metrics"""
        # Reset metrics for clean test
        security_metrics.reset_metrics()
        
        # Record some threats
        security_metrics.record_threat("script_injection")
        security_metrics.record_threat("dangerous_attachment")
        security_metrics.record_threat("script_injection")  # Duplicate
        
        metrics = security_metrics.get_metrics()
        
        assert metrics['threat_counts']['script_injection'] == 2
        assert metrics['threat_counts']['dangerous_attachment'] == 1
    
    def test_record_sanitization_events(self):
        """Test recording sanitization events"""
        security_metrics.reset_metrics()
        
        security_metrics.record_sanitization()
        security_metrics.record_sanitization()
        
        metrics = security_metrics.get_metrics()
        
        assert metrics['sanitization_counts'] == 2
    
    def test_record_blocked_requests(self):
        """Test recording blocked request events"""
        security_metrics.reset_metrics()
        
        security_metrics.record_blocked_request()
        
        metrics = security_metrics.get_metrics()
        
        assert metrics['blocked_requests'] == 1


class TestSecurityMiddleware:
    """Test security middleware functionality"""
    
    def test_get_security_status(self):
        """Test getting security status"""
        status = get_security_status()
        
        assert 'security_features' in status
        assert 'limits' in status
        assert 'metrics' in status
        assert 'performance' in status
        
        # Check security features
        features = status['security_features']
        assert 'content_sanitization' in features
        assert 'security_headers' in features
        
        # Check limits
        limits = status['limits']
        assert 'max_email_size_mb' in limits
        assert 'max_concurrent_requests' in limits


class TestSecurityIntegration:
    """Integration tests for security features"""
    
    def test_analyze_endpoint_with_malicious_content(self):
        """Test that analyze endpoint handles malicious content safely"""
        client = TestClient(app)
        
        malicious_email = """
        From: attacker@evil.com
        Subject: <script>alert('xss')</script>
        
        Click here: <a href="javascript:alert('xss')">Malicious Link</a>
        Download: malware.exe
        """
        
        # Mock the analysis services to avoid actual LLM calls
        with patch('app.api.dependencies.get_analysis_services') as mock_services:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze_email.return_value = MagicMock(
                intent=MagicMock(primary="credential_theft"),
                risk_score=MagicMock(score=8),
                processing_time=1.5,
                metadata={"llm_provider": "openai"}
            )
            
            mock_services.return_value = {
                "email_parser": MagicMock(),
                "ioc_extractor": MagicMock(),
                "llm_analyzer": mock_analyzer
            }
            
            # Configure mock returns
            mock_services.return_value["email_parser"].parse_email.return_value = (
                MagicMock(
                    from_address="attacker@evil.com",
                    to_addresses=["victim@company.com"],
                    subject="Test Subject",
                    date="2024-01-01",
                    reply_to=None,
                    message_id="test123",
                    received_headers=[],
                    x_headers={}
                ),
                "Email body content"
            )
            
            from app.models.analysis_models import IOCCollection
            mock_services.return_value["ioc_extractor"].extract_all_iocs.return_value = IOCCollection()
            
            response = client.post(
                "/api/analyze",
                json={"email_content": malicious_email}
            )
            
            # Should succeed but content should be sanitized
            assert response.status_code == 200
            
            # Verify security features were applied
            response_data = response.json()
            assert response_data["success"] is True
            assert "security_features_applied" in response_data["meta"]
    
    def test_analyze_endpoint_rejects_oversized_content(self):
        """Test that oversized content is rejected"""
        client = TestClient(app)
        
        # Create content larger than the configured limit
        large_content = "A" * (2 * 1024 * 1024)  # 2MB
        
        response = client.post(
            "/api/analyze",
            json={"email_content": large_content}
        )
        
        # Should be rejected with 413 or 400 status
        assert response.status_code in [400, 413]
        
        response_data = response.json()
        assert response_data["success"] is False
        assert "size" in response_data["error"]["message"].lower()
    
    def test_health_security_endpoint(self):
        """Test the security status health endpoint"""
        client = TestClient(app)
        
        response = client.get("/api/health/security")
        
        assert response.status_code == 200
        
        data = response.json()
        assert 'security_features' in data
        assert 'limits' in data
        assert 'metrics' in data


@pytest.fixture(autouse=True)
def cleanup_after_tests():
    """Clean up after each test"""
    yield
    
    # Reset security metrics
    security_metrics.reset_metrics()
    
    # Clear any stored email content
    email_content_manager.cleanup_expired()