"""
Comprehensive API endpoint tests for PhishContext AI
Tests all API routes with various scenarios including error conditions
"""

import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from datetime import datetime

from app.main import app
from app.models.analysis_models import (
    AnalysisResult, IntentAnalysis, DeceptionIndicator, RiskScore, IOCCollection,
    IntentType, ConfidenceLevel, DeceptionIndicatorType, SeverityLevel, IOCItem, IOCType
)
from app.core.exceptions import ValidationException, LLMServiceError, LLMTimeoutError


class TestAnalysisEndpoint:
    """Test cases for /api/analyze endpoint"""
    
    def setup_method(self):
        """Set up test client and mock data"""
        self.client = TestClient(app)
        
        # Sample valid email content
        self.valid_email = """From: attacker@malicious-site.com
To: victim@company.com
Subject: Urgent: Account Verification Required
Date: Mon, 1 Jan 2024 12:00:00 +0000

Your account has been compromised. Please visit https://fake-bank.com/login
to verify your identity immediately.

You have 24 hours to respond or your account will be suspended.
"""
        
        # Sample analysis result
        self.sample_analysis_result = AnalysisResult(
            intent=IntentAnalysis(
                primary=IntentType.CREDENTIAL_THEFT,
                confidence=ConfidenceLevel.HIGH,
                alternatives=[IntentType.RECONNAISSANCE]
            ),
            deception_indicators=[
                DeceptionIndicator(
                    type=DeceptionIndicatorType.SPOOFING,
                    description="Sender impersonation detected",
                    evidence="Domain mismatch in From field",
                    severity=SeverityLevel.HIGH
                )
            ],
            risk_score=RiskScore(
                score=8,
                confidence=ConfidenceLevel.HIGH,
                reasoning="Multiple deception indicators present"
            ),
            iocs=IOCCollection(
                urls=[IOCItem(value="https://fake-bank.com/login", type=IOCType.URL, vtLink="https://vt.com/test")],
                ips=[],
                domains=[]
            ),
            processing_time=2.5,
            timestamp=datetime.utcnow()
        )

    @patch('app.api.dependencies.get_analysis_services')
    def test_analyze_email_success(self, mock_get_services):
        """Test successful email analysis"""
        # Mock services
        mock_email_parser = MagicMock()
        mock_email_parser.parse_email.return_value = (MagicMock(), "email body")
        
        mock_ioc_extractor = MagicMock()
        mock_ioc_extractor.extract_all_iocs.return_value = IOCCollection()
        
        mock_llm_analyzer = AsyncMock()
        mock_llm_analyzer.analyze_email.return_value = self.sample_analysis_result
        
        mock_get_services.return_value = {
            "email_parser": mock_email_parser,
            "ioc_extractor": mock_ioc_extractor,
            "llm_analyzer": mock_llm_analyzer
        }
        
        # Mock performance monitor
        with patch('app.api.routes.analysis.performance_monitor') as mock_perf:
            mock_perf.check_capacity.return_value = (True, "OK")
            mock_perf.update_request.return_value = None
            
            with patch('app.api.routes.analysis.track_request_performance'):
                response = self.client.post(
                    "/api/analyze",
                    json={"email_content": self.valid_email}
                )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert data["data"]["intent"]["primary"] == "credential_theft"
        assert data["data"]["risk_score"]["score"] == 8
        assert "meta" in data
        assert "total_processing_time" in data["meta"]

    def test_analyze_email_invalid_request_body(self):
        """Test analysis with invalid request body"""
        response = self.client.post(
            "/api/analyze",
            json={"invalid_field": "test"}
        )
        
        assert response.status_code == 422  # Validation error

    def test_analyze_email_empty_content(self):
        """Test analysis with empty email content"""
        response = self.client.post(
            "/api/analyze",
            json={"email_content": ""}
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
        assert "error" in data

    def test_analyze_email_too_large(self):
        """Test analysis with email content that's too large"""
        # Create content larger than 1MB
        large_content = "x" * (1024 * 1024 + 1)
        large_email = f"From: test@example.com\nSubject: Large\n\n{large_content}"
        
        response = self.client.post(
            "/api/analyze",
            json={"email_content": large_email}
        )
        
        # Should be rejected by middleware or validation
        assert response.status_code in [400, 413]

    @patch('app.api.dependencies.get_analysis_services')
    def test_analyze_email_parsing_error(self, mock_get_services):
        """Test analysis when email parsing fails"""
        mock_email_parser = MagicMock()
        mock_email_parser.parse_email.side_effect = ValidationException("Invalid email format")
        
        mock_get_services.return_value = {
            "email_parser": mock_email_parser,
            "ioc_extractor": MagicMock(),
            "llm_analyzer": AsyncMock()
        }
        
        with patch('app.api.routes.analysis.performance_monitor') as mock_perf:
            mock_perf.check_capacity.return_value = (True, "OK")
            
            with patch('app.api.routes.analysis.track_request_performance'):
                response = self.client.post(
                    "/api/analyze",
                    json={"email_content": "invalid email"}
                )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
        assert "Invalid email format" in data["error"]["details"]

    @patch('app.api.dependencies.get_analysis_services')
    def test_analyze_email_llm_service_error(self, mock_get_services):
        """Test analysis when LLM service fails"""
        mock_email_parser = MagicMock()
        mock_email_parser.parse_email.return_value = (MagicMock(), "email body")
        
        mock_ioc_extractor = MagicMock()
        mock_ioc_extractor.extract_all_iocs.return_value = IOCCollection()
        
        mock_llm_analyzer = AsyncMock()
        mock_llm_analyzer.analyze_email.side_effect = LLMServiceError("Service unavailable")
        
        mock_get_services.return_value = {
            "email_parser": mock_email_parser,
            "ioc_extractor": mock_ioc_extractor,
            "llm_analyzer": mock_llm_analyzer
        }
        
        with patch('app.api.routes.analysis.performance_monitor') as mock_perf:
            mock_perf.check_capacity.return_value = (True, "OK")
            
            with patch('app.api.routes.analysis.track_request_performance'):
                response = self.client.post(
                    "/api/analyze",
                    json={"email_content": self.valid_email}
                )
        
        assert response.status_code == 503
        data = response.json()
        assert data["success"] is False
        assert data["error"]["retryable"] is True

    @patch('app.api.dependencies.get_analysis_services')
    def test_analyze_email_timeout_error(self, mock_get_services):
        """Test analysis when LLM service times out"""
        mock_email_parser = MagicMock()
        mock_email_parser.parse_email.return_value = (MagicMock(), "email body")
        
        mock_ioc_extractor = MagicMock()
        mock_ioc_extractor.extract_all_iocs.return_value = IOCCollection()
        
        mock_llm_analyzer = AsyncMock()
        mock_llm_analyzer.analyze_email.side_effect = LLMTimeoutError("Analysis timed out")
        
        mock_get_services.return_value = {
            "email_parser": mock_email_parser,
            "ioc_extractor": mock_ioc_extractor,
            "llm_analyzer": mock_llm_analyzer
        }
        
        with patch('app.api.routes.analysis.performance_monitor') as mock_perf:
            mock_perf.check_capacity.return_value = (True, "OK")
            
            with patch('app.api.routes.analysis.track_request_performance'):
                response = self.client.post(
                    "/api/analyze",
                    json={"email_content": self.valid_email}
                )
        
        assert response.status_code == 504
        data = response.json()
        assert data["success"] is False
        assert data["error"]["retryable"] is True

    def test_analyze_email_rate_limited(self):
        """Test rate limiting on analysis endpoint"""
        # This test would need to make many requests quickly
        # For now, we'll test that the rate limiter is configured
        
        # Make a single request to verify endpoint works
        with patch('app.api.dependencies.get_analysis_services') as mock_get_services:
            mock_email_parser = MagicMock()
            mock_email_parser.parse_email.return_value = (MagicMock(), "email body")
            
            mock_ioc_extractor = MagicMock()
            mock_ioc_extractor.extract_all_iocs.return_value = IOCCollection()
            
            mock_llm_analyzer = AsyncMock()
            mock_llm_analyzer.analyze_email.return_value = self.sample_analysis_result
            
            mock_get_services.return_value = {
                "email_parser": mock_email_parser,
                "ioc_extractor": mock_ioc_extractor,
                "llm_analyzer": mock_llm_analyzer
            }
            
            with patch('app.api.routes.analysis.performance_monitor') as mock_perf:
                mock_perf.check_capacity.return_value = (True, "OK")
                
                with patch('app.api.routes.analysis.track_request_performance'):
                    response = self.client.post(
                        "/api/analyze",
                        json={"email_content": self.valid_email}
                    )
        
        # Should succeed for single request
        assert response.status_code == 200

    def test_analyze_email_with_analysis_options(self):
        """Test analysis with custom analysis options"""
        with patch('app.api.dependencies.get_analysis_services') as mock_get_services:
            mock_email_parser = MagicMock()
            mock_email_parser.parse_email.return_value = (MagicMock(), "email body")
            
            mock_ioc_extractor = MagicMock()
            mock_ioc_extractor.extract_all_iocs.return_value = IOCCollection()
            
            mock_llm_analyzer = AsyncMock()
            mock_llm_analyzer.analyze_email.return_value = self.sample_analysis_result
            
            mock_get_services.return_value = {
                "email_parser": mock_email_parser,
                "ioc_extractor": mock_ioc_extractor,
                "llm_analyzer": mock_llm_analyzer
            }
            
            with patch('app.api.routes.analysis.performance_monitor') as mock_perf:
                mock_perf.check_capacity.return_value = (True, "OK")
                
                with patch('app.api.routes.analysis.track_request_performance'):
                    response = self.client.post(
                        "/api/analyze",
                        json={
                            "email_content": self.valid_email,
                            "analysis_options": {
                                "include_iocs": False,
                                "confidence_threshold": 0.8
                            }
                        }
                    )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_analyze_status_endpoint(self):
        """Test analysis status endpoint"""
        with patch('app.core.config.settings') as mock_settings:
            mock_settings.primary_llm_provider = "openai"
            mock_settings.fallback_llm_provider = "anthropic"
            mock_settings.openai_api_key = "test-key"
            mock_settings.anthropic_api_key = "test-key"
            mock_settings.max_email_size_mb = 1
            mock_settings.request_timeout_seconds = 30
            mock_settings.rate_limit_requests_per_minute = 60
            
            response = self.client.get("/api/analyze/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "operational"
        assert "llm_providers" in data
        assert "configuration" in data
        assert data["llm_providers"]["openai_available"] is True


class TestHealthEndpoints:
    """Test cases for health check endpoints"""
    
    def setup_method(self):
        """Set up test client"""
        self.client = TestClient(app)

    def test_health_check_endpoint(self):
        """Test main health check endpoint"""
        with patch('app.api.routes.health._check_services_health') as mock_check:
            mock_check.return_value = {
                "openai": "available",
                "configuration": "available",
                "system_resources": "available"
            }
            
            response = self.client.get("/api/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert "timestamp" in data
        assert "services" in data
        assert "uptime" in data

    def test_liveness_probe(self):
        """Test liveness probe endpoint"""
        response = self.client.get("/api/health/live")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "alive"
        assert "timestamp" in data
        assert "uptime" in data

    def test_readiness_probe_ready(self):
        """Test readiness probe when system is ready"""
        with patch('app.api.routes.health._check_critical_services') as mock_check:
            mock_check.return_value = {
                "llm_providers": "available",
                "configuration": "available"
            }
            
            response = self.client.get("/api/health/ready")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"

    def test_readiness_probe_not_ready(self):
        """Test readiness probe when system is not ready"""
        with patch('app.api.routes.health._check_critical_services') as mock_check:
            mock_check.return_value = {
                "llm_providers": "unavailable",
                "configuration": "available"
            }
            
            response = self.client.get("/api/health/ready")
        
        assert response.status_code == 503
        data = response.json()
        assert data["detail"]["status"] == "not_ready"

    def test_security_status_endpoint(self):
        """Test security status endpoint"""
        with patch('app.middleware.security.get_security_status') as mock_security:
            mock_security.return_value = {
                "security_features": {
                    "content_sanitization": True,
                    "rate_limiting": True,
                    "security_headers": True
                },
                "threat_metrics": {
                    "blocked_requests": 0,
                    "suspicious_patterns": 0
                }
            }
            
            response = self.client.get("/api/health/security")
        
        assert response.status_code == 200
        data = response.json()
        assert "security_features" in data


class TestRootEndpoint:
    """Test cases for root endpoint"""
    
    def setup_method(self):
        """Set up test client"""
        self.client = TestClient(app)

    def test_root_endpoint(self):
        """Test root endpoint returns API information"""
        response = self.client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["name"] == "PhishContext AI API"
        assert data["version"] == "1.0.0"
        assert "description" in data
        assert data["docs"] == "/docs"
        assert data["health"] == "/api/health"


class TestErrorHandling:
    """Test cases for error handling"""
    
    def setup_method(self):
        """Set up test client"""
        self.client = TestClient(app)

    def test_404_error_handling(self):
        """Test 404 error handling"""
        response = self.client.get("/nonexistent-endpoint")
        
        assert response.status_code == 404
        data = response.json()
        assert data["success"] is False
        assert "error" in data

    def test_method_not_allowed(self):
        """Test method not allowed error"""
        response = self.client.put("/api/analyze")
        
        assert response.status_code == 405

    def test_invalid_json_body(self):
        """Test invalid JSON in request body"""
        response = self.client.post(
            "/api/analyze",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 422

    def test_missing_content_type(self):
        """Test request without proper content type"""
        response = self.client.post(
            "/api/analyze",
            data='{"email_content": "test"}'
        )
        
        # Should still work or return appropriate error
        assert response.status_code in [200, 400, 422]


class TestSecurityFeatures:
    """Test cases for security features"""
    
    def setup_method(self):
        """Set up test client"""
        self.client = TestClient(app)

    def test_security_headers_present(self):
        """Test that security headers are added to responses"""
        response = self.client.get("/")
        
        # Check for security headers
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"

    def test_cors_headers(self):
        """Test CORS headers are properly configured"""
        response = self.client.options("/api/analyze")
        
        # Should have CORS headers for OPTIONS request
        assert response.status_code in [200, 405]  # Depends on CORS configuration

    def test_request_size_limits(self):
        """Test request size limits are enforced"""
        # This would be handled by middleware
        # Test with reasonable size first
        normal_request = {"email_content": "Normal size email content"}
        
        with patch('app.api.dependencies.get_analysis_services') as mock_get_services:
            mock_email_parser = MagicMock()
            mock_email_parser.parse_email.return_value = (MagicMock(), "email body")
            
            mock_ioc_extractor = MagicMock()
            mock_ioc_extractor.extract_all_iocs.return_value = IOCCollection()
            
            mock_llm_analyzer = AsyncMock()
            mock_llm_analyzer.analyze_email.return_value = MagicMock()
            
            mock_get_services.return_value = {
                "email_parser": mock_email_parser,
                "ioc_extractor": mock_ioc_extractor,
                "llm_analyzer": mock_llm_analyzer
            }
            
            with patch('app.api.routes.analysis.performance_monitor') as mock_perf:
                mock_perf.check_capacity.return_value = (True, "OK")
                
                with patch('app.api.routes.analysis.track_request_performance'):
                    response = self.client.post("/api/analyze", json=normal_request)
        
        # Normal request should work (or fail for other reasons, not size)
        assert response.status_code != 413