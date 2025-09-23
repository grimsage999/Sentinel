#!/usr/bin/env python3
"""
Validation script for security and performance features
"""

import sys
import asyncio
from datetime import datetime

def test_security_features():
    """Test core security functionality"""
    print("Testing security features...")
    
    try:
        from app.core.security import (
            sanitize_email_content,
            validate_content_size,
            detect_malicious_patterns,
            generate_request_id,
            email_content_manager
        )
        
        # Test 1: Content sanitization
        print("✓ Testing content sanitization...")
        malicious_content = """
        From: test@example.com
        Subject: Test
        
        <script>alert('xss')</script>
        Normal content here.
        """
        
        sanitized = sanitize_email_content(malicious_content)
        assert "<script>" not in sanitized, "Script tags should be removed"
        assert "Normal content here." in sanitized, "Normal content should remain"
        print("  ✓ Content sanitization working")
        
        # Test 2: Size validation
        print("✓ Testing size validation...")
        small_content = "Small email content"
        large_content = "A" * (2 * 1024 * 1024)  # 2MB
        
        is_valid_small, _ = validate_content_size(small_content, 1)
        is_valid_large, error_msg = validate_content_size(large_content, 1)
        
        assert is_valid_small is True, "Small content should be valid"
        assert is_valid_large is False, "Large content should be invalid"
        assert "exceeds maximum size" in error_msg, "Error message should mention size"
        print("  ✓ Size validation working")
        
        # Test 3: Malicious pattern detection
        print("✓ Testing malicious pattern detection...")
        malicious_patterns = """
        <script>alert('test')</script>
        Download: malware.exe
        Visit: http://192.168.1.1/phishing
        """
        
        threats = detect_malicious_patterns(malicious_patterns)
        assert len(threats) > 0, "Should detect threats"
        
        threat_types = [t['type'] for t in threats]
        assert 'script_injection' in threat_types, "Should detect script injection"
        print(f"  ✓ Detected {len(threats)} threats: {threat_types}")
        
        # Test 4: Request ID generation
        print("✓ Testing request ID generation...")
        id1 = generate_request_id()
        id2 = generate_request_id()
        
        assert id1 != id2, "Request IDs should be unique"
        assert len(id1) > 10, "Request ID should be reasonably long"
        print("  ✓ Request ID generation working")
        
        # Test 5: Email content manager
        print("✓ Testing email content manager...")
        test_content = "Test email for memory management"
        content_id = email_content_manager.store_content("test_123", test_content)
        
        retrieved = email_content_manager.get_content("test_123")
        assert retrieved == test_content, "Should retrieve stored content"
        
        email_content_manager.clear_content("test_123")
        retrieved_after_clear = email_content_manager.get_content("test_123")
        assert retrieved_after_clear is None, "Content should be cleared"
        print("  ✓ Email content manager working")
        
        print("✅ All security features working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_performance_features():
    """Test performance monitoring functionality"""
    print("\nTesting performance features...")
    
    try:
        from app.utils.performance import performance_monitor, RequestMetrics
        
        # Test 1: Request tracking
        print("✓ Testing request tracking...")
        request_id = "test_request_123"
        
        metrics = performance_monitor.start_request(
            request_id=request_id,
            endpoint="/api/analyze",
            method="POST",
            email_size=1024
        )
        
        assert metrics.request_id == request_id, "Request ID should match"
        assert metrics.email_size == 1024, "Email size should be recorded"
        print("  ✓ Request tracking started")
        
        # Update metrics
        performance_monitor.update_request(
            request_id=request_id,
            llm_provider="openai",
            llm_processing_time=2.5,
            ioc_count=5
        )
        print("  ✓ Request metrics updated")
        
        # Complete tracking
        completed = performance_monitor.complete_request(
            request_id=request_id,
            status_code=200
        )
        
        assert completed is not None, "Should return completed metrics"
        assert completed.status_code == 200, "Status code should be recorded"
        print("  ✓ Request tracking completed")
        
        # Test 2: Current metrics
        print("✓ Testing current metrics...")
        current_metrics = performance_monitor.get_current_metrics()
        
        required_keys = [
            'active_requests', 'completed_requests', 'avg_response_time_seconds',
            'error_rate', 'system_metrics'
        ]
        
        for key in required_keys:
            assert key in current_metrics, f"Missing key: {key}"
        
        print("  ✓ Current metrics available")
        
        # Test 3: Capacity check
        print("✓ Testing capacity check...")
        can_process, message = performance_monitor.check_capacity()
        
        assert isinstance(can_process, bool), "Should return boolean"
        assert isinstance(message, str), "Should return message"
        print(f"  ✓ Capacity check: {can_process} - {message}")
        
        print("✅ All performance features working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Performance test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_configuration():
    """Test configuration settings"""
    print("\nTesting configuration...")
    
    try:
        from app.core.config import settings
        
        # Test security settings
        print("✓ Testing security configuration...")
        assert hasattr(settings, 'enable_content_sanitization'), "Missing content sanitization setting"
        assert hasattr(settings, 'enable_security_headers'), "Missing security headers setting"
        assert hasattr(settings, 'max_concurrent_requests'), "Missing concurrent requests setting"
        print("  ✓ Security configuration available")
        
        # Test performance settings
        print("✓ Testing performance configuration...")
        assert hasattr(settings, 'enable_performance_monitoring'), "Missing performance monitoring setting"
        assert hasattr(settings, 'memory_cleanup_interval_minutes'), "Missing cleanup interval setting"
        assert hasattr(settings, 'max_request_queue_size'), "Missing queue size setting"
        print("  ✓ Performance configuration available")
        
        print("✅ Configuration working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all validation tests"""
    print("🔒 PhishContext AI Security & Performance Validation")
    print("=" * 50)
    
    results = []
    
    # Run tests
    results.append(test_security_features())
    results.append(test_performance_features())
    results.append(test_configuration())
    
    # Summary
    print("\n" + "=" * 50)
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"🎉 All tests passed! ({passed}/{total})")
        print("\n✅ Security and performance features are working correctly!")
        return 0
    else:
        print(f"❌ Some tests failed ({passed}/{total})")
        return 1


if __name__ == "__main__":
    sys.exit(main())