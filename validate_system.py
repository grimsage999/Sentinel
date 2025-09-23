#!/usr/bin/env python3
"""
PhishContext AI - System Validation Script
Comprehensive end-to-end testing of the complete system
"""

import asyncio
import json
import time
import requests
import sys
from typing import Dict, List, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class TestResult:
    name: str
    passed: bool
    duration: float
    details: str
    error: str = ""

class SystemValidator:
    def __init__(self, backend_url: str = "http://localhost:8000", frontend_url: str = "http://localhost:3000"):
        self.backend_url = backend_url
        self.frontend_url = frontend_url
        self.results: List[TestResult] = []
        
    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def add_result(self, result: TestResult):
        self.results.append(result)
        status = "✅ PASS" if result.passed else "❌ FAIL"
        self.log(f"{result.name}: {status} ({result.duration:.2f}s)")
        if result.error:
            self.log(f"  Error: {result.error}", "ERROR")
        if result.details:
            self.log(f"  Details: {result.details}")
            
    def test_backend_health(self) -> TestResult:
        """Test backend health endpoint"""
        start_time = time.time()
        try:
            response = requests.get(f"{self.backend_url}/api/health", timeout=10)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                details = f"Status: {data.get('status', 'unknown')}, Services: {len(data.get('services', {}))}"
                return TestResult("Backend Health Check", True, duration, details)
            else:
                return TestResult("Backend Health Check", False, duration, "", f"HTTP {response.status_code}")
                
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("Backend Health Check", False, duration, "", str(e))
            
    def test_frontend_accessibility(self) -> TestResult:
        """Test frontend accessibility"""
        start_time = time.time()
        try:
            response = requests.get(self.frontend_url, timeout=10)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                content_length = len(response.content)
                details = f"Content length: {content_length} bytes"
                return TestResult("Frontend Accessibility", True, duration, details)
            else:
                return TestResult("Frontend Accessibility", False, duration, "", f"HTTP {response.status_code}")
                
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("Frontend Accessibility", False, duration, "", str(e))
            
    def test_email_analysis_basic(self) -> TestResult:
        """Test basic email analysis functionality"""
        start_time = time.time()
        
        sample_email = """From: attacker@malicious.com
To: victim@company.com
Subject: Urgent Account Verification
Date: Mon, 1 Jan 2024 12:00:00 +0000

Your account has been compromised. Click here: https://fake-bank.com/login
You have 24 hours to respond."""

        try:
            response = requests.post(
                f"{self.backend_url}/api/analyze",
                json={"email_content": sample_email},
                timeout=60
            )
            duration = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    analysis_data = data.get("data", {})
                    intent = analysis_data.get("intent", {}).get("primary", "unknown")
                    risk_score = analysis_data.get("riskScore", {}).get("score", 0)
                    iocs = analysis_data.get("iocs", {})
                    
                    details = f"Intent: {intent}, Risk: {risk_score}/10, IOCs: {len(iocs.get('urls', []))} URLs"
                    return TestResult("Basic Email Analysis", True, duration, details)
                else:
                    error_msg = data.get("error", {}).get("message", "Unknown error")
                    return TestResult("Basic Email Analysis", False, duration, "", error_msg)
            else:
                return TestResult("Basic Email Analysis", False, duration, "", f"HTTP {response.status_code}")
                
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("Basic Email Analysis", False, duration, "", str(e))
            
    def test_email_analysis_performance(self) -> TestResult:
        """Test email analysis performance requirements"""
        start_time = time.time()
        
        sample_email = """From: test@example.com
To: user@company.com
Subject: Performance Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000

This is a test email for performance validation.
It contains a URL: https://example.com/test
And an IP address: 192.168.1.1
"""

        try:
            response = requests.post(
                f"{self.backend_url}/api/analyze",
                json={"email_content": sample_email},
                timeout=30  # 30 second requirement
            )
            duration = time.time() - start_time
            
            if response.status_code == 200 and duration < 30:
                details = f"Analysis completed in {duration:.2f}s (requirement: <30s)"
                return TestResult("Performance Requirement", True, duration, details)
            elif response.status_code == 200:
                return TestResult("Performance Requirement", False, duration, "", f"Too slow: {duration:.2f}s")
            else:
                return TestResult("Performance Requirement", False, duration, "", f"HTTP {response.status_code}")
                
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("Performance Requirement", False, duration, "", str(e))
            
    def test_ioc_extraction(self) -> TestResult:
        """Test IOC extraction functionality"""
        start_time = time.time()
        
        sample_email = """From: test@example.com
To: user@company.com
Subject: IOC Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000

Visit these links:
https://malicious-site.com/login
http://192.168.1.100:8080/admin
ftp://suspicious-domain.net/files

Contact us at: evil-domain.org
IP address: 203.0.113.45
"""

        try:
            response = requests.post(
                f"{self.backend_url}/api/analyze",
                json={"email_content": sample_email},
                timeout=30
            )
            duration = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    analysis_data = data.get("data", {})
                    iocs = analysis_data.get("iocs", {})
                    
                    urls = iocs.get("urls", [])
                    ips = iocs.get("ips", [])
                    domains = iocs.get("domains", [])
                    
                    total_iocs = len(urls) + len(ips) + len(domains)
                    details = f"Extracted {len(urls)} URLs, {len(ips)} IPs, {len(domains)} domains"
                    
                    # Should extract at least some IOCs from the test email
                    if total_iocs >= 3:
                        return TestResult("IOC Extraction", True, duration, details)
                    else:
                        return TestResult("IOC Extraction", False, duration, details, "Insufficient IOCs extracted")
                else:
                    error_msg = data.get("error", {}).get("message", "Unknown error")
                    return TestResult("IOC Extraction", False, duration, "", error_msg)
            else:
                return TestResult("IOC Extraction", False, duration, "", f"HTTP {response.status_code}")
                
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("IOC Extraction", False, duration, "", str(e))
            
    def test_error_handling(self) -> TestResult:
        """Test error handling with invalid input"""
        start_time = time.time()
        
        try:
            # Test with empty content
            response = requests.post(
                f"{self.backend_url}/api/analyze",
                json={"email_content": ""},
                timeout=10
            )
            duration = time.time() - start_time
            
            if response.status_code == 400:
                data = response.json()
                if not data.get("success") and "error" in data:
                    details = f"Properly handled empty content with error: {data['error'].get('message', 'Unknown')}"
                    return TestResult("Error Handling", True, duration, details)
                else:
                    return TestResult("Error Handling", False, duration, "", "Invalid error response format")
            else:
                return TestResult("Error Handling", False, duration, "", f"Expected 400, got {response.status_code}")
                
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("Error Handling", False, duration, "", str(e))
            
    def test_security_headers(self) -> TestResult:
        """Test security headers are present"""
        start_time = time.time()
        
        try:
            response = requests.get(f"{self.backend_url}/api/health", timeout=10)
            duration = time.time() - start_time
            
            security_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options", 
                "X-XSS-Protection"
            ]
            
            present_headers = []
            for header in security_headers:
                if header in response.headers:
                    present_headers.append(header)
                    
            if len(present_headers) >= 2:  # At least 2 security headers
                details = f"Security headers present: {', '.join(present_headers)}"
                return TestResult("Security Headers", True, duration, details)
            else:
                details = f"Missing security headers. Present: {', '.join(present_headers)}"
                return TestResult("Security Headers", False, duration, details)
                
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("Security Headers", False, duration, "", str(e))
            
    def test_concurrent_requests(self) -> TestResult:
        """Test concurrent request handling"""
        start_time = time.time()
        
        sample_email = """From: test@example.com
To: user@company.com
Subject: Concurrent Test
Date: Mon, 1 Jan 2024 12:00:00 +0000

This is a concurrent test email.
"""

        async def make_request():
            try:
                response = requests.post(
                    f"{self.backend_url}/api/analyze",
                    json={"email_content": sample_email},
                    timeout=30
                )
                return response.status_code == 200
            except:
                return False
                
        try:
            # Test with 3 concurrent requests
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(lambda: requests.post(
                    f"{self.backend_url}/api/analyze",
                    json={"email_content": sample_email},
                    timeout=30
                )) for _ in range(3)]
                
                results = []
                for future in concurrent.futures.as_completed(futures):
                    try:
                        response = future.result()
                        results.append(response.status_code == 200)
                    except:
                        results.append(False)
                        
            duration = time.time() - start_time
            successful = sum(results)
            
            if successful >= 2:  # At least 2 out of 3 should succeed
                details = f"{successful}/3 concurrent requests successful"
                return TestResult("Concurrent Requests", True, duration, details)
            else:
                details = f"Only {successful}/3 concurrent requests successful"
                return TestResult("Concurrent Requests", False, duration, details)
                
        except Exception as e:
            duration = time.time() - start_time
            return TestResult("Concurrent Requests", False, duration, "", str(e))
            
    def run_all_tests(self):
        """Run all validation tests"""
        self.log("Starting PhishContext AI System Validation")
        self.log("=" * 50)
        
        tests = [
            self.test_backend_health,
            self.test_frontend_accessibility,
            self.test_email_analysis_basic,
            self.test_email_analysis_performance,
            self.test_ioc_extraction,
            self.test_error_handling,
            self.test_security_headers,
            self.test_concurrent_requests
        ]
        
        for test in tests:
            try:
                result = test()
                self.add_result(result)
            except Exception as e:
                self.add_result(TestResult(test.__name__, False, 0, "", str(e)))
                
        self.print_summary()
        
    def print_summary(self):
        """Print test summary"""
        self.log("=" * 50)
        self.log("VALIDATION SUMMARY")
        self.log("=" * 50)
        
        passed = sum(1 for r in self.results if r.passed)
        total = len(self.results)
        
        self.log(f"Tests Passed: {passed}/{total}")
        self.log(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            self.log("🎉 ALL TESTS PASSED - SYSTEM READY FOR PRODUCTION", "SUCCESS")
        else:
            self.log("❌ SOME TESTS FAILED - REVIEW REQUIRED", "WARNING")
            
        self.log("\nDetailed Results:")
        for result in self.results:
            status = "✅" if result.passed else "❌"
            self.log(f"  {status} {result.name} ({result.duration:.2f}s)")
            if result.error:
                self.log(f"    Error: {result.error}")
                
        # Requirements validation summary
        self.log("\n" + "=" * 50)
        self.log("REQUIREMENTS VALIDATION")
        self.log("=" * 50)
        
        requirements_map = {
            "Backend Health Check": "System Availability",
            "Frontend Accessibility": "User Interface (Req 6.1)",
            "Basic Email Analysis": "Email Analysis (Req 1.1-1.3)",
            "Performance Requirement": "30-second Analysis (Req 1.2)",
            "IOC Extraction": "IOC Extraction (Req 5.1-5.3)",
            "Error Handling": "Error Messaging (Req 1.4)",
            "Security Headers": "Security (Req 8.1-8.3)",
            "Concurrent Requests": "Concurrency (Req 7.1)"
        }
        
        for result in self.results:
            if result.name in requirements_map:
                status = "✅ PASS" if result.passed else "❌ FAIL"
                req = requirements_map[result.name]
                self.log(f"  {status} {req}")
                
        return passed == total

def main():
    """Main validation function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="PhishContext AI System Validation")
    parser.add_argument("--backend", default="http://localhost:8000", help="Backend URL")
    parser.add_argument("--frontend", default="http://localhost:3000", help="Frontend URL")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    
    args = parser.parse_args()
    
    validator = SystemValidator(args.backend, args.frontend)
    validator.run_all_tests()
    
    if args.json:
        results_json = {
            "timestamp": datetime.now().isoformat(),
            "backend_url": args.backend,
            "frontend_url": args.frontend,
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "duration": r.duration,
                    "details": r.details,
                    "error": r.error
                }
                for r in validator.results
            ],
            "summary": {
                "total_tests": len(validator.results),
                "passed_tests": sum(1 for r in validator.results if r.passed),
                "success_rate": (sum(1 for r in validator.results if r.passed) / len(validator.results)) * 100
            }
        }
        print(json.dumps(results_json, indent=2))
    
    # Exit with error code if any tests failed
    passed = sum(1 for r in validator.results if r.passed)
    total = len(validator.results)
    sys.exit(0 if passed == total else 1)

if __name__ == "__main__":
    main()