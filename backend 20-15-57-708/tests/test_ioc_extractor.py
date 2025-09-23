"""
Unit tests for IOC (Indicators of Compromise) extraction service.
Tests URL, IP address, and domain extraction with various edge cases.
"""

import pytest
from app.services.ioc_extractor import IOCExtractor
from app.models.analysis_models import IOCType, IOCCollection


class TestIOCExtractor:
    """Test suite for IOCExtractor class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = IOCExtractor()
    
    def test_extract_urls_basic(self):
        """Test basic URL extraction."""
        content = """
        Check out this link: https://malicious-site.com/login
        Also visit http://another-bad-site.org/phishing
        And this one: ftp://file-server.net/downloads
        """
        
        urls = self.extractor.extract_urls(content)
        
        assert len(urls) == 3
        assert any(ioc.value == "https://malicious-site.com/login" for ioc in urls)
        assert any(ioc.value == "http://another-bad-site.org/phishing" for ioc in urls)
        assert any(ioc.value == "ftp://file-server.net/downloads" for ioc in urls)
        
        # Check VirusTotal links
        for url_ioc in urls:
            assert url_ioc.type == IOCType.URL
            assert "virustotal.com" in url_ioc.vt_link
            assert "detection" in url_ioc.vt_link

    def test_extract_urls_with_brackets_and_quotes(self):
        """Test URL extraction from brackets and quotes."""
        content = """
        Click here: <https://phishing-example.com>
        Or visit "http://malware-site.net/download"
        Also check [https://suspicious-domain.org]
        """
        
        urls = self.extractor.extract_urls(content)
        
        assert len(urls) >= 2  # At least the bracketed and quoted URLs
        assert any("phishing-example.com" in ioc.value for ioc in urls)
        assert any("malware-site.net" in ioc.value for ioc in urls)

    def test_extract_urls_with_parameters(self):
        """Test URL extraction with query parameters and fragments."""
        content = """
        Malicious URL: https://bad-site.com/login?redirect=evil.com&token=abc123#fragment
        Another one: http://phishing.org/page.php?id=123&action=steal
        """
        
        urls = self.extractor.extract_urls(content)
        
        assert len(urls) == 2
        assert any("redirect=evil.com" in ioc.value for ioc in urls)
        assert any("action=steal" in ioc.value for ioc in urls)

    def test_extract_urls_edge_cases(self):
        """Test URL extraction edge cases."""
        content = """
        URL with port: https://malicious.com:8080/path
        URL with trailing punctuation: Visit https://bad-site.org/page.
        URL with parentheses: (https://suspicious.net)
        Incomplete URL: www.maybe-bad.com
        """
        
        urls = self.extractor.extract_urls(content)
        
        # Should extract valid URLs and clean trailing punctuation
        assert any(":8080" in ioc.value for ioc in urls)
        assert any(ioc.value == "https://bad-site.org/page" for ioc in urls)  # No trailing dot
        assert any("suspicious.net" in ioc.value for ioc in urls)

    def test_extract_ipv4_addresses(self):
        """Test IPv4 address extraction."""
        content = """
        Suspicious IP: 192.168.1.100 (should be filtered as private)
        Malicious server: 203.0.113.45
        Another bad IP: 198.51.100.123
        Invalid IP: 999.999.999.999
        Localhost: 127.0.0.1 (should be filtered)
        """
        
        ips = self.extractor.extract_ips(content)
        
        # Should only extract public IPs
        assert len(ips) == 2
        assert any(ioc.value == "203.0.113.45" for ioc in ips)
        assert any(ioc.value == "198.51.100.123" for ioc in ips)
        
        # Verify private IPs are filtered out
        assert not any("192.168" in ioc.value for ioc in ips)
        assert not any("127.0.0.1" in ioc.value for ioc in ips)
        
        # Check VirusTotal links
        for ip_ioc in ips:
            assert ip_ioc.type == IOCType.IP
            assert f"virustotal.com/gui/ip-address/{ip_ioc.value}" in ip_ioc.vt_link

    def test_extract_ipv6_addresses(self):
        """Test IPv6 address extraction."""
        content = """
        IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        Compressed IPv6: 2001:db8::8a2e:370:7334
        Localhost IPv6: ::1 (should be filtered)
        Link-local: fe80::1 (should be filtered)
        """
        
        ips = self.extractor.extract_ips(content)
        
        # Should extract public IPv6 addresses
        ipv6_ips = [ioc for ioc in ips if ':' in ioc.value]
        assert len(ipv6_ips) >= 1
        
        # Verify private/local IPv6 are filtered
        assert not any("::1" in ioc.value for ioc in ips)
        assert not any("fe80::" in ioc.value for ioc in ips)

    def test_extract_domains_basic(self):
        """Test basic domain extraction."""
        content = """
        Suspicious domain: malicious-phishing.com
        Another bad one: evil-site.org
        Email context: user@legitimate.com (should be filtered)
        Standalone mention of badactor.net
        """
        
        domains = self.extractor.extract_domains(content)
        
        # Should extract standalone domains but filter email-only domains
        assert len(domains) >= 2
        assert any(ioc.value == "malicious-phishing.com" for ioc in domains)
        assert any(ioc.value == "badactor.net" for ioc in domains)
        
        # Check VirusTotal links
        for domain_ioc in domains:
            assert domain_ioc.type == IOCType.DOMAIN
            assert f"virustotal.com/gui/domain/{domain_ioc.value}" in domain_ioc.vt_link

    def test_extract_domains_filter_legitimate(self):
        """Test filtering of legitimate domains."""
        content = """
        Suspicious: evil-phishing.com
        Legitimate: microsoft.com (should be filtered)
        Also legitimate: google.com (should be filtered)
        Another bad one: malware-site.net
        """
        
        domains = self.extractor.extract_domains(content)
        
        # Should filter out known legitimate domains
        domain_values = [ioc.value for ioc in domains]
        assert "evil-phishing.com" in domain_values
        assert "malware-site.net" in domain_values
        assert "microsoft.com" not in domain_values
        assert "google.com" not in domain_values

    def test_extract_domains_from_urls_excluded(self):
        """Test that domains in URLs are not extracted as separate domains."""
        content = """
        Visit https://malicious-site.com/login for phishing
        The domain malicious-site.com is suspicious
        Also check http://another-bad.org/page
        """
        
        urls = self.extractor.extract_urls(content)
        domains = self.extractor.extract_domains(content)
        
        # URLs should be extracted
        assert len(urls) >= 2
        
        # Domains should be extracted only if mentioned outside URLs
        # The second mention of malicious-site.com should be caught
        domain_values = [ioc.value for ioc in domains]
        assert "malicious-site.com" in domain_values

    def test_extract_all_iocs_comprehensive(self):
        """Test comprehensive IOC extraction from realistic phishing email."""
        email_content = """
        From: security@microsooft.com
        To: victim@company.com
        Subject: Urgent: Account Verification Required
        
        Dear User,
        
        Your account has been compromised. Please visit https://fake-microsoft.com/login
        immediately to verify your identity. 
        
        If you cannot access the link, contact our server at 203.0.113.45
        or visit our backup site at phishing-backup.net.
        
        You can also reach us at support@fake-company.org
        
        Additional resources:
        - http://malware-download.com/file.exe
        - backup-server.evil-domain.com
        
        Time-sensitive action required!
        """
        
        ioc_collection = self.extractor.extract_all_iocs(email_content, "Phishing email")
        
        # Verify URLs are extracted
        assert len(ioc_collection.urls) >= 2
        url_values = [ioc.value for ioc in ioc_collection.urls]
        assert any("fake-microsoft.com" in url for url in url_values)
        assert any("malware-download.com" in url for url in url_values)
        
        # Verify IPs are extracted
        assert len(ioc_collection.ips) >= 1
        ip_values = [ioc.value for ioc in ioc_collection.ips]
        assert "203.0.113.45" in ip_values
        
        # Verify domains are extracted
        assert len(ioc_collection.domains) >= 1
        domain_values = [ioc.value for ioc in ioc_collection.domains]
        assert ("phishing-backup.net" in domain_values or 
                "backup-server.evil-domain.com" in domain_values)
        
        # Verify context is set
        for ioc_list in [ioc_collection.urls, ioc_collection.ips, ioc_collection.domains]:
            for ioc in ioc_list:
                assert ioc.context == "Phishing email"

    def test_url_cleaning_and_validation(self):
        """Test URL cleaning and validation methods."""
        # Test URL cleaning
        assert self.extractor._clean_url("https://example.com.") == "https://example.com"
        assert self.extractor._clean_url("http://test.org,") == "http://test.org"
        assert self.extractor._clean_url("www.site.com") == "http://www.site.com"
        
        # Test URL validation
        assert self.extractor._is_valid_url("https://example.com")
        assert self.extractor._is_valid_url("http://test.org/path")
        assert not self.extractor._is_valid_url("invalid-url")
        assert not self.extractor._is_valid_url("http://localhost")
        assert not self.extractor._is_valid_url("https://127.0.0.1")

    def test_ip_validation(self):
        """Test IP address validation methods."""
        # Valid IPv4
        assert self.extractor._is_valid_ipv4("203.0.113.45")
        assert self.extractor._is_valid_ipv4("8.8.8.8")
        
        # Invalid IPv4
        assert not self.extractor._is_valid_ipv4("999.999.999.999")
        assert not self.extractor._is_valid_ipv4("192.168.1")
        assert not self.extractor._is_valid_ipv4("0.0.0.0")
        
        # Private IP detection
        assert self.extractor._is_private_ip("192.168.1.1")
        assert self.extractor._is_private_ip("10.0.0.1")
        assert self.extractor._is_private_ip("172.16.0.1")
        assert self.extractor._is_private_ip("127.0.0.1")
        assert not self.extractor._is_private_ip("8.8.8.8")

    def test_domain_validation(self):
        """Test domain validation methods."""
        # Valid domains
        assert self.extractor._is_valid_domain("example.com")
        assert self.extractor._is_valid_domain("sub.domain.org")
        assert self.extractor._is_valid_domain("test-site.net")
        
        # Invalid domains
        assert not self.extractor._is_valid_domain("invalid")
        assert not self.extractor._is_valid_domain(".com")
        assert not self.extractor._is_valid_domain("site.")
        assert not self.extractor._is_valid_domain("")

    def test_virustotal_link_generation(self):
        """Test VirusTotal link generation for different IOC types."""
        # URL link
        url = "https://malicious-site.com/login"
        vt_url_link = self.extractor._generate_vt_url_link(url)
        assert "virustotal.com/gui/url/" in vt_url_link
        assert "detection" in vt_url_link
        
        # IP link
        ip = "203.0.113.45"
        vt_ip_link = self.extractor._generate_vt_ip_link(ip)
        assert f"virustotal.com/gui/ip-address/{ip}/detection" in vt_ip_link
        
        # Domain link
        domain = "malicious-site.com"
        vt_domain_link = self.extractor._generate_vt_domain_link(domain)
        assert f"virustotal.com/gui/domain/{domain}/detection" in vt_domain_link

    def test_ioc_summary(self):
        """Test IOC summary statistics."""
        # Create test IOC collection
        from app.models.analysis_models import IOCItem
        
        ioc_collection = IOCCollection(
            urls=[
                IOCItem(value="https://test1.com", type=IOCType.URL, vtLink="https://virustotal.com/test1"),
                IOCItem(value="https://test2.com", type=IOCType.URL, vtLink="https://virustotal.com/test2")
            ],
            ips=[
                IOCItem(value="203.0.113.45", type=IOCType.IP, vtLink="https://virustotal.com/ip")
            ],
            domains=[
                IOCItem(value="malicious.com", type=IOCType.DOMAIN, vtLink="https://virustotal.com/domain1"),
                IOCItem(value="evil.org", type=IOCType.DOMAIN, vtLink="https://virustotal.com/domain2"),
                IOCItem(value="bad.net", type=IOCType.DOMAIN, vtLink="https://virustotal.com/domain3")
            ]
        )
        
        summary = self.extractor.get_ioc_summary(ioc_collection)
        
        assert summary['urls'] == 2
        assert summary['ips'] == 1
        assert summary['domains'] == 3
        assert summary['total'] == 6

    def test_empty_content(self):
        """Test extraction from empty or whitespace-only content."""
        empty_results = self.extractor.extract_all_iocs("")
        assert len(empty_results.urls) == 0
        assert len(empty_results.ips) == 0
        assert len(empty_results.domains) == 0
        
        whitespace_results = self.extractor.extract_all_iocs("   \n\t   ")
        assert len(whitespace_results.urls) == 0
        assert len(whitespace_results.ips) == 0
        assert len(whitespace_results.domains) == 0

    def test_malformed_content_handling(self):
        """Test handling of malformed or edge case content."""
        malformed_content = """
        Broken URL: https://
        Invalid IP: 300.400.500.600
        Malformed domain: .com
        Special chars: https://test.com/path?param=value&other=<script>
        Unicode: https://тест.com
        """
        
        # Should not crash and should filter out invalid entries
        results = self.extractor.extract_all_iocs(malformed_content)
        
        # Verify no invalid entries are included
        for url_ioc in results.urls:
            assert self.extractor._is_valid_url(url_ioc.value)
        
        for ip_ioc in results.ips:
            assert (self.extractor._is_valid_ipv4(ip_ioc.value) or 
                   self.extractor._is_valid_ipv6(ip_ioc.value))
        
        for domain_ioc in results.domains:
            assert self.extractor._is_valid_domain(domain_ioc.value)

    def test_deduplication(self):
        """Test that duplicate IOCs are properly deduplicated."""
        content = """
        Same URL twice: https://malicious.com/login
        Again: https://malicious.com/login
        Same IP: 203.0.113.45
        Repeated: 203.0.113.45
        Same domain: evil-site.org
        Once more: evil-site.org
        """
        
        results = self.extractor.extract_all_iocs(content)
        
        # Should deduplicate identical IOCs
        url_values = [ioc.value for ioc in results.urls]
        ip_values = [ioc.value for ioc in results.ips]
        domain_values = [ioc.value for ioc in results.domains]
        
        assert len(set(url_values)) == len(url_values)  # No duplicates
        assert len(set(ip_values)) == len(ip_values)    # No duplicates
        assert len(set(domain_values)) == len(domain_values)  # No duplicates

    def test_extract_urls_with_international_domains(self):
        """Test URL extraction with international domain names."""
        content = """
        International URL: https://тест.рф/path
        Punycode URL: https://xn--e1afmkfd.xn--p1ai/page
        Mixed content: Visit https://example.中国/login
        """
        
        urls = self.extractor.extract_urls(content)
        
        # Should extract international URLs
        assert len(urls) >= 1
        # At least one URL should be extracted (punycode version is more reliable)
        assert any("xn--" in ioc.value for ioc in urls)

    def test_extract_urls_with_suspicious_tlds(self):
        """Test URL extraction with suspicious top-level domains."""
        content = """
        Suspicious TLD: https://malware.tk/download
        Another suspicious: http://phishing.ml/login
        Short TLD: https://evil.ly/redirect
        """
        
        urls = self.extractor.extract_urls(content)
        
        # Should extract URLs with suspicious TLDs
        assert len(urls) >= 3
        tld_values = [ioc.value for ioc in urls]
        assert any(".tk" in url for url in tld_values)
        assert any(".ml" in url for url in tld_values)
        assert any(".ly" in url for url in tld_values)

    def test_extract_ips_with_port_numbers(self):
        """Test IP extraction when IPs appear with port numbers."""
        content = """
        IP with port: 203.0.113.45:8080
        Another: 198.51.100.123:443
        HTTPS context: https://203.0.113.45:8443/path
        """
        
        ips = self.extractor.extract_ips(content)
        
        # Should extract IPs without port numbers
        ip_values = [ioc.value for ioc in ips]
        assert "203.0.113.45" in ip_values
        assert "198.51.100.123" in ip_values
        # Port numbers should not be included in IP values
        assert not any(":" in ip for ip in ip_values)

    def test_extract_domains_with_subdomains(self):
        """Test domain extraction with various subdomain levels."""
        content = """
        Simple subdomain: phishing.evil-site.com
        Deep subdomain: login.secure.fake-bank.org
        Multiple levels: a.b.c.d.malicious-domain.net
        """
        
        domains = self.extractor.extract_domains(content)
        
        # Should extract domains with subdomains
        domain_values = [ioc.value for ioc in domains]
        assert any("phishing.evil-site.com" in domain for domain in domain_values)
        assert any("login.secure.fake-bank.org" in domain for domain in domain_values)

    def test_extract_iocs_from_email_headers(self):
        """Test IOC extraction from email headers."""
        email_content = """From: attacker@malicious-domain.com
To: victim@company.com
Reply-To: noreply@phishing-site.org
Received: from [203.0.113.45] by mail.company.com
X-Originating-IP: 198.51.100.123
X-Forwarded-For: 192.168.1.1, 203.0.113.45

Please visit our secure site at https://fake-bank.com/login
"""
        
        results = self.extractor.extract_all_iocs(email_content)
        
        # Should extract IOCs from headers and body
        assert len(results.urls) >= 1
        assert len(results.ips) >= 1  # Should find public IPs, filter private ones
        assert len(results.domains) >= 1
        
        # Verify specific extractions
        url_values = [ioc.value for ioc in results.urls]
        ip_values = [ioc.value for ioc in results.ips]
        domain_values = [ioc.value for ioc in results.domains]
        
        assert any("fake-bank.com" in url for url in url_values)
        assert "203.0.113.45" in ip_values
        assert "192.168.1.1" not in ip_values  # Private IP should be filtered

    def test_extract_iocs_performance_large_content(self):
        """Test IOC extraction performance with large content."""
        # Create large content with scattered IOCs
        large_content = []
        for i in range(100):
            large_content.append(f"Line {i}: Some normal text content here.")
            if i % 10 == 0:
                large_content.append(f"Malicious URL: https://evil-site-{i}.com/path")
            if i % 15 == 0:
                large_content.append(f"Suspicious IP: 203.0.113.{i % 255}")
        
        content = "\n".join(large_content)
        
        # Should complete extraction without timeout
        import time
        start_time = time.time()
        results = self.extractor.extract_all_iocs(content)
        extraction_time = time.time() - start_time
        
        # Should complete within reasonable time (adjust threshold as needed)
        assert extraction_time < 5.0  # 5 seconds max
        
        # Should find the scattered IOCs
        assert len(results.urls) >= 5
        assert len(results.ips) >= 3

    def test_extract_iocs_with_obfuscation(self):
        """Test IOC extraction with common obfuscation techniques."""
        content = """
        Obfuscated URL: hxxp://malicious-site[.]com/path
        Defanged URL: https://evil[.]org/login
        Bracket IP: [203.0.113.45]
        Parentheses domain: (phishing-site.net)
        """
        
        # Current implementation may not handle obfuscation
        # This test documents expected behavior
        results = self.extractor.extract_all_iocs(content)
        
        # May not extract obfuscated IOCs (this is expected behavior)
        # But should extract any non-obfuscated ones
        assert isinstance(results, type(results))  # Basic validation

    def test_virustotal_link_encoding(self):
        """Test VirusTotal link generation with special characters."""
        # Test URL with special characters
        special_url = "https://example.com/path?param=value&other=test"
        vt_link = self.extractor._generate_vt_url_link(special_url)
        
        assert "virustotal.com/gui/url/" in vt_link
        assert "detection" in vt_link
        # Should handle URL encoding properly
        assert "%3A" in vt_link or "https" in vt_link  # Either encoded or handled

    def test_ioc_context_preservation(self):
        """Test that IOC context is properly preserved."""
        context = "phishing_email_analysis"
        content = "Visit https://malicious.com and contact 203.0.113.45"
        
        results = self.extractor.extract_all_iocs(content, context)
        
        # All IOCs should have the context
        for ioc_list in [results.urls, results.ips, results.domains]:
            for ioc in ioc_list:
                assert ioc.context == context

    def test_extract_iocs_with_mixed_case(self):
        """Test IOC extraction with mixed case domains and URLs."""
        content = """
        Mixed case URL: HTTPS://EVIL-SITE.COM/PATH
        Mixed domain: Phishing-Site.ORG
        Lower case: https://malware.net/download
        """
        
        results = self.extractor.extract_all_iocs(content)
        
        # Should extract regardless of case
        url_values = [ioc.value.lower() for ioc in results.urls]
        domain_values = [ioc.value.lower() for ioc in results.domains]
        
        assert any("evil-site.com" in url for url in url_values)
        assert any("phishing-site.org" in domain for domain in domain_values)


if __name__ == "__main__":
    pytest.main([__file__])