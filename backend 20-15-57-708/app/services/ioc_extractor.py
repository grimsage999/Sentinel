"""
IOC (Indicators of Compromise) extraction service for phishing email analysis.
Extracts URLs, IP addresses, and domains from email content with VirusTotal integration.
"""

import re
import urllib.parse
from typing import List, Set, Dict, Optional
from urllib.parse import urlparse, unquote

from ..models.analysis_models import IOCItem, IOCCollection, IOCType
from .virustotal_service import virustotal_service
from ..utils.logging import get_secure_logger

logger = get_secure_logger(__name__)


class IOCExtractor:
    """
    Extracts and categorizes Indicators of Compromise (IOCs) from email content.
    Supports URLs, IP addresses, and domains with VirusTotal link generation.
    """
    
    def __init__(self):
        # Comprehensive regex patterns for IOC extraction
        self.url_pattern = re.compile(
            r'(?i)\b(?:https?://|ftp://|www\.)'
            r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'(?::[0-9]{1,5})?'
            r'(?:/[^\s<>"{}|\\^`\[\]]*)?',
            re.IGNORECASE | re.MULTILINE
        )
        
        # IPv4 pattern - matches standard IPv4 addresses
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # IPv6 pattern - matches standard IPv6 addresses
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b::1\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
            r'\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|'
            r'\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b'
        )
        
        # Domain pattern - matches domain names (not in URLs)
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        
        # Private IP ranges to exclude from results
        self.private_ip_ranges = [
            re.compile(r'^10\.'),
            re.compile(r'^192\.168\.'),
            re.compile(r'^172\.(?:1[6-9]|2[0-9]|3[01])\.'),
            re.compile(r'^127\.'),
            re.compile(r'^169\.254\.'),
            re.compile(r'^::1$'),
            re.compile(r'^fe80:')
        ]
        
        # Common legitimate domains to exclude
        self.legitimate_domains = {
            'microsoft.com', 'support.microsoft.com', 'update.microsoft.com',
            'google.com', 'support.google.com',
            'apple.com', 'support.apple.com',
            'amazon.com', 'chase.com', 'paypal.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'stackoverflow.com', 'wikipedia.org', 'youtube.com'
        }

    async def extract_all_iocs(self, email_content: str, context: Optional[str] = None) -> IOCCollection:
        """
        Extract all IOCs from email content and return organized collection.
        
        Args:
            email_content: Raw email content including headers and body
            context: Optional context information for IOCs
            
        Returns:
            IOCCollection with categorized IOCs and VirusTotal links
        """
        urls = await self.extract_urls(email_content, context)
        ips = self.extract_ips(email_content, context)
        domains = self.extract_domains(email_content, context)
        
        return IOCCollection(
            urls=urls,
            ips=ips,
            domains=domains
        )

    async def extract_urls(self, content: str, context: Optional[str] = None) -> List[IOCItem]:
        """
        Extract and validate URLs from content.
        
        Args:
            content: Text content to search
            context: Optional context for the IOCs
            
        Returns:
            List of IOCItem objects for URLs
        """
        urls = set()
        
        # Find all URL matches
        matches = self.url_pattern.findall(content)
        
        for match in matches:
            # Clean and validate URL
            cleaned_url = self._clean_url(match)
            if cleaned_url and self._is_valid_url(cleaned_url):
                urls.add(cleaned_url)
        
        # Also look for URLs in angle brackets or quotes
        bracket_pattern = re.compile(r'<(https?://[^>]+)>', re.IGNORECASE)
        quote_pattern = re.compile(r'"(https?://[^"]+)"', re.IGNORECASE)
        
        for pattern in [bracket_pattern, quote_pattern]:
            matches = pattern.findall(content)
            for match in matches:
                cleaned_url = self._clean_url(match)
                if cleaned_url and self._is_valid_url(cleaned_url):
                    urls.add(cleaned_url)
        
        # Convert to IOCItem objects with VirusTotal links
        # Automatically submit URLs to VirusTotal and get analysis URLs
        ioc_items = []
        for url in sorted(urls):
            # Get VirusTotal analysis URL (submits automatically if needed)
            vt_link = await self._get_vt_analysis_url(url)
            
            ioc_items.append(IOCItem(
                value=url,
                type=IOCType.URL,
                vtLink=vt_link,
                context=context
            ))
        
        return ioc_items

    def extract_ips(self, content: str, context: Optional[str] = None) -> List[IOCItem]:
        """
        Extract and validate IP addresses from content.
        
        Args:
            content: Text content to search
            context: Optional context for the IOCs
            
        Returns:
            List of IOCItem objects for IP addresses
        """
        ips = set()
        
        # Extract IPv4 addresses
        ipv4_matches = self.ipv4_pattern.findall(content)
        for ip in ipv4_matches:
            if self._is_valid_ipv4(ip) and not self._is_private_ip(ip):
                ips.add(ip)
        
        # Extract IPv6 addresses
        ipv6_matches = self.ipv6_pattern.findall(content)
        for ip in ipv6_matches:
            if self._is_valid_ipv6(ip) and not self._is_private_ip(ip):
                ips.add(ip)
        
        # Convert to IOCItem objects with VirusTotal links
        return [
            IOCItem(
                value=ip,
                type=IOCType.IP,
                vtLink=self._generate_vt_ip_link(ip),
                context=context
            )
            for ip in sorted(ips)
        ]

    def extract_domains(self, content: str, context: Optional[str] = None) -> List[IOCItem]:
        """
        Extract and validate domain names from content (excluding those in URLs).
        
        Args:
            content: Text content to search
            context: Optional context for the IOCs
            
        Returns:
            List of IOCItem objects for domains
        """
        domains = set()
        
        # Remove URLs first to avoid extracting domains from legitimate URLs
        content_without_urls = self.url_pattern.sub('', content)
        
        # Find domain matches
        matches = self.domain_pattern.findall(content_without_urls)
        
        for match in matches:
            domain = match.lower().strip('.')
            if (self._is_valid_domain(domain) and 
                domain not in self.legitimate_domains and
                not self._is_email_domain_only(domain, content)):
                domains.add(domain)
        
        # Convert to IOCItem objects with VirusTotal links
        return [
            IOCItem(
                value=domain,
                type=IOCType.DOMAIN,
                vtLink=self._generate_vt_domain_link(domain),
                context=context
            )
            for domain in sorted(domains)
        ]

    def _clean_url(self, url: str) -> str:
        """Clean and normalize URL."""
        url = url.strip()
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://', 'ftp://')):
            if url.startswith('www.'):
                url = 'http://' + url
            else:
                return url  # Return as-is if no clear protocol
        
        # Remove trailing punctuation
        url = re.sub(r'[.,;:!?)\]}>"\'\s]+$', '', url)
        
        # Decode URL encoding
        try:
            url = unquote(url)
        except:
            pass  # Keep original if decoding fails
        
        return url

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format and accessibility."""
        try:
            parsed = urlparse(url)
            return (
                parsed.scheme in ('http', 'https', 'ftp') and
                parsed.netloc and
                len(url) < 2048 and  # Reasonable length limit
                not self._is_localhost_url(parsed.netloc)
            )
        except:
            return False

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        try:
            parts = ip.split('.')
            return (
                len(parts) == 4 and
                all(0 <= int(part) <= 255 for part in parts) and
                not ip.startswith('0.') and  # Avoid leading zeros
                ip != '0.0.0.0'
            )
        except:
            return False

    def _is_valid_ipv6(self, ip: str) -> bool:
        """Validate IPv6 address format."""
        try:
            # Basic validation - more comprehensive validation could be added
            return (
                ':' in ip and
                len(ip) >= 3 and
                not ip.startswith('::0') and
                ip != '::'
            )
        except:
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) > 253:
            return False
        
        # Check for valid domain format
        domain_regex = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        return (
            domain_regex.match(domain) and
            '.' in domain and
            not domain.startswith('.') and
            not domain.endswith('.') and
            len(domain.split('.')[-1]) >= 2  # Valid TLD
        )

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private ranges."""
        return any(pattern.match(ip) for pattern in self.private_ip_ranges)

    def _is_localhost_url(self, netloc: str) -> bool:
        """Check if URL points to localhost."""
        localhost_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        return any(pattern in netloc.lower() for pattern in localhost_patterns)

    def _is_email_domain_only(self, domain: str, content: str) -> bool:
        """Check if domain appears only in email addresses."""
        # Look for the domain in email context
        email_pattern = re.compile(rf'\b\w+@{re.escape(domain)}\b', re.IGNORECASE)
        standalone_pattern = re.compile(rf'\b{re.escape(domain)}\b', re.IGNORECASE)
        
        email_matches = len(email_pattern.findall(content))
        total_matches = len(standalone_pattern.findall(content))
        
        # If domain only appears in email addresses, exclude it
        return email_matches > 0 and email_matches == total_matches

    def _generate_vt_url_link(self, url: str) -> str:
        """Generate VirusTotal link for URL analysis."""
        import base64
        
        # Generate VirusTotal URL ID using base64 encoding (official method)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return f"https://www.virustotal.com/gui/url/{url_id}"
    
    async def _get_vt_analysis_url(self, url: str) -> str:
        """
        Get VirusTotal analysis URL - always triggers fresh scan for latest results.
        Returns live analysis URL showing scanning progress.
        """
        try:
            # Always request fresh analysis for most up-to-date results
            return await virustotal_service.ensure_fresh_analysis(url)
                
        except Exception as e:
            # Fallback to static URL if any error occurs
            logger.warning(f"VirusTotal analysis failed for {url}: {str(e)}")
            return self._generate_vt_url_link(url)

    def _generate_vt_ip_link(self, ip: str) -> str:
        """Generate VirusTotal link for IP analysis."""
        return f"https://www.virustotal.com/gui/ip-address/{ip}"

    def _generate_vt_domain_link(self, domain: str) -> str:
        """Generate VirusTotal link for domain analysis."""
        return f"https://www.virustotal.com/gui/domain/{domain}"

    def get_ioc_summary(self, ioc_collection: IOCCollection) -> Dict[str, int]:
        """
        Get summary statistics for extracted IOCs.
        
        Args:
            ioc_collection: Collection of extracted IOCs
            
        Returns:
            Dictionary with IOC counts by type
        """
        return {
            'urls': len(ioc_collection.urls),
            'ips': len(ioc_collection.ips),
            'domains': len(ioc_collection.domains),
            'total': len(ioc_collection.urls) + len(ioc_collection.ips) + len(ioc_collection.domains)
        }