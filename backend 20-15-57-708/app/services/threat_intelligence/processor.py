"""
Threat Intelligence Processor

Processes raw threat intelligence data to extract structured IOCs (Indicators of Compromise)
and enriches the data with confidence scoring and context information.
"""

import re
import sqlite3
import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
import ipaddress
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ThreatIntelligenceProcessor:
    """
    Processes raw threat intelligence to extract and validate IOCs.
    Implements efficient regex patterns and scoring algorithms.
    """
    
    # Regex patterns for IOC extraction
    IOC_PATTERNS = {
        'ipv4': {
            'pattern': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'confidence_base': 80
        },
        'domain': {
            'pattern': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'confidence_base': 70
        },
        'url': {
            'pattern': r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?[\w&=%.]*)?)??',
            'confidence_base': 85
        },
        'hash_md5': {
            'pattern': r'\b[a-fA-F0-9]{32}\b',
            'confidence_base': 95
        },
        'hash_sha1': {
            'pattern': r'\b[a-fA-F0-9]{40}\b',
            'confidence_base': 95
        },
        'hash_sha256': {
            'pattern': r'\b[a-fA-F0-9]{64}\b',
            'confidence_base': 95
        },
        'email': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'confidence_base': 75
        },
        'cve': {
            'pattern': r'CVE-\d{4}-\d{4,7}',
            'confidence_base': 90
        }
    }
    
    # Keywords that increase confidence when found near IOCs
    THREAT_KEYWORDS = [
        'malicious', 'malware', 'trojan', 'phishing', 'ransomware', 'botnet',
        'c2', 'command and control', 'backdoor', 'exploit', 'vulnerability',
        'attack', 'campaign', 'threat', 'suspicious', 'blacklist', 'blocklist',
        'compromised', 'infected', 'indicators', 'ioc', 'apt', 'threat actor'
    ]
    
    # Private IP ranges and common false positives to filter out
    PRIVATE_IP_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16'
    ]
    
    # Common domains to filter out (false positives)
    COMMON_DOMAINS = {
        'google.com', 'microsoft.com', 'amazon.com', 'facebook.com',
        'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
        'example.com', 'test.com', 'localhost', 'w3.org'
    }
    
    def __init__(self, db_path: str = "threat_intel.db"):
        """Initialize the processor with database path."""
        self.db_path = db_path
        self._compile_patterns()
        
    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        self.compiled_patterns = {}
        for ioc_type, config in self.IOC_PATTERNS.items():
            self.compiled_patterns[ioc_type] = re.compile(config['pattern'], re.IGNORECASE)
            
    async def process_all_unprocessed(self) -> Dict[str, Any]:
        """
        Process all unprocessed threat intelligence entries to extract IOCs.
        
        Returns:
            Dict containing processing results and statistics
        """
        results = {
            "entries_processed": 0,
            "iocs_extracted": 0,
            "processing_started": datetime.now().isoformat()
        }
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get unprocessed entries (those without extracted IOCs)
            cursor.execute('''
                SELECT DISTINCT r.id, r.source_name, r.title, r.content, r.credibility_score
                FROM threat_intel_raw r
                LEFT JOIN threat_intel_iocs i ON r.id = i.source_entry_id
                WHERE i.id IS NULL
                ORDER BY r.created_at DESC
                LIMIT 100
            ''')
            
            entries = cursor.fetchall()
            
            for entry_data in entries:
                entry_id, source_name, title, content, credibility_score = entry_data
                
                # Extract IOCs from title and content
                combined_text = f"{title} {content}"
                extracted_iocs = self._extract_iocs_from_text(combined_text, credibility_score)
                
                # Store extracted IOCs
                for ioc in extracted_iocs:
                    cursor.execute('''
                        INSERT INTO threat_intel_iocs 
                        (ioc_type, ioc_value, source_entry_id, confidence_score, context)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        ioc['type'],
                        ioc['value'],
                        entry_id,
                        ioc['confidence'],
                        ioc['context']
                    ))
                    
                results["iocs_extracted"] += len(extracted_iocs)
                results["entries_processed"] += 1
                
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error processing threat intelligence entries: {str(e)}")
            conn.rollback()
            raise
        finally:
            conn.close()
            
        results["processing_completed"] = datetime.now().isoformat()
        logger.info(f"IOC processing completed: {results}")
        return results
        
    def _extract_iocs_from_text(self, text: str, base_credibility: int) -> List[Dict[str, Any]]:
        """
        Extract IOCs from text using pattern matching and confidence scoring.
        
        Args:
            text: Text content to analyze
            base_credibility: Base credibility score from source
            
        Returns:
            List of extracted IOC dictionaries
        """
        iocs = []
        text_lower = text.lower()
        
        # Check for threat-related keywords to boost confidence
        threat_keyword_count = sum(1 for keyword in self.THREAT_KEYWORDS if keyword in text_lower)
        keyword_boost = min(20, threat_keyword_count * 5)  # Max 20 point boost
        
        for ioc_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            
            for match in matches:
                # Validate and filter the IOC
                if self._is_valid_ioc(ioc_type, match):
                    # Calculate confidence score
                    base_confidence = self.IOC_PATTERNS[ioc_type]['confidence_base']
                    confidence = min(100, base_confidence + keyword_boost + (base_credibility - 70))
                    
                    # Extract context around the IOC
                    context = self._extract_context(text, match)
                    
                    iocs.append({
                        'type': ioc_type,
                        'value': match.lower() if ioc_type in ['domain', 'email', 'url'] else match,
                        'confidence': confidence,
                        'context': context
                    })
                    
        # Remove duplicates while preserving highest confidence
        unique_iocs = {}
        for ioc in iocs:
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in unique_iocs or unique_iocs[key]['confidence'] < ioc['confidence']:
                unique_iocs[key] = ioc
                
        return list(unique_iocs.values())
        
    def _is_valid_ioc(self, ioc_type: str, value: str) -> bool:
        """
        Validate IOC to filter out false positives.
        
        Args:
            ioc_type: Type of IOC (ipv4, domain, etc.)
            value: IOC value to validate
            
        Returns:
            True if IOC is valid and not a false positive
        """
        try:
            if ioc_type == 'ipv4':
                # Filter out private IP ranges
                ip = ipaddress.IPv4Address(value)
                for private_range in self.PRIVATE_IP_RANGES:
                    if ip in ipaddress.IPv4Network(private_range):
                        return False
                return True
                
            elif ioc_type == 'domain':
                # Filter out common legitimate domains
                domain = value.lower()
                if domain in self.COMMON_DOMAINS:
                    return False
                # Basic domain validation
                if len(domain) < 4 or domain.count('.') < 1:
                    return False
                return True
                
            elif ioc_type == 'url':
                # Basic URL validation
                try:
                    parsed = urlparse(value)
                    if not parsed.netloc or parsed.netloc.lower() in self.COMMON_DOMAINS:
                        return False
                    return True
                except Exception:
                    return False
                    
            elif ioc_type.startswith('hash_'):
                # Hash validation (just length check, already matched by regex)
                return len(value) in [32, 40, 64]  # MD5, SHA1, SHA256
                
            elif ioc_type == 'email':
                # Basic email validation
                return '@' in value and len(value) > 5
                
            elif ioc_type == 'cve':
                # CVE validation
                return value.upper().startswith('CVE-')
                
            return True
            
        except Exception as e:
            logger.warning(f"Error validating IOC {ioc_type}:{value}: {str(e)}")
            return False
            
    def _extract_context(self, text: str, ioc_value: str, context_length: int = 100) -> str:
        """
        Extract context around an IOC for better understanding.
        
        Args:
            text: Full text content
            ioc_value: IOC value to find context for
            context_length: Number of characters to include on each side
            
        Returns:
            Context string around the IOC
        """
        try:
            # Find the IOC in the text (case-insensitive)
            text_lower = text.lower()
            ioc_lower = ioc_value.lower()
            
            index = text_lower.find(ioc_lower)
            if index == -1:
                return ""
                
            # Extract context around the IOC
            start = max(0, index - context_length)
            end = min(len(text), index + len(ioc_value) + context_length)
            
            context = text[start:end].strip()
            
            # Clean up context (remove extra whitespace)
            context = re.sub(r'\s+', ' ', context)
            
            return context
            
        except Exception as e:
            logger.warning(f"Error extracting context for {ioc_value}: {str(e)}")
            return ""
            
    async def get_iocs_by_value(self, ioc_value: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieve IOCs and their context by value.
        
        Args:
            ioc_value: IOC value to search for
            limit: Maximum number of results
            
        Returns:
            List of IOC dictionaries with context
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT i.ioc_type, i.ioc_value, i.confidence_score, i.context, 
                   i.first_seen, i.last_seen, r.source_name, r.title
            FROM threat_intel_iocs i
            JOIN threat_intel_raw r ON i.source_entry_id = r.id
            WHERE i.ioc_value = ?
            ORDER BY i.confidence_score DESC, i.last_seen DESC
            LIMIT ?
        ''', (ioc_value.lower(), limit))
        
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return results
        
    async def get_recent_iocs(self, hours: int = 24, min_confidence: int = 75) -> List[Dict[str, Any]]:
        """
        Get recently processed IOCs with high confidence.
        
        Args:
            hours: Number of hours back to look
            min_confidence: Minimum confidence score filter
            
        Returns:
            List of high-confidence IOC dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT i.ioc_type, i.ioc_value, i.confidence_score, i.context, 
                   r.source_name, r.title
            FROM threat_intel_iocs i
            JOIN threat_intel_raw r ON i.source_entry_id = r.id
            WHERE i.first_seen >= datetime('now', '-' || ? || ' hours')
            AND i.confidence_score >= ?
            ORDER BY i.confidence_score DESC, i.first_seen DESC
            LIMIT 100
        ''', (hours, min_confidence))
        
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return results