"""
Threat Intelligence Service

Provides a high-level interface for querying processed threat intelligence data.
Integrates with the LLM analyzer to enrich email analysis with contextual threat data.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import asyncio
from functools import lru_cache

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """
    High-level service for querying and utilizing threat intelligence data.
    Provides cached queries and context enrichment for email analysis.
    """
    
    def __init__(self, db_path: str = "threat_intel.db"):
        """Initialize the service with database path."""
        self.db_path = db_path
        
    @lru_cache(maxsize=1000, typed=True)
    def _cached_ioc_lookup(self, ioc_value: str, cache_key: str) -> Tuple[bool, Optional[Dict]]:
        """
        Cached IOC lookup to minimize database hits.
        
        Args:
            ioc_value: IOC value to lookup
            cache_key: Cache invalidation key based on time
            
        Returns:
            Tuple of (found, ioc_data)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT i.ioc_type, i.ioc_value, i.confidence_score, i.context, 
                       i.first_seen, i.last_seen, r.source_name, r.title, r.credibility_score
                FROM threat_intel_iocs i
                JOIN threat_intel_raw r ON i.source_entry_id = r.id
                WHERE i.ioc_value = ?
                ORDER BY i.confidence_score DESC, i.last_seen DESC
                LIMIT 1
            ''', (ioc_value.lower(),))
            
            result = cursor.fetchone()
            
            if result:
                columns = ['ioc_type', 'ioc_value', 'confidence_score', 'context', 
                          'first_seen', 'last_seen', 'source_name', 'title', 'credibility_score']
                ioc_data = dict(zip(columns, result))
                return True, ioc_data
            else:
                return False, None
                
        except Exception as e:
            logger.error(f"Error in cached IOC lookup for {ioc_value}: {str(e)}")
            return False, None
        finally:
            conn.close()
            
    def _get_cache_key(self, hours: int = 1) -> str:
        """Generate cache key that changes every specified hours."""
        return f"cache_{datetime.now().hour // hours}"
        
    async def check_ioc_threat_intelligence(self, ioc_value: str) -> Optional[Dict[str, Any]]:
        """
        Check if an IOC has associated threat intelligence.
        
        Args:
            ioc_value: IOC value to check (URL, IP, domain, hash, etc.)
            
        Returns:
            Dict with threat intelligence data if found, None otherwise
        """
        try:
            # Use cached lookup with 1-hour cache invalidation
            cache_key = self._get_cache_key(1)
            found, ioc_data = self._cached_ioc_lookup(ioc_value, cache_key)
            
            if found and ioc_data:
                # Enrich the data with analysis
                enriched_data = {
                    'ioc_value': ioc_data['ioc_value'],
                    'ioc_type': ioc_data['ioc_type'],
                    'threat_level': self._calculate_threat_level(ioc_data['confidence_score']),
                    'confidence_score': ioc_data['confidence_score'],
                    'source_credibility': ioc_data['credibility_score'],
                    'context': ioc_data['context'],
                    'source': ioc_data['source_name'],
                    'report_title': ioc_data['title'],
                    'first_seen': ioc_data['first_seen'],
                    'last_seen': ioc_data['last_seen'],
                    'threat_context': self._generate_threat_context(ioc_data)
                }
                
                logger.info(f"Found threat intelligence for IOC: {ioc_value}")
                return enriched_data
                
            return None
            
        except Exception as e:
            logger.error(f"Error checking IOC threat intelligence for {ioc_value}: {str(e)}")
            return None
            
    async def enrich_iocs_with_intelligence(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich a list of IOCs with available threat intelligence.
        
        Args:
            iocs: List of IOC dictionaries from email analysis
            
        Returns:
            List of enriched IOC dictionaries with threat intelligence
        """
        enriched_iocs = []
        
        for ioc in iocs:
            try:
                ioc_value = ioc.get('value', '')
                if not ioc_value:
                    enriched_iocs.append(ioc)
                    continue
                    
                # Check for threat intelligence
                threat_intel = await self.check_ioc_threat_intelligence(ioc_value)
                
                if threat_intel:
                    # Merge original IOC data with threat intelligence
                    enriched_ioc = {**ioc}
                    enriched_ioc.update({
                        'has_threat_intelligence': True,
                        'threat_intelligence': threat_intel,
                        'enhanced_confidence': max(
                            ioc.get('confidence', 50),
                            threat_intel['confidence_score']
                        )
                    })
                else:
                    enriched_ioc = {**ioc, 'has_threat_intelligence': False}
                    
                enriched_iocs.append(enriched_ioc)
                
            except Exception as e:
                logger.error(f"Error enriching IOC {ioc}: {str(e)}")
                enriched_iocs.append(ioc)  # Add original IOC on error
                
        return enriched_iocs
        
    def _calculate_threat_level(self, confidence_score: int) -> str:
        """
        Calculate threat level based on confidence score.
        
        Args:
            confidence_score: IOC confidence score (0-100)
            
        Returns:
            Threat level string
        """
        if confidence_score >= 85:
            return "HIGH"
        elif confidence_score >= 70:
            return "MEDIUM" 
        elif confidence_score >= 50:
            return "LOW"
        else:
            return "INFORMATIONAL"
            
    def _generate_threat_context(self, ioc_data: Dict[str, Any]) -> str:
        """
        Generate human-readable threat context from IOC data.
        
        Args:
            ioc_data: IOC data dictionary
            
        Returns:
            Contextual threat description
        """
        try:
            ioc_type = ioc_data.get('ioc_type', 'unknown')
            source = ioc_data.get('source_name', 'unknown source')
            confidence = ioc_data.get('confidence_score', 0)
            context = ioc_data.get('context', '')
            
            threat_level = self._calculate_threat_level(confidence)
            
            # Build contextual description
            context_parts = []
            
            if ioc_type == 'url':
                context_parts.append(f"This URL has been identified as potentially malicious")
            elif ioc_type == 'domain':
                context_parts.append(f"This domain has been flagged in threat intelligence")
            elif ioc_type == 'ipv4':
                context_parts.append(f"This IP address has suspicious activity reported")
            elif ioc_type.startswith('hash_'):
                context_parts.append(f"This file hash matches known malware signatures")
            else:
                context_parts.append(f"This indicator has been reported in cybersecurity feeds")
                
            context_parts.append(f"by {source} with {threat_level.lower()} confidence")
            
            if context and len(context) > 20:
                # Add snippet of original context
                context_snippet = context[:150] + "..." if len(context) > 150 else context
                context_parts.append(f"Context: {context_snippet}")
                
            return ". ".join(context_parts) + "."
            
        except Exception as e:
            logger.error(f"Error generating threat context: {str(e)}")
            return "This indicator has been identified in threat intelligence feeds."
            
    async def get_threat_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get summary of recent threat intelligence activity.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dict with threat intelligence summary statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Count recent IOCs by type and threat level
            cursor.execute('''
                SELECT i.ioc_type, 
                       COUNT(*) as count,
                       AVG(i.confidence_score) as avg_confidence,
                       MAX(i.confidence_score) as max_confidence
                FROM threat_intel_iocs i
                WHERE i.first_seen >= datetime('now', '-' || ? || ' hours')
                GROUP BY i.ioc_type
                ORDER BY count DESC
            ''', (hours,))
            
            ioc_summary = []
            total_iocs = 0
            
            for row in cursor.fetchall():
                ioc_type, count, avg_confidence, max_confidence = row
                threat_level = self._calculate_threat_level(int(avg_confidence))
                
                ioc_summary.append({
                    'type': ioc_type,
                    'count': count,
                    'avg_confidence': round(avg_confidence, 1),
                    'max_confidence': max_confidence,
                    'threat_level': threat_level
                })
                
                total_iocs += count
                
            # Get source statistics
            cursor.execute('''
                SELECT r.source_name, 
                       COUNT(*) as entries,
                       AVG(r.credibility_score) as avg_credibility
                FROM threat_intel_raw r
                WHERE r.created_at >= datetime('now', '-' || ? || ' hours')
                GROUP BY r.source_name
                ORDER BY entries DESC
            ''', (hours,))
            
            source_summary = []
            for row in cursor.fetchall():
                source_name, entries, avg_credibility = row
                source_summary.append({
                    'source': source_name,
                    'entries': entries,
                    'avg_credibility': round(avg_credibility, 1)
                })
                
            return {
                'period_hours': hours,
                'total_iocs': total_iocs,
                'ioc_breakdown': ioc_summary,
                'source_breakdown': source_summary,
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating threat summary: {str(e)}")
            return {
                'period_hours': hours,
                'total_iocs': 0,
                'ioc_breakdown': [],
                'source_breakdown': [],
                'error': str(e),
                'generated_at': datetime.now().isoformat()
            }
        finally:
            conn.close()
            
    async def search_threat_intelligence(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search threat intelligence data by keyword.
        
        Args:
            query: Search query string
            limit: Maximum number of results
            
        Returns:
            List of matching threat intelligence entries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            search_term = f"%{query}%"
            
            cursor.execute('''
                SELECT r.source_name, r.title, r.content, r.published_date, 
                       r.credibility_score, i.ioc_value, i.ioc_type, i.confidence_score
                FROM threat_intel_raw r
                LEFT JOIN threat_intel_iocs i ON r.id = i.source_entry_id
                WHERE r.title LIKE ? OR r.content LIKE ? OR i.ioc_value LIKE ?
                ORDER BY r.credibility_score DESC, i.confidence_score DESC
                LIMIT ?
            ''', (search_term, search_term, search_term, limit))
            
            results = []
            for row in cursor.fetchall():
                source_name, title, content, published_date, credibility_score, ioc_value, ioc_type, confidence_score = row
                
                result = {
                    'source': source_name,
                    'title': title,
                    'content_snippet': content[:200] + "..." if len(content) > 200 else content,
                    'published_date': published_date,
                    'credibility_score': credibility_score
                }
                
                if ioc_value:
                    result['related_ioc'] = {
                        'value': ioc_value,
                        'type': ioc_type,
                        'confidence': confidence_score
                    }
                    
                results.append(result)
                
            return results
            
        except Exception as e:
            logger.error(f"Error searching threat intelligence: {str(e)}")
            return []
        finally:
            conn.close()
            
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
        
        try:
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
            
            return results
            
        except Exception as e:
            logger.error(f"Error getting recent IOCs: {str(e)}")
            return []
        finally:
            conn.close()