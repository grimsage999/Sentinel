"""
Threat Intelligence Harvester

Autonomously collects cybersecurity threat intelligence from RSS feeds and web sources.
Implements rate limiting and caching to stay within credit budget constraints.
"""

import asyncio
import aiohttp
import feedparser
import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import json
import hashlib

logger = logging.getLogger(__name__)


class ThreatIntelligenceHarvester:
    """
    Harvests threat intelligence from configured RSS feeds and web sources.
    Designed for credit efficiency with aggressive caching and rate limiting.
    """
    
    # Default threat intelligence sources (free feeds)
    DEFAULT_SOURCES = [
        {
            "name": "CISA Alerts",
            "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "type": "rss",
            "credibility_score": 95
        },
        {
            "name": "US-CERT Alerts",
            "url": "https://www.us-cert.gov/ncas/alerts.xml", 
            "type": "rss",
            "credibility_score": 95
        },
        {
            "name": "SANS Internet Storm Center",
            "url": "https://isc.sans.edu/rssfeed.xml",
            "type": "rss", 
            "credibility_score": 85
        },
        {
            "name": "Malware Bytes Labs",
            "url": "https://blog.malwarebytes.com/feed/",
            "type": "rss",
            "credibility_score": 80
        },
        {
            "name": "Krebs on Security",
            "url": "https://krebsonsecurity.com/feed/",
            "type": "rss",
            "credibility_score": 90
        }
    ]
    
    def __init__(self, db_path: str = "threat_intel.db", sources: Optional[List[Dict]] = None):
        """
        Initialize the harvester with database path and sources.
        
        Args:
            db_path: Path to SQLite database for storing threat intelligence
            sources: List of threat intelligence sources to monitor
        """
        self.db_path = db_path
        self.sources = sources or self.DEFAULT_SOURCES
        self.session = None
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database tables for threat intelligence storage."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table for raw threat intelligence entries
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel_raw (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT NOT NULL,
                entry_id TEXT UNIQUE NOT NULL,
                title TEXT,
                content TEXT,
                published_date TEXT,
                source_url TEXT,
                credibility_score INTEGER,
                content_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Table for processed IOCs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                source_entry_id INTEGER,
                confidence_score INTEGER,
                context TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (source_entry_id) REFERENCES threat_intel_raw (id)
            )
        ''')
        
        # Index for fast IOC lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_value ON threat_intel_iocs (ioc_value)
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Initialized threat intelligence database at {self.db_path}")
        
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session for web requests."""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=30)
            headers = {
                'User-Agent': 'Cognito-ThreatIntel-Agent/1.0 (Security Research)',
                'Accept': 'application/rss+xml, application/xml, text/xml'
            }
            self.session = aiohttp.ClientSession(timeout=timeout, headers=headers)
        return self.session
        
    async def harvest_all_sources(self) -> Dict[str, Any]:
        """
        Harvest threat intelligence from all configured sources.
        
        Returns:
            Dict containing harvest results and statistics
        """
        results = {
            "sources_processed": 0,
            "entries_collected": 0,
            "entries_new": 0,
            "errors": [],
            "started_at": datetime.now().isoformat()
        }
        
        try:
            session = await self._get_session()
            
            for source in self.sources:
                try:
                    logger.info(f"Harvesting from source: {source['name']}")
                    source_result = await self._harvest_rss_source(session, source)
                    
                    results["sources_processed"] += 1
                    results["entries_collected"] += source_result["entries_collected"]
                    results["entries_new"] += source_result["entries_new"]
                    
                    # Rate limiting between sources (credit conservation)
                    await asyncio.sleep(2)
                    
                except Exception as e:
                    error_msg = f"Error harvesting {source['name']}: {str(e)}"
                    logger.error(error_msg)
                    results["errors"].append(error_msg)
                    
        except Exception as e:
            logger.error(f"Critical error in harvest_all_sources: {str(e)}")
            results["errors"].append(f"Critical error: {str(e)}")
            
        results["completed_at"] = datetime.now().isoformat()
        logger.info(f"Harvest completed: {results}")
        return results
        
    async def _harvest_rss_source(self, session: aiohttp.ClientSession, source: Dict) -> Dict[str, int]:
        """
        Harvest threat intelligence from a single RSS source.
        
        Args:
            session: aiohttp session for making requests
            source: Source configuration dictionary
            
        Returns:
            Dict with collection statistics
        """
        result = {"entries_collected": 0, "entries_new": 0}
        
        try:
            async with session.get(source["url"]) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status} from {source['url']}")
                    
                content = await response.text()
                
                # Parse RSS/Atom feed
                feed = feedparser.parse(content)
                
                if not feed.entries:
                    logger.warning(f"No entries found in feed: {source['name']}")
                    return result
                    
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                for entry in feed.entries[:10]:  # Limit to 10 most recent entries
                    try:
                        # Extract entry data
                        entry_id = entry.get('id', entry.get('link', ''))
                        title = entry.get('title', '')
                        content = entry.get('summary', entry.get('content', [{}])[0].get('value', ''))
                        published = entry.get('published', entry.get('updated', ''))
                        
                        # Create content hash to avoid duplicates
                        content_hash = hashlib.md5(f"{title}{content}".encode()).hexdigest()
                        
                        # Check if entry already exists
                        cursor.execute(
                            "SELECT id FROM threat_intel_raw WHERE entry_id = ? OR content_hash = ?",
                            (entry_id, content_hash)
                        )
                        
                        if cursor.fetchone():
                            continue  # Skip duplicate entry
                            
                        # Insert new entry
                        cursor.execute('''
                            INSERT INTO threat_intel_raw 
                            (source_name, entry_id, title, content, published_date, source_url, credibility_score, content_hash)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            source["name"],
                            entry_id,
                            title,
                            content,
                            published,
                            entry.get('link', source['url']),
                            source["credibility_score"],
                            content_hash
                        ))
                        
                        result["entries_new"] += 1
                        result["entries_collected"] += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing entry from {source['name']}: {str(e)}")
                        
                conn.commit()
                conn.close()
                
        except Exception as e:
            logger.error(f"Error harvesting RSS source {source['name']}: {str(e)}")
            raise
            
        logger.info(f"Harvested {result['entries_new']} new entries from {source['name']}")
        return result
        
    async def get_recent_entries(self, hours: int = 24, min_credibility: int = 70) -> List[Dict]:
        """
        Get recently harvested threat intelligence entries.
        
        Args:
            hours: Number of hours back to look
            min_credibility: Minimum credibility score filter
            
        Returns:
            List of threat intelligence entries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        cursor.execute('''
            SELECT source_name, title, content, published_date, source_url, credibility_score
            FROM threat_intel_raw 
            WHERE created_at >= ? AND credibility_score >= ?
            ORDER BY created_at DESC
            LIMIT 50
        ''', (cutoff_time.isoformat(), min_credibility))
        
        columns = [desc[0] for desc in cursor.description]
        entries = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return entries
        
    async def cleanup_old_entries(self, days: int = 30):
        """Remove threat intelligence entries older than specified days."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = datetime.now() - timedelta(days=days)
        
        cursor.execute("DELETE FROM threat_intel_raw WHERE created_at < ?", (cutoff_time.isoformat(),))
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        logger.info(f"Cleaned up {deleted_count} old threat intelligence entries")
        return deleted_count
        
    async def close(self):
        """Close the harvester and cleanup resources."""
        if self.session:
            await self.session.close()
            self.session = None
            logger.info("Threat intelligence harvester session closed")