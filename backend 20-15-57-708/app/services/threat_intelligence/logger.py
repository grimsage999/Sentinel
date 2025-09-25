"""
Enhanced logging service for threat intelligence operations
Provides comprehensive audit trails and operational monitoring
"""

import logging
import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum


class ThreatIntelLogLevel(str, Enum):
    """Log levels for threat intelligence operations"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    DEBUG = "DEBUG"


class ThreatIntelOperation(str, Enum):
    """Types of threat intelligence operations"""
    HARVEST = "HARVEST"
    PROCESSING = "PROCESSING"
    IOC_EXTRACTION = "IOC_EXTRACTION"
    ENRICHMENT = "ENRICHMENT"
    CORRELATION = "CORRELATION"
    ANALYSIS = "ANALYSIS"
    SHARING = "SHARING"
    RESPONSE_GENERATION = "RESPONSE_GENERATION"


@dataclass
class ThreatIntelLogEntry:
    """Structured log entry for threat intelligence operations"""
    timestamp: str
    level: ThreatIntelLogLevel
    operation: ThreatIntelOperation
    message: str
    details: Optional[Dict[str, Any]] = None
    source: Optional[str] = None
    iocs_processed: int = 0
    confidence_score: Optional[int] = None
    threat_level: Optional[str] = None
    processing_time: Optional[float] = None
    request_id: Optional[str] = None


class ThreatIntelligenceLogger:
    """
    Enhanced logger for threat intelligence operations
    Provides audit trails, operational monitoring, and analytics
    """
    
    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self.logger = logging.getLogger("threat_intelligence")
        self._setup_logger()
        self._initialize_audit_database()
        
    def _setup_logger(self):
        """Configure standard Python logger"""
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)
        
    def _initialize_audit_database(self):
        """Initialize audit logging database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intel_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details TEXT,
                    source TEXT,
                    iocs_processed INTEGER DEFAULT 0,
                    confidence_score INTEGER,
                    threat_level TEXT,
                    processing_time REAL,
                    request_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for efficient queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
                ON threat_intel_audit(timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_operation 
                ON threat_intel_audit(operation)
            ''')
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize audit database: {str(e)}")
        finally:
            conn.close()
    
    def log(self, 
            level: ThreatIntelLogLevel,
            operation: ThreatIntelOperation, 
            message: str,
            details: Optional[Dict[str, Any]] = None,
            source: Optional[str] = None,
            iocs_processed: int = 0,
            confidence_score: Optional[int] = None,
            threat_level: Optional[str] = None,
            processing_time: Optional[float] = None,
            request_id: Optional[str] = None):
        """
        Log a threat intelligence operation with structured data
        
        Args:
            level: Log level
            operation: Type of operation
            message: Human-readable message
            details: Additional structured data
            source: Source of the operation/data
            iocs_processed: Number of IOCs processed
            confidence_score: Confidence score (0-100)
            threat_level: Threat level assessment
            processing_time: Time taken for operation
            request_id: Request identifier for tracing
        """
        
        entry = ThreatIntelLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            level=level,
            operation=operation,
            message=message,
            details=details,
            source=source,
            iocs_processed=iocs_processed,
            confidence_score=confidence_score,
            threat_level=threat_level,
            processing_time=processing_time,
            request_id=request_id
        )
        
        # Log to standard Python logger
        log_msg = f"[{operation.value}] {message}"
        if source:
            log_msg += f" (source: {source})"
        if iocs_processed > 0:
            log_msg += f" (IOCs: {iocs_processed})"
            
        getattr(self.logger, level.value.lower())(log_msg)
        
        # Store in audit database
        self._store_audit_entry(entry)
        
    def _store_audit_entry(self, entry: ThreatIntelLogEntry):
        """Store audit entry in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO threat_intel_audit 
                (timestamp, level, operation, message, details, source, 
                 iocs_processed, confidence_score, threat_level, processing_time, request_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry.timestamp,
                entry.level.value,
                entry.operation.value,
                entry.message,
                json.dumps(entry.details) if entry.details else None,
                entry.source,
                entry.iocs_processed,
                entry.confidence_score,
                entry.threat_level,
                entry.processing_time,
                entry.request_id
            ))
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to store audit entry: {str(e)}")
        finally:
            conn.close()
    
    def log_harvest_operation(self, source: str, entries_collected: int, 
                            processing_time: float, success: bool = True,
                            request_id: Optional[str] = None):
        """Log threat intelligence harvesting operation"""
        level = ThreatIntelLogLevel.INFO if success else ThreatIntelLogLevel.ERROR
        message = f"Harvested {entries_collected} entries from {source}"
        
        if not success:
            message = f"Failed to harvest from {source}"
            
        self.log(
            level=level,
            operation=ThreatIntelOperation.HARVEST,
            message=message,
            source=source,
            iocs_processed=entries_collected,
            processing_time=processing_time,
            request_id=request_id,
            details={"entries_collected": entries_collected, "success": success}
        )
    
    def log_ioc_extraction(self, source_entry_id: str, iocs_extracted: int,
                          confidence_scores: List[int], processing_time: float,
                          request_id: Optional[str] = None):
        """Log IOC extraction operation"""
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        self.log(
            level=ThreatIntelLogLevel.INFO,
            operation=ThreatIntelOperation.IOC_EXTRACTION,
            message=f"Extracted {iocs_extracted} IOCs from entry {source_entry_id}",
            iocs_processed=iocs_extracted,
            confidence_score=int(avg_confidence),
            processing_time=processing_time,
            request_id=request_id,
            details={
                "source_entry_id": source_entry_id,
                "confidence_scores": confidence_scores,
                "avg_confidence": avg_confidence
            }
        )
    
    def log_enrichment_operation(self, ioc_value: str, ioc_type: str,
                               threat_intelligence_found: bool, confidence_score: Optional[int],
                               threat_level: Optional[str], source: Optional[str],
                               processing_time: float, request_id: Optional[str] = None):
        """Log IOC enrichment operation"""
        message = f"{'Enhanced' if threat_intelligence_found else 'No enhancement for'} {ioc_type}: {ioc_value}"
        
        self.log(
            level=ThreatIntelLogLevel.INFO,
            operation=ThreatIntelOperation.ENRICHMENT,
            message=message,
            source=source,
            iocs_processed=1,
            confidence_score=confidence_score,
            threat_level=threat_level,
            processing_time=processing_time,
            request_id=request_id,
            details={
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "threat_intelligence_found": threat_intelligence_found
            }
        )
    
    def log_analysis_enhancement(self, request_id: str, original_risk_score: int,
                               enhanced_risk_score: int, threat_intel_findings: int,
                               processing_time: float):
        """Log analysis enhancement with threat intelligence"""
        risk_change = enhanced_risk_score - original_risk_score
        message = f"Enhanced analysis with {threat_intel_findings} threat intel findings"
        
        if risk_change > 0:
            message += f" (risk increased by {risk_change})"
        elif risk_change < 0:
            message += f" (risk decreased by {abs(risk_change)})"
        else:
            message += " (no risk change)"
            
        self.log(
            level=ThreatIntelLogLevel.INFO,
            operation=ThreatIntelOperation.ANALYSIS,
            message=message,
            iocs_processed=threat_intel_findings,
            processing_time=processing_time,
            request_id=request_id,
            details={
                "original_risk_score": original_risk_score,
                "enhanced_risk_score": enhanced_risk_score,
                "risk_change": risk_change,
                "threat_intel_findings": threat_intel_findings
            }
        )
    
    def get_audit_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get audit summary for the specified time period"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get operation counts
            cursor.execute('''
                SELECT operation, level, COUNT(*) as count
                FROM threat_intel_audit
                WHERE timestamp >= datetime('now', '-' || ? || ' hours')
                GROUP BY operation, level
                ORDER BY operation, level
            ''', (hours,))
            
            operations = {}
            for row in cursor.fetchall():
                operation, level, count = row
                if operation not in operations:
                    operations[operation] = {}
                operations[operation][level] = count
                
            # Get processing statistics
            cursor.execute('''
                SELECT 
                    operation,
                    COUNT(*) as total_ops,
                    AVG(processing_time) as avg_processing_time,
                    SUM(iocs_processed) as total_iocs,
                    AVG(confidence_score) as avg_confidence
                FROM threat_intel_audit
                WHERE timestamp >= datetime('now', '-' || ? || ' hours')
                AND processing_time IS NOT NULL
                GROUP BY operation
            ''', (hours,))
            
            processing_stats = {}
            for row in cursor.fetchall():
                operation, total_ops, avg_time, total_iocs, avg_conf = row
                processing_stats[operation] = {
                    "total_operations": total_ops,
                    "avg_processing_time": round(avg_time, 3) if avg_time else None,
                    "total_iocs_processed": total_iocs or 0,
                    "avg_confidence": round(avg_conf, 1) if avg_conf else None
                }
                
            return {
                "period_hours": hours,
                "operations_by_level": operations,
                "processing_statistics": processing_stats,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate audit summary: {str(e)}")
            return {"error": str(e)}
        finally:
            conn.close()
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent threat intelligence alerts/events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT timestamp, level, operation, message, source, 
                       iocs_processed, confidence_score, threat_level, request_id
                FROM threat_intel_audit
                WHERE level IN ('WARNING', 'ERROR', 'CRITICAL')
                   OR (confidence_score IS NOT NULL AND confidence_score >= 75)
                   OR threat_level IN ('HIGH', 'CRITICAL')
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            columns = [desc[0] for desc in cursor.description]
            alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to get recent alerts: {str(e)}")
            return []
        finally:
            conn.close()


# Global logger instance
threat_intel_logger = ThreatIntelligenceLogger()