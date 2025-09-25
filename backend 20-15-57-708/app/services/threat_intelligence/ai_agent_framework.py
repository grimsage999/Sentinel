"""
AI Agent Framework Integration
Orchestrates the complete threat intelligence pipeline with enhanced capabilities
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from .logger import threat_intel_logger, ThreatIntelLogLevel, ThreatIntelOperation
from .response_generator import ThreatResponseGenerator
from .sharing import ThreatIntelligenceSharing
from .service import ThreatIntelService
from .harvester import ThreatIntelligenceHarvester
from .processor import ThreatIntelligenceProcessor


class AIThreatIntelligenceAgent:
    """
    Complete AI-powered threat intelligence agent framework
    Integrates all components for autonomous threat intelligence operations
    """
    
    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        
        # Initialize core components
        self.threat_intel_service = ThreatIntelService(db_path=db_path)
        self.harvester = ThreatIntelligenceHarvester(db_path=db_path)
        self.processor = ThreatIntelligenceProcessor(db_path=db_path)
        
        # Initialize Phase 3 components
        self.response_generator = ThreatResponseGenerator()
        self.sharing_service = ThreatIntelligenceSharing(db_path=db_path)
        
        threat_intel_logger.log(
            level=ThreatIntelLogLevel.INFO,
            operation=ThreatIntelOperation.ANALYSIS,
            message="AI Threat Intelligence Agent Framework initialized",
            details={
                "components": [
                    "ThreatIntelService",
                    "ThreatIntelligenceHarvester", 
                    "ThreatIntelligenceProcessor",
                    "ThreatResponseGenerator",
                    "ThreatIntelligenceSharing"
                ],
                "database": db_path
            }
        )
    
    async def process_email_analysis(self,
                                   analysis_result: Dict[str, Any],
                                   iocs: List[Dict[str, Any]],
                                   request_id: str) -> Dict[str, Any]:
        """
        Complete AI-powered processing of email analysis with threat intelligence
        
        Args:
            analysis_result: Email analysis result from LLM
            iocs: Extracted IOCs from email
            request_id: Request ID for tracking
            
        Returns:
            Enhanced analysis result with threat intelligence and automated responses
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.INFO,
                operation=ThreatIntelOperation.ANALYSIS,
                message=f"Starting AI-powered threat intelligence processing",
                iocs_processed=len(iocs),
                request_id=request_id
            )
            
            # Phase 1 & 2: IOC Enrichment with Threat Intelligence
            enriched_iocs = []
            threat_intel_findings = []
            
            for ioc in iocs:
                ioc_value = ioc.get('value', '')
                ioc_type = ioc.get('type', '').lower()
                
                if ioc_value:
                    # Check threat intelligence for this IOC
                    threat_intel = await self.threat_intel_service.check_ioc_threat_intelligence(ioc_value)
                    
                    enriched_ioc = {**ioc}
                    if threat_intel:
                        enriched_ioc['has_threat_intelligence'] = True
                        enriched_ioc['threat_intelligence'] = threat_intel
                        threat_intel_findings.append({
                            'ioc_value': ioc_value,
                            'ioc_type': ioc_type,
                            **threat_intel
                        })
                        
                        # Log enrichment
                        threat_intel_logger.log_enrichment_operation(
                            ioc_value=ioc_value,
                            ioc_type=ioc_type,
                            threat_intelligence_found=True,
                            confidence_score=threat_intel.get('confidence_score'),
                            threat_level=threat_intel.get('threat_level'),
                            source=threat_intel.get('source'),
                            processing_time=0.1,  # Individual IOC processing is fast
                            request_id=request_id
                        )
                    else:
                        enriched_ioc['has_threat_intelligence'] = False
                        
                    enriched_iocs.append(enriched_ioc)
                    
            # Update analysis result with enriched IOCs
            enhanced_analysis = {**analysis_result}
            enhanced_analysis['iocs'] = enriched_iocs
            enhanced_analysis['threat_intelligence_findings'] = threat_intel_findings
            
            # Calculate enhanced risk score based on threat intelligence
            original_risk_score = analysis_result.get('risk_score', {}).get('score', 5)
            enhanced_risk_score = await self._calculate_enhanced_risk_score(
                original_risk_score, threat_intel_findings
            )
            
            enhanced_analysis['risk_score']['score'] = enhanced_risk_score
            enhanced_analysis['risk_score']['threat_intelligence_enhanced'] = True
            
            # Log analysis enhancement
            threat_intel_logger.log_analysis_enhancement(
                request_id=request_id,
                original_risk_score=original_risk_score,
                enhanced_risk_score=enhanced_risk_score,
                threat_intel_findings=len(threat_intel_findings),
                processing_time=(datetime.now(timezone.utc) - start_time).total_seconds()
            )
            
            # Phase 3: Generate Automated Responses
            automated_responses = []
            if threat_intel_findings:
                responses = await self.response_generator.analyze_threat_intelligence(
                    enhanced_analysis, threat_intel_findings, request_id
                )
                automated_responses = responses
                
            enhanced_analysis['automated_responses'] = [
                {
                    'response_id': resp.response_id,
                    'response_type': resp.response_type.value,
                    'threat_pattern': resp.threat_pattern.name,
                    'priority': resp.priority,
                    'requires_approval': resp.requires_approval,
                    'action_summary': resp.action.split('\n')[0]  # First line summary
                }
                for resp in automated_responses
            ]
            
            # Phase 3: Share Threat Intelligence
            sharing_results = {}
            if threat_intel_findings and enhanced_risk_score >= 6:  # Share medium-high risk threats
                threat_level = self._determine_threat_level(enhanced_risk_score)
                confidence_score = self._calculate_overall_confidence(threat_intel_findings)
                
                sharing_results = await self.sharing_service.share_threat_intelligence(
                    iocs=enriched_iocs,
                    analysis_context=enhanced_analysis,
                    threat_level=threat_level,
                    confidence_score=confidence_score,
                    request_id=request_id
                )
                
            enhanced_analysis['threat_intelligence_sharing'] = sharing_results
            
            # Add processing metadata
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            enhanced_analysis['ai_agent_processing'] = {
                'processing_time': processing_time,
                'threat_intel_findings': len(threat_intel_findings),
                'automated_responses_generated': len(automated_responses),
                'sharing_targets_notified': sharing_results.get('targets_notified', 0),
                'enhanced_risk_score': enhanced_risk_score,
                'framework_version': '1.0.0'
            }
            
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.INFO,
                operation=ThreatIntelOperation.ANALYSIS,
                message=f"AI threat intelligence processing completed successfully",
                iocs_processed=len(iocs),
                processing_time=processing_time,
                request_id=request_id,
                details={
                    'threat_intel_findings': len(threat_intel_findings),
                    'automated_responses': len(automated_responses),
                    'sharing_targets': sharing_results.get('targets_notified', 0),
                    'risk_enhancement': enhanced_risk_score - original_risk_score
                }
            )
            
            return enhanced_analysis
            
        except Exception as e:
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.ERROR,
                operation=ThreatIntelOperation.ANALYSIS,
                message=f"AI threat intelligence processing failed: {str(e)}",
                request_id=request_id,
                details={'error': str(e)}
            )
            
            # Return original analysis with error information
            return {
                **analysis_result,
                'ai_agent_error': str(e),
                'threat_intelligence_findings': [],
                'automated_responses': [],
                'threat_intelligence_sharing': {}
            }
    
    async def _calculate_enhanced_risk_score(self, original_score: int, 
                                           threat_intel_findings: List[Dict[str, Any]]) -> int:
        """Calculate enhanced risk score based on threat intelligence"""
        
        if not threat_intel_findings:
            return original_score
            
        # Calculate threat intelligence risk adjustment
        risk_adjustment = 0
        
        for finding in threat_intel_findings:
            threat_level = finding.get('threat_level', '').upper()
            confidence = finding.get('confidence_score', 0)
            
            # Base adjustment by threat level
            level_adjustment = {
                'CRITICAL': 3,
                'HIGH': 2,
                'MEDIUM': 1,
                'LOW': 0
            }.get(threat_level, 0)
            
            # Scale by confidence (0-100 -> 0-1)
            confidence_factor = confidence / 100.0
            
            # Add weighted adjustment
            risk_adjustment += level_adjustment * confidence_factor
            
        # Apply maximum adjustment of +3 points
        risk_adjustment = min(risk_adjustment, 3)
        
        # Calculate enhanced score (cap at 10)
        enhanced_score = min(original_score + int(risk_adjustment), 10)
        
        return enhanced_score
    
    def _determine_threat_level(self, risk_score: int) -> str:
        """Determine threat level from risk score"""
        if risk_score >= 9:
            return "CRITICAL"
        elif risk_score >= 7:
            return "HIGH"
        elif risk_score >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_overall_confidence(self, threat_intel_findings: List[Dict[str, Any]]) -> int:
        """Calculate overall confidence from threat intelligence findings"""
        if not threat_intel_findings:
            return 50
            
        confidences = [finding.get('confidence_score', 50) for finding in threat_intel_findings]
        return int(sum(confidences) / len(confidences))
    
    async def get_framework_status(self) -> Dict[str, Any]:
        """Get comprehensive status of the AI agent framework"""
        
        try:
            # Get threat intelligence summary
            threat_intel_summary = await self.threat_intel_service.get_threat_summary(hours=24)
            
            # Get audit summary from logger
            audit_summary = threat_intel_logger.get_audit_summary(hours=24)
            
            # Get sharing statistics
            sharing_stats = self.sharing_service.get_sharing_statistics(hours=24)
            
            # Get recent alerts
            recent_alerts = threat_intel_logger.get_recent_alerts(limit=10)
            
            return {
                "framework_status": "operational",
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "threat_intelligence_summary": threat_intel_summary,
                "audit_summary": audit_summary,
                "sharing_statistics": sharing_stats,
                "recent_alerts": recent_alerts,
                "components_status": {
                    "threat_intel_service": "active",
                    "harvester": "active", 
                    "processor": "active",
                    "response_generator": "active",
                    "sharing_service": "active",
                    "logger": "active"
                }
            }
            
        except Exception as e:
            return {
                "framework_status": "error",
                "error": str(e),
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
    
    async def close(self):
        """Close all framework components"""
        try:
            await self.harvester.close()
            
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.INFO,
                operation=ThreatIntelOperation.ANALYSIS,
                message="AI Threat Intelligence Agent Framework shutdown completed"
            )
        except Exception as e:
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.ERROR,
                operation=ThreatIntelOperation.ANALYSIS,
                message=f"Error during framework shutdown: {str(e)}",
                details={'error': str(e)}
            )