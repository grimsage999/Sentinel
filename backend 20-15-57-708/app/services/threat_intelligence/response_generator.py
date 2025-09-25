"""
Basic Response Generation for Threat Intelligence
Generates autonomous responses for common threat patterns
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

from .logger import threat_intel_logger, ThreatIntelLogLevel, ThreatIntelOperation


class ResponseType(str, Enum):
    """Types of automated responses"""
    ALERT_ESCALATION = "ALERT_ESCALATION" 
    IOC_BLOCKING = "IOC_BLOCKING"
    THREAT_HUNTING = "THREAT_HUNTING"
    INTELLIGENCE_SHARING = "INTELLIGENCE_SHARING"
    MITIGATION_RECOMMENDATION = "MITIGATION_RECOMMENDATION"
    USER_NOTIFICATION = "USER_NOTIFICATION"


class ThreatSeverity(str, Enum):
    """Threat severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatPattern:
    """Represents a recognized threat pattern"""
    pattern_id: str
    name: str
    indicators: List[str]
    severity: ThreatSeverity
    confidence: int
    mitre_techniques: List[str]
    recommended_actions: List[str]


@dataclass
class AutomatedResponse:
    """Represents an automated response action"""
    response_id: str
    response_type: ResponseType
    threat_pattern: ThreatPattern
    action: str
    priority: int
    generated_at: str
    requires_approval: bool = True
    executed: bool = False
    execution_result: Optional[Dict[str, Any]] = None


class ThreatResponseGenerator:
    """
    Generates automated responses for recognized threat patterns
    """
    
    def __init__(self):
        self.known_patterns = self._initialize_threat_patterns()
        
    def _initialize_threat_patterns(self) -> List[ThreatPattern]:
        """Initialize known threat patterns for response generation"""
        return [
            ThreatPattern(
                pattern_id="PHISHING_CREDENTIAL_THEFT",
                name="Credential Theft Phishing",
                indicators=["credential_theft", "spearphishing", "login_page"],
                severity=ThreatSeverity.HIGH,
                confidence=85,
                mitre_techniques=["T1566.002", "T1598.003"],
                recommended_actions=[
                    "Block suspicious URLs",
                    "Alert security team",
                    "Warn potentially targeted users",
                    "Enable enhanced monitoring"
                ]
            ),
            ThreatPattern(
                pattern_id="MALWARE_DELIVERY",
                name="Malware Delivery Campaign",
                indicators=["malware_attachment", "suspicious_executable", "dropper"],
                severity=ThreatSeverity.CRITICAL,
                confidence=90,
                mitre_techniques=["T1566.001", "T1204.001", "T1204.002"],
                recommended_actions=[
                    "Quarantine email attachments",
                    "Block file hashes",
                    "Scan endpoints for compromise",
                    "Update endpoint protection signatures"
                ]
            ),
            ThreatPattern(
                pattern_id="BUSINESS_EMAIL_COMPROMISE",
                name="Business Email Compromise",
                indicators=["wire_transfer", "ceo_impersonation", "urgent_payment"],
                severity=ThreatSeverity.CRITICAL,
                confidence=88,
                mitre_techniques=["T1566.003", "T1534", "T1565.001"],
                recommended_actions=[
                    "Freeze financial transactions",
                    "Verify sender identity through alternate channel",
                    "Alert finance team",
                    "Review recent email communications"
                ]
            ),
            ThreatPattern(
                pattern_id="RECONNAISSANCE_ATTEMPT",
                name="Reconnaissance Activity",
                indicators=["information_gathering", "social_engineering", "company_research"],
                severity=ThreatSeverity.MEDIUM,
                confidence=70,
                mitre_techniques=["T1598.003", "T1589", "T1590"],
                recommended_actions=[
                    "Monitor for follow-up attacks",
                    "Review public information exposure",
                    "Alert staff to social engineering risks",
                    "Enhance email filtering rules"
                ]
            ),
            ThreatPattern(
                pattern_id="APT_INDICATORS",
                name="Advanced Persistent Threat",
                indicators=["apt_techniques", "living_off_land", "lateral_movement"],
                severity=ThreatSeverity.CRITICAL,
                confidence=95,
                mitre_techniques=["T1566.001", "T1055", "T1027", "T1083"],
                recommended_actions=[
                    "Initiate incident response protocol",
                    "Isolate potentially affected systems",
                    "Deploy advanced monitoring",
                    "Engage external threat hunting team"
                ]
            )
        ]
    
    async def analyze_threat_intelligence(self, analysis_result: Dict[str, Any], 
                                       threat_intel_findings: List[Dict[str, Any]],
                                       request_id: str) -> List[AutomatedResponse]:
        """
        Analyze threat intelligence and generate appropriate automated responses
        
        Args:
            analysis_result: Email analysis result
            threat_intel_findings: Threat intelligence findings
            request_id: Request ID for tracking
            
        Returns:
            List of automated response recommendations
        """
        start_time = datetime.now(timezone.utc)
        responses = []
        
        try:
            # Extract key indicators from analysis
            indicators = self._extract_indicators(analysis_result, threat_intel_findings)
            
            # Match against known threat patterns
            matched_patterns = self._match_threat_patterns(indicators)
            
            # Generate responses for matched patterns
            for pattern, confidence in matched_patterns:
                response = await self._generate_response(pattern, confidence, indicators, request_id)
                if response:
                    responses.append(response)
                    
            # Log response generation
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.INFO,
                operation=ThreatIntelOperation.RESPONSE_GENERATION,
                message=f"Generated {len(responses)} automated responses for {len(matched_patterns)} threat patterns",
                iocs_processed=len(threat_intel_findings),
                processing_time=processing_time,
                request_id=request_id,
                details={
                    "matched_patterns": [p.pattern_id for p, _ in matched_patterns],
                    "response_types": [r.response_type.value for r in responses],
                    "indicators": indicators
                }
            )
                
            return responses
            
        except Exception as e:
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.ERROR,
                operation=ThreatIntelOperation.RESPONSE_GENERATION,
                message=f"Failed to generate automated responses: {str(e)}",
                request_id=request_id,
                details={"error": str(e)}
            )
            return []
    
    def _extract_indicators(self, analysis_result: Dict[str, Any], 
                          threat_intel_findings: List[Dict[str, Any]]) -> List[str]:
        """Extract threat indicators from analysis results"""
        indicators = []
        
        # From analysis result
        if 'intent' in analysis_result:
            intent_type = analysis_result['intent'].get('primary', '').lower()
            indicators.append(intent_type)
            
        if 'risk_score' in analysis_result:
            risk_score = analysis_result['risk_score'].get('score', 0)
            if risk_score >= 8:
                indicators.append("high_risk")
            elif risk_score >= 6:
                indicators.append("medium_risk")
                
        if 'mitre_attack' in analysis_result:
            techniques = analysis_result['mitre_attack'].get('techniques', [])
            for technique in techniques:
                indicators.append(f"mitre_{technique.lower()}")
                
        # From threat intelligence findings
        for finding in threat_intel_findings:
            threat_level = finding.get('threat_level', '').lower()
            if threat_level in ['high', 'critical']:
                indicators.append(f"threat_intel_{threat_level}")
                
            confidence = finding.get('confidence_score', 0)
            if confidence >= 80:
                indicators.append("high_confidence_threat")
                
        return list(set(indicators))  # Remove duplicates
    
    def _match_threat_patterns(self, indicators: List[str]) -> List[Tuple[ThreatPattern, int]]:
        """Match indicators against known threat patterns"""
        matches = []
        
        for pattern in self.known_patterns:
            # Calculate match score based on overlapping indicators
            pattern_indicators = [indicator.lower() for indicator in pattern.indicators]
            matching_indicators = set(indicators) & set(pattern_indicators)
            
            if matching_indicators:
                # Calculate confidence score
                match_ratio = len(matching_indicators) / len(pattern_indicators)
                confidence = int(pattern.confidence * match_ratio)
                
                # Only include if confidence is above threshold
                if confidence >= 50:
                    matches.append((pattern, confidence))
                    
        # Sort by confidence descending
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches
    
    async def _generate_response(self, pattern: ThreatPattern, confidence: int,
                               indicators: List[str], request_id: str) -> Optional[AutomatedResponse]:
        """Generate automated response for a matched pattern"""
        
        # Determine response type based on pattern severity
        response_type = self._determine_response_type(pattern)
        
        # Generate response ID
        response_id = f"{pattern.pattern_id}_{request_id}_{int(datetime.now().timestamp())}"
        
        # Create response action based on pattern
        action = self._create_response_action(pattern, confidence, indicators)
        
        # Determine priority (1-5, with 1 being highest)
        priority = self._calculate_priority(pattern, confidence)
        
        # High severity patterns might need immediate execution
        requires_approval = pattern.severity != ThreatSeverity.CRITICAL or confidence < 90
        
        response = AutomatedResponse(
            response_id=response_id,
            response_type=response_type,
            threat_pattern=pattern,
            action=action,
            priority=priority,
            generated_at=datetime.now(timezone.utc).isoformat(),
            requires_approval=requires_approval
        )
        
        return response
    
    def _determine_response_type(self, pattern: ThreatPattern) -> ResponseType:
        """Determine appropriate response type for threat pattern"""
        if pattern.severity == ThreatSeverity.CRITICAL:
            if "malware" in pattern.name.lower():
                return ResponseType.IOC_BLOCKING
            elif "business" in pattern.name.lower():
                return ResponseType.ALERT_ESCALATION
            else:
                return ResponseType.MITIGATION_RECOMMENDATION
        elif pattern.severity == ThreatSeverity.HIGH:
            return ResponseType.THREAT_HUNTING
        else:
            return ResponseType.USER_NOTIFICATION
            
    def _create_response_action(self, pattern: ThreatPattern, confidence: int, 
                             indicators: List[str]) -> str:
        """Create detailed response action description"""
        action_parts = [
            f"Threat Pattern Detected: {pattern.name}",
            f"Confidence: {confidence}%",
            f"Severity: {pattern.severity.value}",
            "",
            "Recommended Actions:"
        ]
        
        for i, action in enumerate(pattern.recommended_actions, 1):
            action_parts.append(f"{i}. {action}")
            
        if pattern.mitre_techniques:
            action_parts.extend([
                "",
                "MITRE ATT&CK Techniques:",
                ", ".join(pattern.mitre_techniques)
            ])
            
        return "\n".join(action_parts)
    
    def _calculate_priority(self, pattern: ThreatPattern, confidence: int) -> int:
        """Calculate response priority (1-5, with 1 being highest)"""
        base_priority = {
            ThreatSeverity.CRITICAL: 1,
            ThreatSeverity.HIGH: 2, 
            ThreatSeverity.MEDIUM: 3,
            ThreatSeverity.LOW: 4
        }.get(pattern.severity, 5)
        
        # Adjust based on confidence
        if confidence >= 90:
            priority_adjustment = 0
        elif confidence >= 80:
            priority_adjustment = 1
        else:
            priority_adjustment = 2
            
        return min(base_priority + priority_adjustment, 5)
    
    async def execute_response(self, response: AutomatedResponse) -> Dict[str, Any]:
        """
        Execute an automated response (placeholder for actual implementation)
        
        Args:
            response: Automated response to execute
            
        Returns:
            Execution result
        """
        start_time = datetime.now(timezone.utc)
        
        try:
            # This would contain actual response execution logic
            # For now, this is a simulation
            
            execution_result = {
                "status": "simulated",
                "response_id": response.response_id,
                "response_type": response.response_type.value,
                "threat_pattern": response.threat_pattern.name,
                "executed_at": datetime.now(timezone.utc).isoformat(),
                "actions_taken": [
                    "Logged threat detection",
                    "Generated security alert", 
                    "Notified security team",
                    "Updated threat intelligence database"
                ]
            }
            
            # Log execution
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.INFO,
                operation=ThreatIntelOperation.RESPONSE_GENERATION,
                message=f"Executed automated response for {response.threat_pattern.name}",
                processing_time=processing_time,
                details=execution_result
            )
            
            # Update response status
            response.executed = True
            response.execution_result = execution_result
            
            return execution_result
            
        except Exception as e:
            error_result = {
                "status": "failed",
                "error": str(e),
                "response_id": response.response_id
            }
            
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.ERROR,
                operation=ThreatIntelOperation.RESPONSE_GENERATION,
                message=f"Failed to execute automated response: {str(e)}",
                details=error_result
            )
            
            return error_result