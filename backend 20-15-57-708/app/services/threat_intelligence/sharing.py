"""
Threat Intelligence Sharing Service
Handles sharing of threat intelligence with external systems and internal components
"""

import asyncio
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum

from .logger import threat_intel_logger, ThreatIntelLogLevel, ThreatIntelOperation


class SharingProtocol(str, Enum):
    """Threat intelligence sharing protocols"""
    STIX_TAXII = "STIX_TAXII"
    MISP = "MISP" 
    INTERNAL_API = "INTERNAL_API"
    EMAIL_ALERT = "EMAIL_ALERT"
    SIEM_INTEGRATION = "SIEM_INTEGRATION"
    WEBHOOK = "WEBHOOK"


class SharingLevel(str, Enum):
    """Data sharing classification levels"""
    PUBLIC = "PUBLIC"
    COMMUNITY = "COMMUNITY" 
    ORGANIZATION = "ORGANIZATION"
    RESTRICTED = "RESTRICTED"
    CONFIDENTIAL = "CONFIDENTIAL"


@dataclass
class SharingTarget:
    """Represents a threat intelligence sharing target"""
    target_id: str
    name: str
    protocol: SharingProtocol
    endpoint: str
    sharing_level: SharingLevel
    enabled: bool = True
    authentication: Optional[Dict[str, str]] = None
    filters: Optional[Dict[str, Any]] = None


@dataclass
class ThreatIntelPackage:
    """Standardized threat intelligence package for sharing"""
    package_id: str
    generated_at: str
    source: str
    sharing_level: SharingLevel
    iocs: List[Dict[str, Any]]
    threat_actors: List[str]
    techniques: List[str]
    confidence_score: int
    threat_level: str
    context: str
    metadata: Optional[Dict[str, Any]] = None


class ThreatIntelligenceSharing:
    """
    Service for sharing threat intelligence with internal and external systems
    """
    
    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self.sharing_targets = self._initialize_sharing_targets()
        self.shared_packages = {}  # Cache of recently shared packages
        
    def _initialize_sharing_targets(self) -> List[SharingTarget]:
        """Initialize default sharing targets"""
        return [
            SharingTarget(
                target_id="internal_siem",
                name="Internal SIEM System",
                protocol=SharingProtocol.SIEM_INTEGRATION,
                endpoint="/api/siem/threat-intel",
                sharing_level=SharingLevel.ORGANIZATION,
                filters={"min_confidence": 70}
            ),
            SharingTarget(
                target_id="security_team_alerts",
                name="Security Team Email Alerts",
                protocol=SharingProtocol.EMAIL_ALERT,
                endpoint="security-team@company.com",
                sharing_level=SharingLevel.ORGANIZATION,
                filters={"threat_level": ["HIGH", "CRITICAL"]}
            ),
            SharingTarget(
                target_id="correlation_engine",
                name="Alert Correlation Engine",
                protocol=SharingProtocol.INTERNAL_API,
                endpoint="/api/correlation/threat-intel",
                sharing_level=SharingLevel.ORGANIZATION,
                filters={"min_confidence": 60}
            ),
            SharingTarget(
                target_id="threat_hunting_team",
                name="Threat Hunting Team Webhook",
                protocol=SharingProtocol.WEBHOOK,
                endpoint="https://internal-webhook.company.com/threat-intel",
                sharing_level=SharingLevel.ORGANIZATION,
                filters={"threat_level": ["HIGH", "CRITICAL"], "min_ioc_count": 3}
            )
        ]
    
    async def share_threat_intelligence(self, 
                                     iocs: List[Dict[str, Any]],
                                     analysis_context: Dict[str, Any],
                                     threat_level: str,
                                     confidence_score: int,
                                     source: str = "AI_Agent_Framework",
                                     request_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Share threat intelligence with configured targets
        
        Args:
            iocs: List of IOCs to share
            analysis_context: Context from email analysis
            threat_level: Assessed threat level
            confidence_score: Overall confidence score
            source: Source of the intelligence
            request_id: Request ID for tracking
            
        Returns:
            Sharing results summary
        """
        start_time = datetime.now(timezone.utc)
        sharing_results = {
            "packages_generated": 0,
            "targets_notified": 0,
            "sharing_errors": [],
            "shared_with": []
        }
        
        try:
            # Create standardized threat intelligence package
            package = await self._create_threat_package(
                iocs, analysis_context, threat_level, confidence_score, source
            )
            
            sharing_results["packages_generated"] = 1
            
            # Share with each eligible target
            for target in self.sharing_targets:
                if not target.enabled:
                    continue
                    
                # Check if package meets target's sharing criteria
                if self._meets_sharing_criteria(package, target):
                    result = await self._share_with_target(package, target, request_id)
                    
                    if result.get("success"):
                        sharing_results["targets_notified"] += 1
                        sharing_results["shared_with"].append(target.name)
                    else:
                        sharing_results["sharing_errors"].append({
                            "target": target.name,
                            "error": result.get("error", "Unknown error")
                        })
                        
            # Cache the shared package
            self.shared_packages[package.package_id] = package
            
            # Log sharing operation
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.INFO,
                operation=ThreatIntelOperation.SHARING,
                message=f"Shared threat intelligence with {sharing_results['targets_notified']}/{len(self.sharing_targets)} targets",
                source=source,
                iocs_processed=len(iocs),
                confidence_score=confidence_score,
                threat_level=threat_level,
                processing_time=processing_time,
                request_id=request_id,
                details=sharing_results
            )
            
            return sharing_results
            
        except Exception as e:
            threat_intel_logger.log(
                level=ThreatIntelLogLevel.ERROR,
                operation=ThreatIntelOperation.SHARING,
                message=f"Failed to share threat intelligence: {str(e)}",
                source=source,
                request_id=request_id,
                details={"error": str(e)}
            )
            
            sharing_results["sharing_errors"].append({
                "target": "all",
                "error": str(e)
            })
            
            return sharing_results
    
    async def _create_threat_package(self,
                                   iocs: List[Dict[str, Any]],
                                   analysis_context: Dict[str, Any],
                                   threat_level: str,
                                   confidence_score: int,
                                   source: str) -> ThreatIntelPackage:
        """Create standardized threat intelligence package"""
        
        # Generate unique package ID
        package_content = f"{source}_{threat_level}_{confidence_score}_{len(iocs)}_{datetime.now().isoformat()}"
        package_id = hashlib.sha256(package_content.encode()).hexdigest()[:16]
        
        # Extract threat actors and techniques from analysis context
        threat_actors = []
        techniques = []
        
        if 'mitre_attack' in analysis_context:
            techniques = analysis_context['mitre_attack'].get('techniques', [])
            
        if 'threat_intelligence' in analysis_context:
            for finding in analysis_context.get('threat_intelligence_findings', []):
                if 'threat_actor' in finding:
                    threat_actors.append(finding['threat_actor'])
        
        # Determine sharing level based on threat level and confidence
        if threat_level in ['CRITICAL'] and confidence_score >= 90:
            sharing_level = SharingLevel.COMMUNITY
        elif threat_level in ['HIGH', 'CRITICAL']:
            sharing_level = SharingLevel.ORGANIZATION
        else:
            sharing_level = SharingLevel.RESTRICTED
            
        # Generate context summary
        context_parts = [
            f"Threat intelligence derived from email analysis",
            f"Risk Score: {analysis_context.get('risk_score', {}).get('score', 'Unknown')}/10",
            f"Intent: {analysis_context.get('intent', {}).get('primary', 'Unknown')}"
        ]
        
        if analysis_context.get('deception_indicators'):
            context_parts.append(f"Deception indicators: {len(analysis_context['deception_indicators'])}")
            
        context = " | ".join(context_parts)
        
        package = ThreatIntelPackage(
            package_id=package_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            source=source,
            sharing_level=sharing_level,
            iocs=iocs,
            threat_actors=list(set(threat_actors)),  # Remove duplicates
            techniques=list(set(techniques)),  # Remove duplicates
            confidence_score=confidence_score,
            threat_level=threat_level,
            context=context,
            metadata={
                "analysis_timestamp": analysis_context.get('timestamp'),
                "processing_time": analysis_context.get('processing_time'),
                "ioc_count": len(iocs),
                "has_threat_intelligence": any(ioc.get('has_threat_intelligence') for ioc in iocs)
            }
        )
        
        return package
    
    def _meets_sharing_criteria(self, package: ThreatIntelPackage, target: SharingTarget) -> bool:
        """Check if package meets target's sharing criteria"""
        
        # Check sharing level compatibility
        level_hierarchy = {
            SharingLevel.CONFIDENTIAL: 0,
            SharingLevel.RESTRICTED: 1,
            SharingLevel.ORGANIZATION: 2,
            SharingLevel.COMMUNITY: 3,
            SharingLevel.PUBLIC: 4
        }
        
        if level_hierarchy.get(package.sharing_level, 0) < level_hierarchy.get(target.sharing_level, 0):
            return False
        
        # Check target-specific filters
        if target.filters:
            filters = target.filters
            
            # Minimum confidence filter
            if 'min_confidence' in filters:
                if package.confidence_score < filters['min_confidence']:
                    return False
                    
            # Threat level filter
            if 'threat_level' in filters:
                allowed_levels = filters['threat_level']
                if isinstance(allowed_levels, list) and package.threat_level not in allowed_levels:
                    return False
                elif isinstance(allowed_levels, str) and package.threat_level != allowed_levels:
                    return False
                    
            # Minimum IOC count filter
            if 'min_ioc_count' in filters:
                if len(package.iocs) < filters['min_ioc_count']:
                    return False
                    
            # Technique filter
            if 'required_techniques' in filters:
                required_techniques = set(filters['required_techniques'])
                package_techniques = set(package.techniques)
                if not required_techniques.intersection(package_techniques):
                    return False
        
        return True
    
    async def _share_with_target(self, 
                               package: ThreatIntelPackage,
                               target: SharingTarget,
                               request_id: Optional[str] = None) -> Dict[str, Any]:
        """Share package with specific target"""
        
        try:
            if target.protocol == SharingProtocol.SIEM_INTEGRATION:
                return await self._share_with_siem(package, target)
                
            elif target.protocol == SharingProtocol.EMAIL_ALERT:
                return await self._share_via_email(package, target)
                
            elif target.protocol == SharingProtocol.INTERNAL_API:
                return await self._share_via_internal_api(package, target)
                
            elif target.protocol == SharingProtocol.WEBHOOK:
                return await self._share_via_webhook(package, target)
                
            else:
                return {
                    "success": False,
                    "error": f"Unsupported sharing protocol: {target.protocol.value}"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _share_with_siem(self, package: ThreatIntelPackage, target: SharingTarget) -> Dict[str, Any]:
        """Share with SIEM system (simulated)"""
        # This would contain actual SIEM integration logic
        await asyncio.sleep(0.1)  # Simulate API call
        
        return {
            "success": True,
            "target": target.name,
            "protocol": target.protocol.value,
            "iocs_shared": len(package.iocs),
            "package_id": package.package_id,
            "shared_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def _share_via_email(self, package: ThreatIntelPackage, target: SharingTarget) -> Dict[str, Any]:
        """Share via email alert (simulated)"""
        # This would contain actual email sending logic
        await asyncio.sleep(0.1)  # Simulate email sending
        
        email_content = self._format_email_alert(package)
        
        return {
            "success": True,
            "target": target.name,
            "protocol": target.protocol.value,
            "email_recipient": target.endpoint,
            "subject": f"Threat Intelligence Alert - {package.threat_level}",
            "content_length": len(email_content),
            "package_id": package.package_id,
            "shared_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def _share_via_internal_api(self, package: ThreatIntelPackage, target: SharingTarget) -> Dict[str, Any]:
        """Share via internal API (simulated)"""
        # This would contain actual internal API call logic
        await asyncio.sleep(0.1)  # Simulate API call
        
        return {
            "success": True,
            "target": target.name,
            "protocol": target.protocol.value,
            "endpoint": target.endpoint,
            "package_id": package.package_id,
            "payload_size": len(json.dumps(asdict(package))),
            "shared_at": datetime.now(timezone.utc).isoformat()
        }
    
    async def _share_via_webhook(self, package: ThreatIntelPackage, target: SharingTarget) -> Dict[str, Any]:
        """Share via webhook (simulated)"""
        # This would contain actual webhook call logic
        await asyncio.sleep(0.1)  # Simulate webhook call
        
        return {
            "success": True,
            "target": target.name,
            "protocol": target.protocol.value,
            "webhook_url": target.endpoint,
            "package_id": package.package_id,
            "shared_at": datetime.now(timezone.utc).isoformat()
        }
    
    def _format_email_alert(self, package: ThreatIntelPackage) -> str:
        """Format threat intelligence package for email alert"""
        
        email_parts = [
            f"THREAT INTELLIGENCE ALERT",
            f"Generated: {package.generated_at}",
            f"Package ID: {package.package_id}",
            "",
            f"THREAT SUMMARY:",
            f"Level: {package.threat_level}",
            f"Confidence: {package.confidence_score}%",
            f"Source: {package.source}",
            "",
            f"INDICATORS OF COMPROMISE ({len(package.iocs)}):"
        ]
        
        for i, ioc in enumerate(package.iocs[:10], 1):  # Limit to first 10 IOCs
            ioc_type = ioc.get('type', 'unknown').upper()
            ioc_value = ioc.get('value', 'unknown')
            email_parts.append(f"{i}. {ioc_type}: {ioc_value}")
            
        if len(package.iocs) > 10:
            email_parts.append(f"... and {len(package.iocs) - 10} more IOCs")
            
        if package.techniques:
            email_parts.extend([
                "",
                f"MITRE ATT&CK TECHNIQUES:",
                ", ".join(package.techniques)
            ])
            
        if package.threat_actors:
            email_parts.extend([
                "",
                f"THREAT ACTORS:",
                ", ".join(package.threat_actors)
            ])
            
        email_parts.extend([
            "",
            f"CONTEXT:",
            package.context
        ])
        
        return "\n".join(email_parts)
    
    def get_sharing_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat intelligence sharing statistics"""
        return {
            "period_hours": hours,
            "packages_shared": len(self.shared_packages),
            "active_targets": len([t for t in self.sharing_targets if t.enabled]),
            "total_targets": len(self.sharing_targets),
            "sharing_protocols": list(set(t.protocol.value for t in self.sharing_targets)),
            "recent_packages": [
                {
                    "package_id": pkg.package_id,
                    "generated_at": pkg.generated_at,
                    "threat_level": pkg.threat_level,
                    "confidence_score": pkg.confidence_score,
                    "ioc_count": len(pkg.iocs)
                }
                for pkg in list(self.shared_packages.values())[-10:]  # Last 10 packages
            ]
        }