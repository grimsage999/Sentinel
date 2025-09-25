"""
Analysis models for Sentinel backend
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator


class ConfidenceLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class IntentType(str, Enum):
    CREDENTIAL_THEFT = "credential_theft"
    WIRE_TRANSFER = "wire_transfer"
    MALWARE_DELIVERY = "malware_delivery"
    RECONNAISSANCE = "reconnaissance"
    LEGITIMATE = "legitimate"
    OTHER = "other"


class DeceptionIndicatorType(str, Enum):
    SPOOFING = "spoofing"
    URGENCY = "urgency"
    AUTHORITY = "authority"
    SUSPICIOUS_LINKS = "suspicious_links"
    GRAMMAR = "grammar"


class IOCType(str, Enum):
    URL = "url"
    IP = "ip"
    DOMAIN = "domain"


class SeverityLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class AnalysisOptions(BaseModel):
    include_iocs: bool = Field(default=True, alias="includeIOCs")
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0, alias="confidenceThreshold")


class EmailAnalysisRequest(BaseModel):
    email_content: str = Field(..., min_length=10, max_length=1024*1024, alias="emailContent")
    analysis_options: Optional[AnalysisOptions] = Field(default=None, alias="analysisOptions")

    @validator('email_content')
    def validate_email_content(cls, v):
        if not v.strip():
            raise ValueError("Email content cannot be empty")
        return v.strip()

    class Config:
        populate_by_name = True


class DeceptionIndicator(BaseModel):
    type: DeceptionIndicatorType
    description: str = Field(..., min_length=1, max_length=500)
    evidence: str = Field(..., min_length=1, max_length=1000)
    severity: SeverityLevel


class IOCItem(BaseModel):
    value: str = Field(..., min_length=1, max_length=500)
    type: IOCType
    vt_link: str = Field(..., alias="vtLink")
    context: Optional[str] = Field(default=None, max_length=200)
    # Threat intelligence enhancement fields
    has_threat_intelligence: bool = Field(default=False)
    threat_intelligence: Optional[Dict[str, Any]] = Field(default=None)

    class Config:
        populate_by_name = True


class IntentAnalysis(BaseModel):
    primary: IntentType
    confidence: ConfidenceLevel
    alternatives: Optional[List[IntentType]] = Field(default=None)


class RiskScore(BaseModel):
    score: int = Field(..., ge=1, le=10)
    confidence: ConfidenceLevel
    reasoning: str = Field(..., min_length=1, max_length=1000)


class MitreAttackTechnique(BaseModel):
    technique_id: str = Field(..., alias="techniqueId")
    name: str
    description: str
    tactic: str
    tactic_description: str = Field(..., alias="tacticDescription")
    context: str
    mitre_url: str = Field(..., alias="mitreUrl")

    class Config:
        populate_by_name = True


class MitreAttackRecommendations(BaseModel):
    immediate_actions: List[str] = Field(default_factory=list, alias="immediateActions")
    security_controls: List[str] = Field(default_factory=list, alias="securityControls")
    user_training: List[str] = Field(default_factory=list, alias="userTraining")
    monitoring: List[str] = Field(default_factory=list)

    class Config:
        populate_by_name = True


class MitreAttackAnalysis(BaseModel):
    techniques: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    attack_narrative: str = Field(default="", alias="attackNarrative")

    class Config:
        populate_by_name = True


class MitreAttackEnhanced(BaseModel):
    techniques_detailed: List[MitreAttackTechnique] = Field(default_factory=list, alias="techniquesDetailed")
    recommendations: MitreAttackRecommendations = Field(default_factory=MitreAttackRecommendations)
    attack_narrative_detailed: str = Field(default="", alias="attackNarrativeDetailed")
    framework_version: str = Field(default="MITRE ATT&CK v13.1", alias="frameworkVersion")
    analysis_timestamp: str = Field(default="", alias="analysisTimestamp")

    class Config:
        populate_by_name = True


class IOCCollection(BaseModel):
    urls: List[IOCItem] = Field(default_factory=list)
    ips: List[IOCItem] = Field(default_factory=list)
    domains: List[IOCItem] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    intent: IntentAnalysis
    deception_indicators: List[DeceptionIndicator] = Field(default_factory=list, alias="deceptionIndicators")
    risk_score: RiskScore = Field(..., alias="riskScore")
    iocs: IOCCollection
    mitre_attack: Optional[MitreAttackAnalysis] = Field(default=None, alias="mitreAttack")
    mitre_attack_enhanced: Optional[MitreAttackEnhanced] = Field(default=None, alias="mitreAttackEnhanced")
    processing_time: float = Field(..., ge=0, alias="processingTime")
    timestamp: datetime

    class Config:
        populate_by_name = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }