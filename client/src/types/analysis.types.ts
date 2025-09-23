/**
 * Core analysis types for Sentinel
 */

export type ConfidenceLevel = 'High' | 'Medium' | 'Low';

export type IntentType = 
  | 'credential_theft'
  | 'wire_transfer'
  | 'malware_delivery'
  | 'reconnaissance'
  | 'other';

export type DeceptionIndicatorType = 
  | 'spoofing'
  | 'urgency'
  | 'authority'
  | 'suspicious_links'
  | 'grammar';

export type IOCType = 'url' | 'ip' | 'domain';

export type SeverityLevel = 'High' | 'Medium' | 'Low';

export interface EmailAnalysisRequest {
  emailContent: string;
  analysisOptions?: {
    includeIOCs: boolean;
    confidenceThreshold: number;
  };
}

export interface DeceptionIndicator {
  type: DeceptionIndicatorType;
  description: string;
  evidence: string;
  severity: SeverityLevel;
}

export interface IOCItem {
  value: string;
  type: IOCType;
  vtLink: string;
  context?: string;
}

export interface MitreAttackTechnique {
  techniqueId: string;
  name: string;
  description: string;
  tactic: string;
  tacticDescription: string;
  context: string;
  mitreUrl: string;
}

export interface MitreAttackRecommendations {
  immediateActions: string[];
  securityControls: string[];
  userTraining: string[];
  monitoring: string[];
}

export interface MitreAttackAnalysis {
  techniques: string[];
  tactics: string[];
  attackNarrative: string;
}

export interface MitreAttackEnhanced {
  techniquesDetailed: MitreAttackTechnique[];
  recommendations: MitreAttackRecommendations;
  attackNarrativeDetailed: string;
  frameworkVersion: string;
  analysisTimestamp: string;
}

export interface AnalysisResult {
  intent: {
    primary: IntentType;
    confidence: ConfidenceLevel;
    alternatives?: IntentType[];
  };
  deceptionIndicators: DeceptionIndicator[];
  riskScore: {
    score: number; // 1-10
    confidence: ConfidenceLevel;
    reasoning: string;
  };
  iocs: {
    urls: IOCItem[];
    ips: IOCItem[];
    domains: IOCItem[];
  };
  mitreAttack?: MitreAttackAnalysis;
  mitreAttackEnhanced?: MitreAttackEnhanced;
  processingTime: number;
  timestamp: string;
}