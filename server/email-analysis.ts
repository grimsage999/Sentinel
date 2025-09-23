// Email Phishing Analysis Service
// Integrates with Python backend for advanced email analysis

import { spawn } from "child_process";
import { randomUUID } from "crypto";
import path from "path";

export interface EmailAnalysisRequest {
  emailContent: string;
  headers?: Record<string, string>;
}

export interface EmailAnalysisResult {
  id: string;
  timestamp: string;
  email_content: string;
  analysis: {
    intent: {
      primary_intent: string;
      confidence: number;
      secondary_intents: Array<{
        intent: string;
        confidence: number;
      }>;
      reasoning: string;
    };
    risk_score: {
      overall_score: number;
      risk_level: string;
      factors: Array<{
        factor: string;
        impact: number;
        description: string;
      }>;
    };
    deception_indicators: Array<{
      type: string;
      severity: string;
      description: string;
      evidence: string;
    }>;
    mitre_attack: {
      techniques: Array<{
        id: string;
        name: string;
        confidence: number;
        description: string;
      }>;
      tactics: Array<{
        id: string;
        name: string;
        description: string;
      }>;
    };
    iocs: {
      urls: string[];
      domains: string[];
      ips: string[];
      emails: string[];
      hashes: string[];
    };
  };
}

class EmailAnalysisService {
  private pythonBackendUrl = process.env.PYTHON_BACKEND_URL || "http://localhost:8000";
  
  async analyzeEmail(request: EmailAnalysisRequest): Promise<EmailAnalysisResult> {
    try {
      // Call the Python backend for analysis
      const response = await fetch(`${this.pythonBackendUrl}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email_content: request.emailContent,
          headers: request.headers || {}
        })
      });

      if (!response.ok) {
        throw new Error(`Python backend error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      
      return {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        email_content: request.emailContent,
        analysis: result.analysis
      };
    } catch (error) {
      console.error("Email analysis failed:", error);
      
      // Return a fallback analysis
      return this.getFallbackAnalysis(request.emailContent);
    }
  }

  private getFallbackAnalysis(emailContent: string): EmailAnalysisResult {
    // Simple fallback analysis when Python backend is unavailable
    const hasPhishingKeywords = /urgent|verify|suspend|click here|update.*account/i.test(emailContent);
    const hasUrls = /https?:\/\/[^\s]+/g.test(emailContent);
    
    return {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      email_content: emailContent,
      analysis: {
        intent: {
          primary_intent: hasPhishingKeywords ? "phishing" : "benign",
          confidence: hasPhishingKeywords ? 0.8 : 0.6,
          secondary_intents: [],
          reasoning: "Fallback analysis - Python backend unavailable"
        },
        risk_score: {
          overall_score: hasPhishingKeywords ? 75 : 25,
          risk_level: hasPhishingKeywords ? "High" : "Low",
          factors: [
            {
              factor: "Keyword Analysis",
              impact: hasPhishingKeywords ? 50 : -25,
              description: hasPhishingKeywords ? "Contains suspicious keywords" : "No suspicious keywords detected"
            }
          ]
        },
        deception_indicators: hasPhishingKeywords ? [
          {
            type: "social_engineering",
            severity: "medium",
            description: "Contains urgency keywords",
            evidence: "Detected urgency-based language"
          }
        ] : [],
        mitre_attack: {
          techniques: hasPhishingKeywords ? [
            {
              id: "T1566.001",
              name: "Spearphishing Attachment",
              confidence: 0.6,
              description: "Potential phishing attempt detected"
            }
          ] : [],
          tactics: hasPhishingKeywords ? [
            {
              id: "TA0001",
              name: "Initial Access",
              description: "Techniques used to gain initial access"
            }
          ] : []
        },
        iocs: {
          urls: hasUrls ? emailContent.match(/https?:\/\/[^\s]+/g) || [] : [],
          domains: [],
          ips: [],
          emails: [],
          hashes: []
        }
      }
    };
  }
}

export const emailAnalysisService = new EmailAnalysisService();
