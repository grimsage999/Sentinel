// Email Phishing Analysis Service
// Integrates with Python backend for advanced email analysis

import { spawn } from "child_process";
import { randomUUID } from "crypto";
import path from "path";
import { mitreAttackService, type EnrichedMitreTechnique } from "./mitre-attack";

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
  private pythonProcess: any = null;
  private isStarting = false;
  private isReady = false;
  
  constructor() {
    this.checkPythonBackend().catch(console.error);
  }

  private async checkPythonBackend() {
    try {
      // Check if Python backend is already running
      const response = await fetch(`${this.pythonBackendUrl}/api/health`);
      if (response.ok) {
        console.log("✅ Python email analysis backend is already running");
        this.isReady = true;
        return;
      }
    } catch (error) {
      // Python backend not running, try to start it
      console.log("🐍 Python backend not found, starting...");
      this.startPythonBackend();
    }
  }

  private async startPythonBackend() {
    if (this.isStarting || this.pythonProcess) return;
    this.isStarting = true;

    try {
      const pythonBackendPath = path.join(process.cwd(), "backend 20-15-57-708");
      
      console.log("🐍 Starting integrated Python email analysis backend...");
      
      // Start Python backend as a child process
      this.pythonProcess = spawn("bash", ["-c", `cd "${pythonBackendPath}" && source venv/bin/activate && uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level warning`], {
        stdio: ["ignore", "pipe", "pipe"],
        detached: false
      });

      this.pythonProcess.stdout.on("data", (data: Buffer) => {
        const output = data.toString().trim();
        if (output.includes("Uvicorn running")) {
          this.isReady = true;
          console.log("✅ Python email analysis backend is ready");
        }
      });

      this.pythonProcess.stderr.on("data", (data: Buffer) => {
        const error = data.toString().trim();
        if (!error.includes("WARNING")) {
          console.log(`[Python Backend] ${error}`);
        }
      });

      this.pythonProcess.on("exit", (code: number) => {
        console.log(`Python backend exited with code ${code}`);
        this.pythonProcess = null;
        this.isReady = false;
        this.isStarting = false;
      });

      // Wait for Python backend to start
      await new Promise(resolve => {
        const checkReady = () => {
          if (this.isReady) {
            resolve(true);
          } else {
            setTimeout(checkReady, 500);
          }
        };
        checkReady();
      });
      
    } catch (error) {
      console.log("❌ Failed to start Python backend:", error.message);
      this.isStarting = false;
    }
  }
  
  async analyzeEmail(request: EmailAnalysisRequest): Promise<EmailAnalysisResult> {
    // Ensure Python backend is ready
    if (!this.isReady) {
      await this.checkPythonBackend();
      if (!this.isReady) {
        throw new Error("Python backend is not available");
      }
    }

    try {
      console.log(`🔍 Analyzing email via Python backend: ${this.pythonBackendUrl}/api/analyze`);
      
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
        const errorText = await response.text();
        throw new Error(`Python backend error: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const result = await response.json();
      console.log(`✅ Python backend analysis completed for email`);
      
      // Handle the Python backend response structure
      if (result.success && result.data) {
        const pythonData = result.data;
        return {
          id: randomUUID(),
          timestamp: new Date().toISOString(),
          email_content: request.emailContent,
          analysis: {
            intent: {
              primary_intent: pythonData.intent?.primary || "unknown",
              confidence: pythonData.intent?.confidence === "Medium" ? 0.7 : pythonData.intent?.confidence === "High" ? 0.9 : 0.5,
              secondary_intents: pythonData.intent?.alternatives || [],
              reasoning: pythonData.riskScore?.reasoning || "Analysis completed by Python backend"
            },
            risk_score: {
              overall_score: pythonData.riskScore?.score || 0,
              risk_level: pythonData.riskScore?.score >= 8 ? "High" : pythonData.riskScore?.score >= 5 ? "Medium" : "Low",
              factors: pythonData.deceptionIndicators?.map((indicator: any) => ({
                factor: indicator.type,
                impact: indicator.severity === "High" ? 30 : indicator.severity === "Medium" ? 20 : 10,
                description: indicator.description
              })) || []
            },
            deception_indicators: pythonData.deceptionIndicators?.map((indicator: any) => ({
              type: indicator.type,
              severity: indicator.severity?.toLowerCase() || "medium",
              description: indicator.description,
              evidence: indicator.evidence
            })) || [],
            mitre_attack: await this.enrichMitreData(pythonData.mitreAttack),
            iocs: {
              urls: pythonData.iocs?.urls?.map((ioc: any) => {
                if (typeof ioc === 'string') {
                  return { value: ioc, vtLink: null };
                }
                return {
                  value: ioc.value || ioc,
                  vtLink: ioc.vtLink || null,
                  type: ioc.type || 'url',
                  context: ioc.context || null
                };
              }) || [],
              domains: pythonData.iocs?.domains?.map((ioc: any) => 
                typeof ioc === 'string' ? ioc : ioc.value || ioc
              ) || [],
              ips: pythonData.iocs?.ips?.map((ioc: any) => 
                typeof ioc === 'string' ? ioc : ioc.value || ioc
              ) || [],
              emails: pythonData.iocs?.emails?.map((ioc: any) => 
                typeof ioc === 'string' ? ioc : ioc.value || ioc
              ) || [],
              hashes: pythonData.iocs?.hashes?.map((ioc: any) => 
                typeof ioc === 'string' ? ioc : ioc.value || ioc
              ) || []
            }
          }
        };
      }
      
      throw new Error("Invalid response structure from Python backend");
    } catch (error) {
      console.error("❌ Email analysis failed:", error);
      throw error; // Re-throw the error instead of using fallback
    }
  }

  /**
   * Enrich MITRE ATT&CK data with official framework information
   */
  private async enrichMitreData(mitreData: any): Promise<any> {
    if (!mitreData || (!mitreData.techniques && !mitreData.tactics)) {
      return {
        techniques: [],
        tactics: []
      };
    }

    try {
      // Enrich techniques with official MITRE data
      const enrichedTechniques = [];
      if (mitreData.techniques && Array.isArray(mitreData.techniques)) {
        for (const techniqueId of mitreData.techniques) {
          const officialTechnique = await mitreAttackService.getTechnique(techniqueId);
          if (officialTechnique) {
            enrichedTechniques.push({
              id: officialTechnique.id,
              name: officialTechnique.name,
              confidence: officialTechnique.confidence,
              description: officialTechnique.description,
              url: officialTechnique.url,
              platforms: officialTechnique.platforms,
              tactics: officialTechnique.tactics,
              data_sources: officialTechnique.data_sources,
              detection: officialTechnique.detection,
              sub_techniques: officialTechnique.sub_techniques
            });
          } else {
            // Fallback for unknown techniques
            enrichedTechniques.push({
              id: techniqueId,
              name: `MITRE ${techniqueId}`,
              confidence: 0.6,
              description: `MITRE ATT&CK technique ${techniqueId}`,
              url: `https://attack.mitre.org/techniques/${techniqueId}`,
              platforms: [],
              tactics: [],
              data_sources: [],
              detection: '',
              sub_techniques: []
            });
          }
        }
      }

      // Enrich tactics with official MITRE data
      const enrichedTactics = [];
      if (mitreData.tactics && Array.isArray(mitreData.tactics)) {
        for (const tacticName of mitreData.tactics) {
          // Try to find tactic by name since Python backend returns tactic names
          const allTactics = await mitreAttackService.getAllTactics();
          const officialTactic = allTactics.find(t => 
            t.shortname.toLowerCase() === tacticName.toLowerCase() ||
            t.name.toLowerCase().includes(tacticName.toLowerCase())
          );

          if (officialTactic) {
            enrichedTactics.push({
              id: officialTactic.id,
              name: officialTactic.name,
              description: officialTactic.description,
              shortname: officialTactic.shortname,
              url: officialTactic.url
            });
          } else {
            // Fallback for unknown tactics
            enrichedTactics.push({
              id: tacticName,
              name: tacticName.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
              description: `MITRE ATT&CK tactic: ${tacticName}`,
              shortname: tacticName,
              url: `https://attack.mitre.org/tactics/${tacticName}`
            });
          }
        }
      }

      return {
        techniques: enrichedTechniques,
        tactics: enrichedTactics
      };

    } catch (error) {
      console.error('❌ Failed to enrich MITRE data:', error);
      // Return basic structure on error
      return {
        techniques: mitreData.techniques?.map((id: string) => ({
          id,
          name: `MITRE ${id}`,
          confidence: 0.6,
          description: `MITRE ATT&CK technique ${id}`
        })) || [],
        tactics: mitreData.tactics?.map((tactic: string) => ({
          id: tactic,
          name: tactic.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
          description: `MITRE ATT&CK tactic: ${tactic}`
        })) || []
      };
    }
  }

  // Cleanup method to properly shut down the Python backend
  cleanup() {
    if (this.pythonProcess) {
      console.log("🛑 Shutting down Python email analysis backend...");
      this.pythonProcess.kill('SIGTERM');
      this.pythonProcess = null;
      this.isReady = false;
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

// Create and export a singleton instance
export const emailAnalysisService = new EmailAnalysisService();
