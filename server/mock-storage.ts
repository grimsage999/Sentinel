import { 
  type Alert, 
  type InsertAlert, 
  type ThreatIntelligence, 
  type InsertThreatIntelligence,
  type IOC,
  type InsertIOC,
  type AuditLog,
  type InsertAuditLog,
  type User,
  type InsertUser,
  type Correlation,
  type InsertCorrelation,
  type Playbook,
  type InsertPlaybook,
  type PlaybookAction,
  type InsertPlaybookAction,
  type PlaybookExecution,
  type InsertPlaybookExecution
} from "@shared/schema";
import { randomUUID } from "crypto";
import type { IStorage } from "./storage";

// Sample data
const sampleAlerts: Alert[] = [
  {
    id: "alert-1",
    type: "Phishing Email Campaign",
    severity: "Critical",
    source: "Email Security Gateway",
    timestamp: new Date(Date.now() - 15 * 60 * 1000), // 15 minutes ago
    status: "New",
    confidence: 98,
    affectedAssets: 1,
    businessImpact: "High",
    assignee: null,
    aiTriaged: true,
    title: "PayPal Credential Harvesting Attempt",
    description: "Sophisticated phishing email impersonating PayPal security team with credential harvesting links and suspicious IOCs detected",
    metadata: {
      emailFrom: "security@paypal-verification.com",
      emailTo: "user@example.com",
      subject: "Urgent: Verify Your Account Now!",
      maliciousUrls: [
        "http://paypal-secure-login.malicious-site.com/verify",
        "https://paypal-verification.suspicious-domain.net"
      ],
      suspiciousIPs: ["203.0.113.45"],
      phishingTechniques: ["Urgency Tactics", "Brand Impersonation", "Account Suspension Threat"],
      mitreAttack: {
        techniques: ["T1566.002", "T1598.003"],
        tactics: ["Initial Access", "Collection"]
      },
      vtAnalysis: {
        maliciousUrls: 2,
        suspiciousScore: 92,
        vtLinks: [
          "https://www.virustotal.com/gui/url-analysis/u-abc123",
          "https://www.virustotal.com/gui/url-analysis/u-def456"
        ]
      },
      riskFactors: [
        "Domain typosquatting detected",
        "Suspicious IP geolocation",
        "No SPF/DKIM authentication",
        "High urgency language patterns"
      ]
    }
  },
  {
    id: "alert-2",
    type: "Phishing Email Campaign", 
    severity: "High",
    source: "Email Security Gateway",
    timestamp: new Date(Date.now() - 32 * 60 * 1000), // 32 minutes ago
    status: "Triaging",
    confidence: 94,
    affectedAssets: 1,
    businessImpact: "High",
    assignee: "security-lead@company.com",
    aiTriaged: true,
    title: "Amazon Account Takeover Attempt",
    description: "Phishing campaign targeting Amazon customers with account verification scam and malicious attachment",
    metadata: {
      emailFrom: "security@amazon-verification.com",
      emailTo: "customer@example.com", 
      subject: "Amazon Security Alert - Verify Your Account",
      maliciousUrls: [
        "http://amazon-secure-verify.fake-domain.com/login",
        "https://aws-security-check.malicious-site.org/verify"
      ],
      suspiciousIPs: ["198.51.100.42"],
      attachments: ["amazon_verification.pdf"],
      phishingTechniques: ["Account Verification", "Security Alert Impersonation", "Fake Attachments"],
      mitreAttack: {
        techniques: ["T1566.001", "T1204.002"],
        tactics: ["Initial Access", "Execution"]
      },
      vtAnalysis: {
        maliciousUrls: 2,
        suspiciousScore: 89,
        vtLinks: [
          "https://www.virustotal.com/gui/url-analysis/u-ghi789",
          "https://www.virustotal.com/gui/url-analysis/u-jkl012"
        ]
      },
      riskFactors: [
        "Malicious PDF attachment",
        "Domain impersonation",
        "Suspicious sender reputation",
        "Social engineering indicators"
      ]
    }
  },
  {
    id: "alert-3",
    type: "Phishing Email Campaign",
    severity: "Critical",
    source: "Email Security Gateway", 
    timestamp: new Date(Date.now() - 8 * 60 * 1000), // 8 minutes ago
    status: "New",
    confidence: 99,
    affectedAssets: 1,
    businessImpact: "High",
    assignee: null,
    aiTriaged: true,
    title: "IRS Tax Refund Scam - High Confidence",
    description: "Government impersonation phishing targeting tax refund processing with sophisticated social engineering",
    metadata: {
      emailFrom: "noreply@irs-refund.com",
      emailTo: "taxpayer@example.com",
      subject: "IRS Tax Refund - Action Required",
      maliciousUrls: [
        "http://irs-refund-portal.suspicious-site.com/claim"
      ],
      phishingTechniques: ["Government Impersonation", "Financial Incentive", "Urgent Action Required"],
      mitreAttack: {
        techniques: ["T1566.002", "T1598.002"],
        tactics: ["Initial Access", "Collection"]
      },
      vtAnalysis: {
        maliciousUrls: 1,
        suspiciousScore: 96,
        vtLinks: [
          "https://www.virustotal.com/gui/url-analysis/u-mno345"
        ]
      },
      riskFactors: [
        "Government agency impersonation",
        "Financial fraud indicators", 
        "Domain not associated with IRS",
        "Suspicious URL structure"
      ],
      emailContent: "You have a pending tax refund of $2,847. Claim your refund: http://irs-refund-portal.suspicious-site.com/claim"
    }
  },
  {
    id: "alert-4",
    type: "Malware Detection",
    severity: "Critical",
    source: "Endpoint Protection",
    timestamp: new Date(Date.now() - 45 * 60 * 1000), // 45 minutes ago
    status: "Investigating",
    confidence: 95,
    affectedAssets: 1,
    businessImpact: "High",
    assignee: "john.doe@company.com",
    aiTriaged: true,
    title: "Ransomware Activity Detected",
    description: "Suspicious encryption activity detected on workstation WS-001",
    metadata: { endpoint: "WS-001", user: "john.doe", process: "encrypt.exe" }
  },
  {
    id: "alert-5", 
    type: "Data Exfiltration",
    severity: "High",
    source: "Network Monitor",
    timestamp: new Date(Date.now() - 67 * 60 * 1000), // 67 minutes ago
    status: "Investigating",
    confidence: 87,
    affectedAssets: 3,
    businessImpact: "Medium",
    assignee: "analyst@company.com",
    aiTriaged: false,
    title: "Unusual Data Transfer Detected",
    description: "Large volume of data transferred to external IP",
    metadata: { bytes: 2500000000, destination: "185.243.115.84" }
  }
];

const sampleAuditEntries: AuditLog[] = [
  {
    id: "audit-1",
    timestamp: new Date("2024-01-15T10:35:00Z"),
    actor: "USER",
    action: "Alert assigned to analyst",
    alertId: "alert-2",
    metadata: { assignee: "analyst@company.com" }
  }
];

export class MockStorage implements IStorage {
  private alerts: Alert[] = [...sampleAlerts];
  private auditLog: AuditLog[] = [...sampleAuditEntries];
  private users: User[] = [];
  private iocs: IOC[] = [];
  private threatIntel: ThreatIntelligence[] = [];
  private correlations: Correlation[] = [];
  private playbooks: Playbook[] = [];
  private playbookActions: PlaybookAction[] = [];
  private playbookExecutions: PlaybookExecution[] = [];

  async getAlerts(): Promise<Alert[]> {
    return [...this.alerts];
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    return this.alerts.find(alert => alert.id === id);
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const newAlert: Alert = {
      id: randomUUID(),
      timestamp: new Date(),
      ...alert
    };
    this.alerts.unshift(newAlert);
    return newAlert;
  }

  async updateAlert(id: string, alert: Partial<Alert>): Promise<Alert | undefined> {
    const index = this.alerts.findIndex(a => a.id === id);
    if (index === -1) return undefined;
    
    this.alerts[index] = { ...this.alerts[index], ...alert };
    return this.alerts[index];
  }

  async deleteAlert(id: string): Promise<boolean> {
    const index = this.alerts.findIndex(a => a.id === id);
    if (index === -1) return false;
    
    this.alerts.splice(index, 1);
    return true;
  }

  async getThreatIntelligence(alertId: string): Promise<ThreatIntelligence | undefined> {
    return this.threatIntel.find(ti => ti.alertId === alertId);
  }

  async createThreatIntelligence(intel: InsertThreatIntelligence): Promise<ThreatIntelligence> {
    const newIntel: ThreatIntelligence = {
      id: randomUUID(),
      createdAt: new Date(),
      ...intel
    };
    this.threatIntel.push(newIntel);
    return newIntel;
  }

  async getIOCs(alertId?: string): Promise<IOC[]> {
    if (alertId) {
      return this.iocs.filter(ioc => ioc.alertId === alertId);
    }
    return [...this.iocs];
  }

  async createIOC(ioc: InsertIOC): Promise<IOC> {
    const newIOC: IOC = {
      id: randomUUID(),
      createdAt: new Date(),
      ...ioc
    };
    this.iocs.push(newIOC);
    return newIOC;
  }

  async enrichIOC(id: string, enrichmentData: any): Promise<IOC | undefined> {
    const index = this.iocs.findIndex(ioc => ioc.id === id);
    if (index === -1) return undefined;
    
    this.iocs[index] = { ...this.iocs[index], enrichmentData };
    return this.iocs[index];
  }

  async getAuditLog(): Promise<AuditLog[]> {
    return [...this.auditLog];
  }

  async createAuditEntry(entry: InsertAuditLog): Promise<AuditLog> {
    const newLog: AuditLog = {
      id: randomUUID(),
      timestamp: new Date(),
      ...entry
    };
    this.auditLog.unshift(newLog);
    return newLog;
  }

  async getUsers(): Promise<User[]> {
    return [...this.users];
  }

  async createUser(user: InsertUser): Promise<User> {
    const newUser: User = {
      id: randomUUID(),
      ...user
    };
    this.users.push(newUser);
    return newUser;
  }

  async getCorrelations(alertId: string): Promise<Correlation[]> {
    return this.correlations.filter(corr => 
      corr.primaryAlertId === alertId || corr.relatedAlertId === alertId
    );
  }

  async createCorrelation(correlation: InsertCorrelation): Promise<Correlation> {
    const newCorrelation: Correlation = {
      id: randomUUID(),
      createdAt: new Date(),
      ...correlation
    };
    this.correlations.push(newCorrelation);
    return newCorrelation;
  }

  async getPlaybooks(): Promise<Playbook[]> {
    return [...this.playbooks];
  }

  async getPlaybook(id: string): Promise<Playbook | undefined> {
    return this.playbooks.find(pb => pb.id === id);
  }

  async createPlaybook(playbook: InsertPlaybook): Promise<Playbook> {
    const newPlaybook: Playbook = {
      id: randomUUID(),
      createdAt: new Date(),
      updatedAt: new Date(),
      ...playbook
    };
    this.playbooks.push(newPlaybook);
    return newPlaybook;
  }

  async getPlaybookActions(playbookId: string): Promise<PlaybookAction[]> {
    return this.playbookActions.filter(action => action.playbookId === playbookId);
  }

  async createPlaybookAction(action: InsertPlaybookAction): Promise<PlaybookAction> {
    const newAction: PlaybookAction = {
      id: randomUUID(),
      createdAt: new Date(),
      ...action
    };
    this.playbookActions.push(newAction);
    return newAction;
  }

  async getPlaybookExecutions(playbookId?: string): Promise<PlaybookExecution[]> {
    if (playbookId) {
      return this.playbookExecutions.filter(exec => exec.playbookId === playbookId);
    }
    return [...this.playbookExecutions];
  }

  async createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution> {
    const newExecution: PlaybookExecution = {
      id: randomUUID(),
      startedAt: new Date(),
      ...execution
    };
    this.playbookExecutions.push(newExecution);
    return newExecution;
  }

  async updatePlaybookExecution(id: string, execution: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined> {
    const index = this.playbookExecutions.findIndex(exec => exec.id === id);
    if (index === -1) return undefined;
    
    this.playbookExecutions[index] = { ...this.playbookExecutions[index], ...execution };
    return this.playbookExecutions[index];
  }

  async initializeSampleData(): Promise<void> {
    // Sample data is already initialized in the constructor
    console.log("Sample data initialized");
  }
}
