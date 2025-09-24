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
  type InsertPlaybookExecution,
  alerts,
  threatIntelligence,
  iocs,
  auditLog,
  users,
  correlations,
  playbooks,
  playbookActions,
  playbookExecutions
} from "@shared/schema";
import { randomUUID } from "crypto";
import { db as getDb } from "./db";
import { eq, desc, sql } from "drizzle-orm";

export interface IStorage {
  // Alert operations
  getAlerts(): Promise<Alert[]>;
  getAlert(id: string): Promise<Alert | undefined>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  updateAlert(id: string, alert: Partial<Alert>): Promise<Alert | undefined>;
  deleteAlert(id: string): Promise<boolean>;

  // Threat Intelligence operations
  getThreatIntelligence(alertId: string): Promise<ThreatIntelligence | undefined>;
  createThreatIntelligence(intel: InsertThreatIntelligence): Promise<ThreatIntelligence>;

  // IOC operations
  getIOCs(alertId?: string): Promise<IOC[]>;
  createIOC(ioc: InsertIOC): Promise<IOC>;
  enrichIOC(id: string, enrichmentData: any): Promise<IOC | undefined>;

  // Audit Log operations
  getAuditLog(): Promise<AuditLog[]>;
  createAuditEntry(entry: InsertAuditLog): Promise<AuditLog>;

  // User operations
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;

  // Correlation operations
  getCorrelations(alertId: string): Promise<Correlation[]>;
  createCorrelation(correlation: InsertCorrelation): Promise<Correlation>;

  // Playbook operations
  getPlaybooks(): Promise<Playbook[]>;
  getPlaybook(id: string): Promise<Playbook | undefined>;
  createPlaybook(playbook: InsertPlaybook): Promise<Playbook>;
  updatePlaybook(id: string, playbook: Partial<Playbook>): Promise<Playbook | undefined>;
  deletePlaybook(id: string): Promise<boolean>;

  // Playbook Action operations
  getPlaybookActions(playbookId: string): Promise<PlaybookAction[]>;
  createPlaybookAction(action: InsertPlaybookAction): Promise<PlaybookAction>;
  deletePlaybookAction(id: string): Promise<boolean>;

  // Playbook Execution operations
  getPlaybookExecutions(alertId?: string): Promise<PlaybookExecution[]>;
  createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution>;
  updatePlaybookExecution(id: string, execution: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined>;
}

export class DatabaseStorage implements IStorage {
  async getAlerts(): Promise<Alert[]> {
    return await getDb().select().from(alerts).orderBy(desc(alerts.timestamp));
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    const [alert] = await getDb().select().from(alerts).where(eq(alerts.id, id));
    return alert || undefined;
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    // Use a simple approach to get the next alert ID without full table scan
    const result = await getDb().execute(sql`
      SELECT COALESCE(MAX(CAST(SUBSTRING(id FROM 5) AS INTEGER)), 0) + 1 as next_num 
      FROM alerts 
      WHERE id LIKE 'ALT-%'
    `);
    const nextNum = (result.rows[0] as any)?.next_num || 1;
    const id = `ALT-${String(nextNum).padStart(5, '0')}`;
    
    const [newAlert] = await getDb()
      .insert(alerts)
      .values({ ...alert, id })
      .returning();
    return newAlert;
  }

  async updateAlert(id: string, alert: Partial<Alert>): Promise<Alert | undefined> {
    const [updated] = await getDb()
      .update(alerts)
      .set(alert)
      .where(eq(alerts.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteAlert(id: string): Promise<boolean> {
    const result = await getDb().delete(alerts).where(eq(alerts.id, id));
    return result.rowCount !== null && result.rowCount > 0;
  }

  async getThreatIntelligence(alertId: string): Promise<ThreatIntelligence | undefined> {
    const [intel] = await getDb()
      .select()
      .from(threatIntelligence)
      .where(eq(threatIntelligence.alertId, alertId));
    return intel || undefined;
  }

  async createThreatIntelligence(intel: InsertThreatIntelligence): Promise<ThreatIntelligence> {
    const [newIntel] = await getDb()
      .insert(threatIntelligence)
      .values(intel)
      .returning();
    return newIntel;
  }

  async getIOCs(alertId?: string): Promise<IOC[]> {
    if (alertId) {
      return await getDb().select().from(iocs).where(eq(iocs.alertId, alertId));
    }
    return await getDb().select().from(iocs);
  }

  async createIOC(ioc: InsertIOC): Promise<IOC> {
    const [newIOC] = await getDb().insert(iocs).values(ioc).returning();
    return newIOC;
  }

  async enrichIOC(id: string, enrichmentData: any): Promise<IOC | undefined> {
    const [updated] = await getDb()
      .update(iocs)
      .set({ enrichmentData })
      .where(eq(iocs.id, id))
      .returning();
    return updated || undefined;
  }

  async getAuditLog(): Promise<AuditLog[]> {
    return await getDb().select().from(auditLog).orderBy(desc(auditLog.timestamp));
  }

  async createAuditEntry(entry: InsertAuditLog): Promise<AuditLog> {
    const [newEntry] = await getDb().insert(auditLog).values(entry).returning();
    return newEntry;
  }

  async getUser(id: string): Promise<User | undefined> {
    const [user] = await getDb().select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await getDb().select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async createUser(user: InsertUser): Promise<User> {
    const [newUser] = await getDb().insert(users).values(user).returning();
    return newUser;
  }

  async getCorrelations(alertId: string): Promise<Correlation[]> {
    return await getDb()
      .select()
      .from(correlations)
      .where(eq(correlations.primaryAlertId, alertId))
      .orderBy(desc(correlations.confidence));
  }

  async createCorrelation(correlation: InsertCorrelation): Promise<Correlation> {
    const [newCorrelation] = await getDb().insert(correlations).values(correlation).returning();
    return newCorrelation;
  }

  // Playbook operations
  async getPlaybooks(): Promise<Playbook[]> {
    return await getDb().select().from(playbooks).orderBy(desc(playbooks.createdAt));
  }

  async getPlaybook(id: string): Promise<Playbook | undefined> {
    const [playbook] = await getDb().select().from(playbooks).where(eq(playbooks.id, id));
    return playbook || undefined;
  }

  async createPlaybook(playbook: InsertPlaybook): Promise<Playbook> {
    const [newPlaybook] = await getDb().insert(playbooks).values(playbook).returning();
    return newPlaybook;
  }

  async updatePlaybook(id: string, playbookUpdate: Partial<Playbook>): Promise<Playbook | undefined> {
    const [updated] = await getDb().update(playbooks)
      .set({ ...playbookUpdate, updatedAt: sql`now()` })
      .where(eq(playbooks.id, id))
      .returning();
    return updated || undefined;
  }

  async deletePlaybook(id: string): Promise<boolean> {
    const result = await getDb().delete(playbooks).where(eq(playbooks.id, id));
    return (result.rowCount || 0) > 0;
  }

  // Playbook Action operations
  async getPlaybookActions(playbookId: string): Promise<PlaybookAction[]> {
    return await getDb()
      .select()
      .from(playbookActions)
      .where(eq(playbookActions.playbookId, playbookId))
      .orderBy(playbookActions.actionOrder);
  }

  async createPlaybookAction(action: InsertPlaybookAction): Promise<PlaybookAction> {
    const [newAction] = await getDb().insert(playbookActions).values(action).returning();
    return newAction;
  }

  async deletePlaybookAction(id: string): Promise<boolean> {
    const result = await getDb().delete(playbookActions).where(eq(playbookActions.id, id));
    return (result.rowCount || 0) > 0;
  }

  // Playbook Execution operations
  async getPlaybookExecutions(alertId?: string): Promise<PlaybookExecution[]> {
    if (alertId) {
      return await getDb()
        .select()
        .from(playbookExecutions)
        .where(eq(playbookExecutions.alertId, alertId))
        .orderBy(desc(playbookExecutions.startedAt));
    }
    return await getDb().select().from(playbookExecutions).orderBy(desc(playbookExecutions.startedAt));
  }

  async createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution> {
    const [newExecution] = await getDb().insert(playbookExecutions).values(execution).returning();
    return newExecution;
  }

  async updatePlaybookExecution(id: string, execution: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined> {
    const [updated] = await getDb().update(playbookExecutions)
      .set(execution)
      .where(eq(playbookExecutions.id, id))
      .returning();
    return updated || undefined;
  }

  // Initialize with sample data for development
  async initializeSampleData(): Promise<void> {
    // Check if data already exists
    const existingAlerts = await this.getAlerts();
    if (existingAlerts.length > 0) return;

    // Create sample alerts
    const sampleAlerts: InsertAlert[] = [
      {
        type: "Phishing Email Campaign",
        severity: "Critical",
        source: "Email Security Gateway",
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
        type: "Phishing Email Campaign",
        severity: "High", 
        source: "Email Security Gateway",
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
        type: "Phishing Email Campaign",
        severity: "Critical",
        source: "Email Security Gateway",
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
      }
    ];

    for (const alert of sampleAlerts) {
      await this.createAlert(alert);
    }

    // Create sample audit log entries
    const sampleAuditEntries: InsertAuditLog[] = [
      {
        actor: "SYSTEM",
        action: "New alert detected: ALT-00001",
        alertId: "ALT-00001",
        metadata: null
      },
      {
        actor: "USER",
        action: "Opened alert ALT-00002 for investigation",
        alertId: "ALT-00002",
        metadata: null
      }
    ];

    for (const entry of sampleAuditEntries) {
      await this.createAuditEntry(entry);
    }
  }
}

export class StorageManager implements IStorage {
  private actualStorage: IStorage | null = null;
  private mockStorage: IStorage | null = null;

  private async getStorage(): Promise<IStorage> {
    if (this.actualStorage) {
      return this.actualStorage;
    }

    if (this.mockStorage) {
      return this.mockStorage;
    }

    try {
      // Try to use database storage first
      const dbStorage = new DatabaseStorage();
      await dbStorage.getAlerts(); // Test connection
      this.actualStorage = dbStorage;
      return dbStorage;
    } catch (error) {
      console.log("Database operation failed, using mock data:", error instanceof Error ? error.message : String(error));
      const { MockStorage } = await import("./mock-storage");
      this.mockStorage = new MockStorage();
      return this.mockStorage;
    }
  }

  async getAlerts(): Promise<Alert[]> {
    const storage = await this.getStorage();
    return storage.getAlerts();
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    const storage = await this.getStorage();
    return storage.getAlert(id);
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const storage = await this.getStorage();
    return storage.createAlert(alert);
  }

  async updateAlert(id: string, alert: Partial<Alert>): Promise<Alert | undefined> {
    const storage = await this.getStorage();
    return storage.updateAlert(id, alert);
  }

  async deleteAlert(id: string): Promise<boolean> {
    const storage = await this.getStorage();
    return storage.deleteAlert(id);
  }

  async getThreatIntelligence(alertId: string): Promise<ThreatIntelligence | undefined> {
    const storage = await this.getStorage();
    return storage.getThreatIntelligence(alertId);
  }

  async createThreatIntelligence(intel: InsertThreatIntelligence): Promise<ThreatIntelligence> {
    const storage = await this.getStorage();
    return storage.createThreatIntelligence(intel);
  }

  async getIOCs(alertId?: string): Promise<IOC[]> {
    const storage = await this.getStorage();
    return storage.getIOCs(alertId);
  }

  async createIOC(ioc: InsertIOC): Promise<IOC> {
    const storage = await this.getStorage();
    return storage.createIOC(ioc);
  }

  async enrichIOC(id: string, enrichmentData: any): Promise<IOC | undefined> {
    const storage = await this.getStorage();
    return storage.enrichIOC(id, enrichmentData);
  }

  async getAuditLog(): Promise<AuditLog[]> {
    const storage = await this.getStorage();
    return storage.getAuditLog();
  }

  async createAuditEntry(entry: InsertAuditLog): Promise<AuditLog> {
    const storage = await this.getStorage();
    return storage.createAuditEntry(entry);
  }

  async getUsers(): Promise<User[]> {
    const storage = await this.getStorage();
    return storage.getUsers();
  }

  async createUser(user: InsertUser): Promise<User> {
    const storage = await this.getStorage();
    return storage.createUser(user);
  }

  async getCorrelations(alertId: string): Promise<Correlation[]> {
    const storage = await this.getStorage();
    return storage.getCorrelations(alertId);
  }

  async createCorrelation(correlation: InsertCorrelation): Promise<Correlation> {
    const storage = await this.getStorage();
    return storage.createCorrelation(correlation);
  }

  async getPlaybooks(): Promise<Playbook[]> {
    const storage = await this.getStorage();
    return storage.getPlaybooks();
  }

  async getPlaybook(id: string): Promise<Playbook | undefined> {
    const storage = await this.getStorage();
    return storage.getPlaybook(id);
  }

  async createPlaybook(playbook: InsertPlaybook): Promise<Playbook> {
    const storage = await this.getStorage();
    return storage.createPlaybook(playbook);
  }

  async getPlaybookActions(playbookId: string): Promise<PlaybookAction[]> {
    const storage = await this.getStorage();
    return storage.getPlaybookActions(playbookId);
  }

  async createPlaybookAction(action: InsertPlaybookAction): Promise<PlaybookAction> {
    const storage = await this.getStorage();
    return storage.createPlaybookAction(action);
  }

  async getPlaybookExecutions(playbookId?: string): Promise<PlaybookExecution[]> {
    const storage = await this.getStorage();
    return storage.getPlaybookExecutions(playbookId);
  }

  async createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution> {
    const storage = await this.getStorage();
    return storage.createPlaybookExecution(execution);
  }

  async updatePlaybookExecution(id: string, execution: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined> {
    const storage = await this.getStorage();
    return storage.updatePlaybookExecution(id, execution);
  }

  // Add the initializeSampleData method for mock storage compatibility
  async initializeSampleData?(): Promise<void> {
    const storage = await this.getStorage();
    if ('initializeSampleData' in storage && typeof storage.initializeSampleData === 'function') {
      await storage.initializeSampleData();
    }
  }
}

export const storage = new StorageManager();
