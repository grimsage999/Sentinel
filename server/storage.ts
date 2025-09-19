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
import { db } from "./db";
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
    return await db.select().from(alerts).orderBy(desc(alerts.timestamp));
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    const [alert] = await db.select().from(alerts).where(eq(alerts.id, id));
    return alert || undefined;
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    // Use a simple approach to get the next alert ID without full table scan
    const result = await db.execute(sql`
      SELECT COALESCE(MAX(CAST(SUBSTRING(id FROM 5) AS INTEGER)), 0) + 1 as next_num 
      FROM alerts 
      WHERE id LIKE 'ALT-%'
    `);
    const nextNum = (result.rows[0] as any)?.next_num || 1;
    const id = `ALT-${String(nextNum).padStart(5, '0')}`;
    
    const [newAlert] = await db
      .insert(alerts)
      .values({ ...alert, id })
      .returning();
    return newAlert;
  }

  async updateAlert(id: string, alert: Partial<Alert>): Promise<Alert | undefined> {
    const [updated] = await db
      .update(alerts)
      .set(alert)
      .where(eq(alerts.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteAlert(id: string): Promise<boolean> {
    const result = await db.delete(alerts).where(eq(alerts.id, id));
    return result.rowCount !== null && result.rowCount > 0;
  }

  async getThreatIntelligence(alertId: string): Promise<ThreatIntelligence | undefined> {
    const [intel] = await db
      .select()
      .from(threatIntelligence)
      .where(eq(threatIntelligence.alertId, alertId));
    return intel || undefined;
  }

  async createThreatIntelligence(intel: InsertThreatIntelligence): Promise<ThreatIntelligence> {
    const [newIntel] = await db
      .insert(threatIntelligence)
      .values(intel)
      .returning();
    return newIntel;
  }

  async getIOCs(alertId?: string): Promise<IOC[]> {
    if (alertId) {
      return await db.select().from(iocs).where(eq(iocs.alertId, alertId));
    }
    return await db.select().from(iocs);
  }

  async createIOC(ioc: InsertIOC): Promise<IOC> {
    const [newIOC] = await db.insert(iocs).values(ioc).returning();
    return newIOC;
  }

  async enrichIOC(id: string, enrichmentData: any): Promise<IOC | undefined> {
    const [updated] = await db
      .update(iocs)
      .set({ enrichmentData })
      .where(eq(iocs.id, id))
      .returning();
    return updated || undefined;
  }

  async getAuditLog(): Promise<AuditLog[]> {
    return await db.select().from(auditLog).orderBy(desc(auditLog.timestamp));
  }

  async createAuditEntry(entry: InsertAuditLog): Promise<AuditLog> {
    const [newEntry] = await db.insert(auditLog).values(entry).returning();
    return newEntry;
  }

  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async createUser(user: InsertUser): Promise<User> {
    const [newUser] = await db.insert(users).values(user).returning();
    return newUser;
  }

  async getCorrelations(alertId: string): Promise<Correlation[]> {
    return await db
      .select()
      .from(correlations)
      .where(eq(correlations.primaryAlertId, alertId))
      .orderBy(desc(correlations.confidence));
  }

  async createCorrelation(correlation: InsertCorrelation): Promise<Correlation> {
    const [newCorrelation] = await db.insert(correlations).values(correlation).returning();
    return newCorrelation;
  }

  // Playbook operations
  async getPlaybooks(): Promise<Playbook[]> {
    return await db.select().from(playbooks).orderBy(desc(playbooks.createdAt));
  }

  async getPlaybook(id: string): Promise<Playbook | undefined> {
    const [playbook] = await db.select().from(playbooks).where(eq(playbooks.id, id));
    return playbook || undefined;
  }

  async createPlaybook(playbook: InsertPlaybook): Promise<Playbook> {
    const [newPlaybook] = await db.insert(playbooks).values(playbook).returning();
    return newPlaybook;
  }

  async updatePlaybook(id: string, playbookUpdate: Partial<Playbook>): Promise<Playbook | undefined> {
    const [updated] = await db.update(playbooks)
      .set({ ...playbookUpdate, updatedAt: sql`now()` })
      .where(eq(playbooks.id, id))
      .returning();
    return updated || undefined;
  }

  async deletePlaybook(id: string): Promise<boolean> {
    const result = await db.delete(playbooks).where(eq(playbooks.id, id));
    return (result.rowCount || 0) > 0;
  }

  // Playbook Action operations
  async getPlaybookActions(playbookId: string): Promise<PlaybookAction[]> {
    return await db
      .select()
      .from(playbookActions)
      .where(eq(playbookActions.playbookId, playbookId))
      .orderBy(playbookActions.actionOrder);
  }

  async createPlaybookAction(action: InsertPlaybookAction): Promise<PlaybookAction> {
    const [newAction] = await db.insert(playbookActions).values(action).returning();
    return newAction;
  }

  async deletePlaybookAction(id: string): Promise<boolean> {
    const result = await db.delete(playbookActions).where(eq(playbookActions.id, id));
    return (result.rowCount || 0) > 0;
  }

  // Playbook Execution operations
  async getPlaybookExecutions(alertId?: string): Promise<PlaybookExecution[]> {
    if (alertId) {
      return await db
        .select()
        .from(playbookExecutions)
        .where(eq(playbookExecutions.alertId, alertId))
        .orderBy(desc(playbookExecutions.startedAt));
    }
    return await db.select().from(playbookExecutions).orderBy(desc(playbookExecutions.startedAt));
  }

  async createPlaybookExecution(execution: InsertPlaybookExecution): Promise<PlaybookExecution> {
    const [newExecution] = await db.insert(playbookExecutions).values(execution).returning();
    return newExecution;
  }

  async updatePlaybookExecution(id: string, execution: Partial<PlaybookExecution>): Promise<PlaybookExecution | undefined> {
    const [updated] = await db.update(playbookExecutions)
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
        source: "Email Gateway",
        status: "New",
        confidence: 95,
        affectedAssets: 12,
        businessImpact: "High",
        assignee: "Unassigned",
        aiTriaged: true,
        title: "Phishing Email Campaign Detected",
        description: "Suspicious emails targeting C-level executives with credential harvesting attempts",
        metadata: null
      },
      {
        type: "Suspicious Login Activity",
        severity: "High",
        source: "SIEM",
        status: "Triaging",
        confidence: 82,
        affectedAssets: 3,
        businessImpact: "Medium",
        assignee: "Sarah M.",
        aiTriaged: true,
        title: "Suspicious Login Activity",
        description: "Multiple failed login attempts from unusual geographic locations",
        metadata: null
      },
      {
        type: "Data Exfiltration Attempt",
        severity: "Medium",
        source: "Network Monitor",
        status: "Investigating",
        confidence: 76,
        affectedAssets: 5,
        businessImpact: "Medium",
        assignee: "John D.",
        aiTriaged: true,
        title: "Data Exfiltration Attempt",
        description: "Unusual data transfer patterns detected on network perimeter",
        metadata: null
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

export const storage = new DatabaseStorage();
