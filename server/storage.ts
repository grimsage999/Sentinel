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
  type InsertUser
} from "@shared/schema";
import { randomUUID } from "crypto";

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
}

export class MemStorage implements IStorage {
  private alerts: Map<string, Alert>;
  private threatIntel: Map<string, ThreatIntelligence>;
  private iocs: Map<string, IOC>;
  private auditLogs: Map<string, AuditLog>;
  private users: Map<string, User>;

  constructor() {
    this.alerts = new Map();
    this.threatIntel = new Map();
    this.iocs = new Map();
    this.auditLogs = new Map();
    this.users = new Map();
    this.initializeMockData();
  }

  private initializeMockData() {
    // Initialize with some sample data
    const alertsData: Alert[] = [
      {
        id: "ALT-00001",
        type: "Phishing Email Campaign",
        severity: "Critical",
        source: "Email Gateway",
        timestamp: new Date(Date.now() - 120000),
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
        id: "ALT-00002",
        type: "Suspicious Login Activity",
        severity: "High",
        source: "SIEM",
        timestamp: new Date(Date.now() - 900000),
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
        id: "ALT-00003",
        type: "Data Exfiltration Attempt",
        severity: "Medium",
        source: "Network Monitor",
        timestamp: new Date(Date.now() - 2700000),
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

    alertsData.forEach(alert => this.alerts.set(alert.id, alert));

    // Add some audit log entries
    this.auditLogs.set("1", {
      id: "1",
      timestamp: new Date(Date.now() - 120000),
      actor: "SYSTEM",
      action: "New alert detected: ALT-00001",
      alertId: "ALT-00001",
      metadata: null
    });

    this.auditLogs.set("2", {
      id: "2",
      timestamp: new Date(Date.now() - 480000),
      actor: "USER",
      action: "Opened alert ALT-00002 for investigation",
      alertId: "ALT-00002",
      metadata: null
    });
  }

  async getAlerts(): Promise<Alert[]> {
    return Array.from(this.alerts.values()).sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  async getAlert(id: string): Promise<Alert | undefined> {
    return this.alerts.get(id);
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const id = `ALT-${String(this.alerts.size + 1).padStart(5, '0')}`;
    const newAlert: Alert = {
      ...alert,
      id,
      timestamp: new Date(),
      metadata: alert.metadata || null
    };
    this.alerts.set(id, newAlert);
    return newAlert;
  }

  async updateAlert(id: string, alert: Partial<Alert>): Promise<Alert | undefined> {
    const existing = this.alerts.get(id);
    if (!existing) return undefined;

    const updated = { ...existing, ...alert };
    this.alerts.set(id, updated);
    return updated;
  }

  async deleteAlert(id: string): Promise<boolean> {
    return this.alerts.delete(id);
  }

  async getThreatIntelligence(alertId: string): Promise<ThreatIntelligence | undefined> {
    return Array.from(this.threatIntel.values()).find(intel => intel.alertId === alertId);
  }

  async createThreatIntelligence(intel: InsertThreatIntelligence): Promise<ThreatIntelligence> {
    const id = randomUUID();
    const newIntel: ThreatIntelligence = {
      ...intel,
      id,
      createdAt: new Date(),
      alertId: intel.alertId || null,
      iocs: intel.iocs || null,
      attribution: intel.attribution || null
    };
    this.threatIntel.set(id, newIntel);
    return newIntel;
  }

  async getIOCs(alertId?: string): Promise<IOC[]> {
    const allIOCs = Array.from(this.iocs.values());
    if (alertId) {
      return allIOCs.filter(ioc => ioc.alertId === alertId);
    }
    return allIOCs;
  }

  async createIOC(ioc: InsertIOC): Promise<IOC> {
    const id = randomUUID();
    const newIOC: IOC = {
      ...ioc,
      id,
      createdAt: new Date(),
      alertId: ioc.alertId || null,
      enrichmentData: ioc.enrichmentData || null
    };
    this.iocs.set(id, newIOC);
    return newIOC;
  }

  async enrichIOC(id: string, enrichmentData: any): Promise<IOC | undefined> {
    const ioc = this.iocs.get(id);
    if (!ioc) return undefined;

    const updated = { ...ioc, enrichmentData };
    this.iocs.set(id, updated);
    return updated;
  }

  async getAuditLog(): Promise<AuditLog[]> {
    return Array.from(this.auditLogs.values()).sort((a, b) => 
      new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime()
    );
  }

  async createAuditEntry(entry: InsertAuditLog): Promise<AuditLog> {
    const id = randomUUID();
    const newEntry: AuditLog = {
      ...entry,
      id,
      timestamp: new Date(),
      alertId: entry.alertId || null,
      metadata: entry.metadata || null
    };
    this.auditLogs.set(id, newEntry);
    return newEntry;
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(user => user.username === username);
  }

  async createUser(user: InsertUser): Promise<User> {
    const id = randomUUID();
    const newUser: User = { 
      ...user, 
      id,
      clearanceLevel: user.clearanceLevel || null
    };
    this.users.set(id, newUser);
    return newUser;
  }
}

export const storage = new MemStorage();
