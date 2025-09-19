// SIEM Integration Service for Cybersecurity Workbench
// Centralized threat data collection from multiple SIEM platforms

import { storage } from "./storage";
import { correlationEngine } from "./correlation-engine";
import { playbookEngine } from "./playbook-engine";
import { emailService } from "./email-service";
import { type Alert, type AuditLog } from "@shared/schema";
// JSON type for metadata and enrichment data
type Json = any;

// SIEM Platform Types
export type SIEMPlatform = "splunk" | "qradar" | "sentinel" | "arcsight" | "securonix" | "logrhythm" | "sumo_logic" | "elastic_siem";

// SIEM Event Interface - normalized format for all SIEM platforms
export interface SIEMEvent {
  id: string;
  platform: SIEMPlatform;
  timestamp: string;
  eventType: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  sourceIP?: string;
  destinationIP?: string;
  sourceHost?: string;
  destinationHost?: string;
  user?: string;
  action?: string;
  protocol?: string;
  port?: number;
  payload?: string;
  signature?: string;
  malwareFamily?: string;
  threatCategory?: string;
  confidence: number;
  rawEvent: any;
  enrichedData?: {
    geoLocation?: { country: string; city: string; latitude: number; longitude: number };
    reputation?: { score: number; category: string; source: string };
    threatIntel?: { isMalicious: boolean; threatType: string; source: string };
  };
}

// SIEM Connector Interface
interface SIEMConnector {
  platform: SIEMPlatform;
  name: string;
  isConnected(): boolean;
  connect(): Promise<boolean>;
  disconnect(): Promise<void>;
  fetchEvents(timeRange?: { start: Date; end: Date }, limit?: number): Promise<SIEMEvent[]>;
  subscribeToRealTime(callback: (event: SIEMEvent) => void): Promise<void>;
  testConnection(): Promise<boolean>;
}

// Splunk SIEM Connector (Simulation)
class SplunkConnector implements SIEMConnector {
  platform: SIEMPlatform = "splunk";
  name = "Splunk Enterprise Security";
  private connected = false;
  private realTimeSubscriptions: ((event: SIEMEvent) => void)[] = [];

  isConnected(): boolean {
    return this.connected;
  }

  async connect(): Promise<boolean> {
    console.log("[SIEM] Connecting to Splunk Enterprise Security...");
    
    // Simulate connection logic
    await new Promise(resolve => setTimeout(resolve, 1000));
    this.connected = true;
    
    console.log("[SIEM] Successfully connected to Splunk");
    this.startRealTimeSimulation();
    return true;
  }

  async disconnect(): Promise<void> {
    console.log("[SIEM] Disconnecting from Splunk...");
    this.connected = false;
    this.realTimeSubscriptions = [];
  }

  async fetchEvents(timeRange?: { start: Date; end: Date }, limit = 100): Promise<SIEMEvent[]> {
    if (!this.connected) throw new Error("Not connected to Splunk");

    console.log(`[SIEM] Fetching ${limit} events from Splunk...`);
    
    // Simulate fetching historical events
    const events: SIEMEvent[] = [];
    for (let i = 0; i < Math.min(limit, 20); i++) {
      events.push(this.generateSampleEvent());
    }
    
    return events;
  }

  async subscribeToRealTime(callback: (event: SIEMEvent) => void): Promise<void> {
    this.realTimeSubscriptions.push(callback);
  }

  async testConnection(): Promise<boolean> {
    try {
      console.log("[SIEM] Testing Splunk connection...");
      await new Promise(resolve => setTimeout(resolve, 500));
      return this.connected;
    } catch {
      return false;
    }
  }

  private startRealTimeSimulation(): void {
    // Simulate real-time events every 30-60 seconds
    setInterval(() => {
      if (this.connected && this.realTimeSubscriptions.length > 0) {
        const event = this.generateSampleEvent();
        this.realTimeSubscriptions.forEach(callback => callback(event));
      }
    }, 45000 + Math.random() * 30000); // 45-75 seconds
  }

  private generateSampleEvent(): SIEMEvent {
    const eventTypes = [
      "Malware Detected",
      "Suspicious Network Activity", 
      "Failed Login Attempts",
      "Data Exfiltration Attempt",
      "Privilege Escalation",
      "Command and Control Communication",
      "Lateral Movement",
      "Anomalous User Behavior"
    ];

    const severities: ("Critical" | "High" | "Medium" | "Low")[] = ["Critical", "High", "Medium", "Low"];
    const threatCategories = ["Malware", "Phishing", "Ransomware", "APT", "Insider Threat", "DDoS", "Data Breach"];

    return {
      id: `SPL-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      platform: "splunk",
      timestamp: new Date().toISOString(),
      eventType: eventTypes[Math.floor(Math.random() * eventTypes.length)],
      severity: severities[Math.floor(Math.random() * severities.length)],
      sourceIP: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      destinationIP: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      sourceHost: `workstation-${Math.floor(Math.random() * 1000)}`,
      user: `user${Math.floor(Math.random() * 100)}@company.com`,
      confidence: 70 + Math.random() * 30,
      threatCategory: threatCategories[Math.floor(Math.random() * threatCategories.length)],
      rawEvent: {
        source: "splunk_enterprise_security",
        index: "main",
        sourcetype: "security_alert"
      },
      enrichedData: {
        geoLocation: {
          country: "United States",
          city: "New York",
          latitude: 40.7128,
          longitude: -74.0060
        },
        reputation: {
          score: Math.floor(Math.random() * 100),
          category: "suspicious",
          source: "VirusTotal"
        }
      }
    };
  }
}

// QRadar SIEM Connector (Simulation)
class QRadarConnector implements SIEMConnector {
  platform: SIEMPlatform = "qradar";
  name = "IBM QRadar SIEM";
  private connected = false;
  private realTimeSubscriptions: ((event: SIEMEvent) => void)[] = [];

  isConnected(): boolean {
    return this.connected;
  }

  async connect(): Promise<boolean> {
    console.log("[SIEM] Connecting to IBM QRadar...");
    await new Promise(resolve => setTimeout(resolve, 800));
    this.connected = true;
    console.log("[SIEM] Successfully connected to QRadar");
    this.startRealTimeSimulation();
    return true;
  }

  async disconnect(): Promise<void> {
    console.log("[SIEM] Disconnecting from QRadar...");
    this.connected = false;
    this.realTimeSubscriptions = [];
  }

  async fetchEvents(timeRange?: { start: Date; end: Date }, limit = 100): Promise<SIEMEvent[]> {
    if (!this.connected) throw new Error("Not connected to QRadar");

    console.log(`[SIEM] Fetching ${limit} events from QRadar...`);
    
    const events: SIEMEvent[] = [];
    for (let i = 0; i < Math.min(limit, 15); i++) {
      events.push(this.generateSampleEvent());
    }
    
    return events;
  }

  async subscribeToRealTime(callback: (event: SIEMEvent) => void): Promise<void> {
    this.realTimeSubscriptions.push(callback);
  }

  async testConnection(): Promise<boolean> {
    try {
      console.log("[SIEM] Testing QRadar connection...");
      await new Promise(resolve => setTimeout(resolve, 400));
      return this.connected;
    } catch {
      return false;
    }
  }

  private startRealTimeSimulation(): void {
    setInterval(() => {
      if (this.connected && this.realTimeSubscriptions.length > 0) {
        const event = this.generateSampleEvent();
        this.realTimeSubscriptions.forEach(callback => callback(event));
      }
    }, 60000 + Math.random() * 40000); // 60-100 seconds
  }

  private generateSampleEvent(): SIEMEvent {
    const eventTypes = [
      "Network Intrusion Detected",
      "Malicious File Execution",
      "Unauthorized Access Attempt",
      "Policy Violation",
      "Suspicious DNS Query",
      "Anomalous Traffic Pattern"
    ];

    const severities: ("Critical" | "High" | "Medium" | "Low")[] = ["High", "Medium", "Low"];

    return {
      id: `QR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      platform: "qradar",
      timestamp: new Date().toISOString(),
      eventType: eventTypes[Math.floor(Math.random() * eventTypes.length)],
      severity: severities[Math.floor(Math.random() * severities.length)],
      sourceIP: `172.16.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      protocol: Math.random() > 0.5 ? "TCP" : "UDP",
      port: Math.floor(Math.random() * 65535),
      confidence: 60 + Math.random() * 40,
      rawEvent: {
        source: "qradar_siem",
        offense_id: Math.floor(Math.random() * 10000),
        rule_name: "Custom Security Rule"
      }
    };
  }
}

// SIEM Integration Manager
class SIEMIntegrationManager {
  private connectors: Map<SIEMPlatform, SIEMConnector> = new Map();
  private eventProcessingQueue: SIEMEvent[] = [];
  private isProcessing = false;
  private statistics = {
    totalEventsProcessed: 0,
    alertsGenerated: 0,
    lastProcessedAt: null as Date | null,
    connectedPlatforms: 0,
    processingErrors: 0
  };

  constructor() {
    // Initialize SIEM connectors
    this.connectors.set("splunk", new SplunkConnector());
    this.connectors.set("qradar", new QRadarConnector());
    
    // Start event processing
    this.startEventProcessing();
  }

  // Connect to SIEM platforms
  async connectToPlatform(platform: SIEMPlatform): Promise<boolean> {
    const connector = this.connectors.get(platform);
    if (!connector) {
      console.error(`[SIEM] Unknown platform: ${platform}`);
      return false;
    }

    try {
      const success = await connector.connect();
      if (success) {
        this.statistics.connectedPlatforms++;
        
        // Subscribe to real-time events
        await connector.subscribeToRealTime((event) => {
          this.enqueueEvent(event);
        });
        
        console.log(`[SIEM] Successfully connected to ${connector.name}`);
      }
      return success;
    } catch (error) {
      console.error(`[SIEM] Failed to connect to ${platform}:`, error);
      return false;
    }
  }

  // Disconnect from SIEM platforms
  async disconnectFromPlatform(platform: SIEMPlatform): Promise<void> {
    const connector = this.connectors.get(platform);
    if (connector && connector.isConnected()) {
      await connector.disconnect();
      this.statistics.connectedPlatforms--;
      console.log(`[SIEM] Disconnected from ${connector.name}`);
    }
  }

  // Fetch historical events
  async fetchHistoricalEvents(platform: SIEMPlatform, timeRange?: { start: Date; end: Date }, limit = 100): Promise<SIEMEvent[]> {
    const connector = this.connectors.get(platform);
    if (!connector || !connector.isConnected()) {
      throw new Error(`${platform} is not connected`);
    }

    const events = await connector.fetchEvents(timeRange, limit);
    
    // Process events immediately
    for (const event of events) {
      await this.processEvent(event);
    }
    
    return events;
  }

  // Convert SIEM event to Alert
  private async convertToAlert(event: SIEMEvent): Promise<Omit<Alert, "id">> {
    return {
      type: this.mapEventTypeToAlertType(event.eventType),
      severity: event.severity,
      status: "Open",
      source: `SIEM:${event.platform}`,
      timestamp: new Date(event.timestamp),
      title: `${event.eventType}${event.sourceHost ? ` on ${event.sourceHost}` : ''}`,
      description: this.generateAlertDescription(event),
      confidence: Math.round(event.confidence),
      affectedAssets: event.sourceHost ? 1 : 0,
      businessImpact: this.assessBusinessImpact(event),
      aiTriaged: true,
      assignee: event.severity === "Critical" ? "security-lead@company.com" : null,
      metadata: {
        siemEvent: {
          id: event.id,
          platform: event.platform,
          rawEvent: event.rawEvent
        },
        sourceIP: event.sourceIP,
        destinationIP: event.destinationIP,
        user: event.user,
        threatCategory: event.threatCategory
      } as Json
    };
  }

  private mapEventTypeToAlertType(eventType: string): string {
    const mappings: Record<string, string> = {
      "Malware Detected": "Malware Detection",
      "Malicious File Execution": "Malware Detection", 
      "Suspicious Network Activity": "Network Intrusion",
      "Network Intrusion Detected": "Network Intrusion",
      "Failed Login Attempts": "Suspicious Login Activity",
      "Unauthorized Access Attempt": "Suspicious Login Activity",
      "Data Exfiltration Attempt": "Data Exfiltration Attempt",
      "Command and Control Communication": "Network Intrusion",
      "Lateral Movement": "Network Intrusion",
      "Privilege Escalation": "Suspicious Login Activity",
      "Anomalous User Behavior": "Suspicious Login Activity",
      "Policy Violation": "Policy Violation",
      "Suspicious DNS Query": "Network Intrusion",
      "Anomalous Traffic Pattern": "Network Intrusion"
    };

    return mappings[eventType] || "Security Event";
  }

  private generateAlertDescription(event: SIEMEvent): string {
    let description = `SIEM Alert from ${event.platform.toUpperCase()}: ${event.eventType}`;
    
    if (event.sourceIP) description += `\nSource IP: ${event.sourceIP}`;
    if (event.destinationIP) description += `\nDestination IP: ${event.destinationIP}`;
    if (event.sourceHost) description += `\nSource Host: ${event.sourceHost}`;
    if (event.user) description += `\nUser: ${event.user}`;
    if (event.threatCategory) description += `\nThreat Category: ${event.threatCategory}`;
    if (event.malwareFamily) description += `\nMalware Family: ${event.malwareFamily}`;
    
    description += `\nConfidence: ${Math.round(event.confidence)}%`;
    
    if (event.enrichedData?.geoLocation) {
      const geo = event.enrichedData.geoLocation;
      description += `\nLocation: ${geo.city}, ${geo.country}`;
    }
    
    if (event.enrichedData?.reputation) {
      const rep = event.enrichedData.reputation;
      description += `\nReputation Score: ${rep.score}/100 (${rep.category})`;
    }

    return description;
  }

  private assessBusinessImpact(event: SIEMEvent): string {
    if (event.severity === "Critical") return "High";
    if (event.severity === "High") return "Medium";
    if (event.severity === "Medium") return "Low";
    return "Minimal";
  }

  // Event processing queue
  private enqueueEvent(event: SIEMEvent): void {
    this.eventProcessingQueue.push(event);
    console.log(`[SIEM] Queued event ${event.id} from ${event.platform} (${event.eventType})`);
  }

  private startEventProcessing(): void {
    setInterval(async () => {
      if (!this.isProcessing && this.eventProcessingQueue.length > 0) {
        this.isProcessing = true;
        
        const eventsToProcess = this.eventProcessingQueue.splice(0, 10); // Process up to 10 events at once
        
        for (const event of eventsToProcess) {
          try {
            await this.processEvent(event);
          } catch (error) {
            console.error(`[SIEM] Error processing event ${event.id}:`, error);
            this.statistics.processingErrors++;
          }
        }
        
        this.isProcessing = false;
      }
    }, 5000); // Process every 5 seconds
  }

  private async processEvent(event: SIEMEvent): Promise<void> {
    try {
      console.log(`[SIEM] Processing event ${event.id}: ${event.eventType} (${event.severity})`);
      
      // Convert SIEM event to Alert
      const alertData = await this.convertToAlert(event);
      const alert = await storage.createAlert(alertData as any);
      
      this.statistics.totalEventsProcessed++;
      this.statistics.alertsGenerated++;
      this.statistics.lastProcessedAt = new Date();
      
      console.log(`[SIEM] Created alert ${alert.id} from SIEM event ${event.id}`);
      
      // Extract IOCs from the event
      await this.extractAndStoreIOCs(event, alert.id);
      
      // Run correlation analysis
      const correlationAnalysis = await correlationEngine.analyzeAlert(alert.id);
      if (correlationAnalysis.correlations.length > 0) {
        console.log(`[SIEM] Found ${correlationAnalysis.correlations.length} correlations for alert ${alert.id}`);
      }
      
      // Check for automatic playbook triggers (critical alerts)
      if (alert.severity === "Critical") {
        const playbooks = await storage.getPlaybooks();
        const criticalPlaybook = playbooks.find(p => p.name === "Critical Alert Response");
        
        if (criticalPlaybook) {
          console.log(`[SIEM] Triggering critical alert playbook for ${alert.id}`);
          await playbookEngine.executePlaybook(criticalPlaybook, alert, "AUTOMATIC");
        }
      }
      
    } catch (error) {
      console.error(`[SIEM] Failed to process event ${event.id}:`, error);
      this.statistics.processingErrors++;
      throw error;
    }
  }

  private async extractAndStoreIOCs(event: SIEMEvent, alertId: string): Promise<void> {
    const iocs: Array<{
      type: string;
      value: string;
      source?: string | null;
      reputation?: string | null;
      alertId?: string | null;
      enrichmentData?: Json;
    }> = [];
    
    // Extract IP addresses
    if (event.sourceIP && this.isValidIOC(event.sourceIP)) {
      iocs.push({
        type: "ip",
        value: event.sourceIP,
        source: `SIEM:${event.platform}`,
        reputation: "Suspicious",
        alertId: alertId,
        enrichmentData: {
          confidence: Math.round(event.confidence),
          threatTypes: event.threatCategory ? [event.threatCategory] : [],
          tags: ["siem-extracted", event.platform],
          platform: event.platform,
          firstSeen: event.timestamp
        } as Json
      });
    }
    
    if (event.destinationIP && this.isValidIOC(event.destinationIP)) {
      iocs.push({
        type: "ip",
        value: event.destinationIP,
        source: `SIEM:${event.platform}`,
        reputation: "Suspicious", 
        alertId: alertId,
        enrichmentData: {
          confidence: Math.round(event.confidence),
          threatTypes: event.threatCategory ? [event.threatCategory] : [],
          tags: ["siem-extracted", event.platform],
          platform: event.platform,
          firstSeen: event.timestamp
        } as Json
      });
    }
    
    // Extract hostnames
    if (event.sourceHost && this.isValidIOC(event.sourceHost)) {
      iocs.push({
        type: "domain",
        value: event.sourceHost,
        source: `SIEM:${event.platform}`,
        reputation: "Unknown",
        alertId: alertId,
        enrichmentData: {
          confidence: Math.round(event.confidence),
          threatTypes: event.threatCategory ? [event.threatCategory] : [],
          tags: ["siem-extracted", event.platform],
          platform: event.platform,
          firstSeen: event.timestamp
        } as Json
      });
    }
    
    // Store IOCs
    for (const ioc of iocs) {
      try {
        await storage.createIOC(ioc);
        console.log(`[SIEM] Extracted IOC: ${ioc.type}:${ioc.value}`);
      } catch (error) {
        console.error(`[SIEM] Failed to store IOC ${ioc.value}:`, error);
      }
    }
  }

  private isValidIOC(value: string): boolean {
    // Basic validation - in production this would be more sophisticated
    if (!value || value.length < 3) return false;
    if (value.startsWith("192.168.") || value.startsWith("10.0.") || value.startsWith("172.16.")) {
      return false; // Skip private IPs
    }
    return true;
  }

  // Management methods
  async connectToAllPlatforms(): Promise<void> {
    console.log("[SIEM] Connecting to all configured SIEM platforms...");
    
    const platforms: SIEMPlatform[] = ["splunk", "qradar"];
    
    for (const platform of platforms) {
      try {
        await this.connectToPlatform(platform);
      } catch (error) {
        console.error(`[SIEM] Failed to connect to ${platform}:`, error);
      }
    }
    
    console.log(`[SIEM] Connected to ${this.statistics.connectedPlatforms} SIEM platforms`);
  }

  async disconnectFromAllPlatforms(): Promise<void> {
    console.log("[SIEM] Disconnecting from all SIEM platforms...");
    
    const entries = Array.from(this.connectors.entries());
    for (const [platform, connector] of entries) {
      if (connector.isConnected()) {
        await this.disconnectFromPlatform(platform);
      }
    }
  }

  getConnectedPlatforms(): { platform: SIEMPlatform; name: string; connected: boolean }[] {
    return Array.from(this.connectors.entries()).map(([platform, connector]) => ({
      platform,
      name: connector.name,
      connected: connector.isConnected()
    }));
  }

  getStatistics() {
    return {
      ...this.statistics,
      queueLength: this.eventProcessingQueue.length,
      isProcessing: this.isProcessing
    };
  }

  async testAllConnections(): Promise<{ platform: SIEMPlatform; success: boolean; error?: string }[]> {
    const results: { platform: SIEMPlatform; success: boolean; error?: string }[] = [];
    
    const entries = Array.from(this.connectors.entries());
    for (const [platform, connector] of entries) {
      try {
        const success = await connector.testConnection();
        results.push({ platform, success });
      } catch (error) {
        results.push({ 
          platform, 
          success: false, 
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
    
    return results;
  }
}

// Export the SIEM integration manager instance
export const siemIntegration = new SIEMIntegrationManager();