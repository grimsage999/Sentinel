import { apiRequest } from "./queryClient";
import type { Alert, AuditLog, ThreatIntelligence } from "@shared/schema";
import type { DashboardMetrics, IOCParseResult, IOCEnrichmentResult, UserRole } from "../types";

export const api = {
  // Alert operations
  async getAlerts(): Promise<Alert[]> {
    const response = await apiRequest("GET", "/api/alerts");
    return response.json();
  },

  async getAlert(id: string): Promise<Alert> {
    const response = await apiRequest("GET", `/api/alerts/${id}`);
    return response.json();
  },

  async updateAlert(id: string, data: Partial<Alert>): Promise<Alert> {
    const response = await apiRequest("PATCH", `/api/alerts/${id}`, data);
    return response.json();
  },

  // Threat Intelligence
  async getThreatIntelligence(alertId: string): Promise<ThreatIntelligence> {
    const response = await apiRequest("GET", `/api/threat-intelligence/${alertId}`);
    return response.json();
  },

  // IOC operations
  async parseIOCs(text: string): Promise<IOCParseResult> {
    const response = await apiRequest("POST", "/api/iocs/parse", { text });
    return response.json();
  },

  async enrichIOC(iocType: string, iocValue: string): Promise<IOCEnrichmentResult> {
    const response = await apiRequest("POST", "/api/iocs/enrich", { iocType, iocValue });
    return response.json();
  },

  // Audit log
  async getAuditLog(): Promise<AuditLog[]> {
    const response = await apiRequest("GET", "/api/audit-log");
    return response.json();
  },

  async createAuditEntry(actor: string, action: string, alertId?: string): Promise<AuditLog> {
    const response = await apiRequest("POST", "/api/audit-log", { actor, action, alertId });
    return response.json();
  },

  // Metrics
  async getMetrics(role: UserRole): Promise<DashboardMetrics> {
    const response = await apiRequest("GET", `/api/metrics/${role}`);
    return response.json();
  },

  // Correlation Analysis
  async getCorrelationAnalysis(alertId: string): Promise<any> {
    const response = await apiRequest("GET", `/api/correlations/${alertId}`);
    return response.json();
  }
};
