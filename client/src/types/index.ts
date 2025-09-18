export interface DashboardMetrics {
  title: string;
  metrics: {
    label: string;
    value: string;
    color: string;
  }[];
}

export interface IOCParseResult {
  success: boolean;
  iocs: {
    ips: string[];
    domains: string[];
    urls: string[];
    hashes: string[];
  };
}

export interface IOCEnrichmentResult {
  success: boolean;
  iocType: string;
  iocValue: string;
  enrichment: Record<string, any>;
}

export type UserRole = "analyst" | "manager" | "executive";
export type AlertSeverity = "Critical" | "High" | "Medium" | "Low";
export type AlertStatus = "New" | "Triaging" | "Investigating" | "Resolved";
