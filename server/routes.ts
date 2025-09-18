import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertAlertSchema, insertAuditLogSchema, insertIOCSchema } from "@shared/schema";
import { z } from "zod";

export async function registerRoutes(app: Express): Promise<Server> {
  // Alert routes
  app.get("/api/alerts", async (req, res) => {
    try {
      const alerts = await storage.getAlerts();
      res.json(alerts);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch alerts" });
    }
  });

  app.get("/api/alerts/:id", async (req, res) => {
    try {
      const alert = await storage.getAlert(req.params.id);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }
      res.json(alert);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch alert" });
    }
  });

  app.post("/api/alerts", async (req, res) => {
    try {
      const alertData = insertAlertSchema.parse(req.body);
      const alert = await storage.createAlert(alertData);
      res.status(201).json(alert);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to create alert" });
    }
  });

  app.patch("/api/alerts/:id", async (req, res) => {
    try {
      const alert = await storage.updateAlert(req.params.id, req.body);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }
      res.json(alert);
    } catch (error) {
      res.status(500).json({ error: "Failed to update alert" });
    }
  });

  // Threat Intelligence routes
  app.get("/api/threat-intelligence/:alertId", async (req, res) => {
    try {
      const intel = await storage.getThreatIntelligence(req.params.alertId);
      if (!intel) {
        // Create mock threat intelligence data
        const mockIntel = await storage.createThreatIntelligence({
          alertId: req.params.alertId,
          maliciousScore: Math.floor(Math.random() * 100),
          previousSightings: Math.floor(Math.random() * 50),
          threatActor: ['APT28', 'Lazarus', 'FIN7', 'Unknown'][Math.floor(Math.random() * 4)],
          iocs: [
            { type: 'IP', value: '192.168.1.' + Math.floor(Math.random() * 255), reputation: 'Malicious' },
            { type: 'Domain', value: 'suspicious-domain.com', reputation: 'Suspicious' },
            { type: 'Hash', value: 'a1b2c3d4e5f6...', reputation: 'Clean' }
          ],
          attribution: {
            confidence: 'High',
            campaign: 'WellMail'
          }
        });
        return res.json(mockIntel);
      }
      res.json(intel);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch threat intelligence" });
    }
  });

  // IOC routes
  app.get("/api/iocs", async (req, res) => {
    try {
      const alertId = req.query.alertId as string;
      const iocs = await storage.getIOCs(alertId);
      res.json(iocs);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch IOCs" });
    }
  });

  app.post("/api/iocs/parse", async (req, res) => {
    try {
      const { text } = req.body;
      if (!text) {
        return res.status(400).json({ error: "Text content required" });
      }

      // IOC parsing patterns
      const patterns = {
        ip: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
        domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
        url: /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g,
        hash_md5: /\b[a-fA-F0-9]{32}\b/g,
        hash_sha1: /\b[a-fA-F0-9]{40}\b/g,
        hash_sha256: /\b[a-fA-F0-9]{64}\b/g
      };

      const extractedIOCs = {
        ips: Array.from(new Set(text.match(patterns.ip) || [])),
        domains: Array.from(new Set(text.match(patterns.domain) || [])),
        urls: Array.from(new Set(text.match(patterns.url) || [])),
        hashes: Array.from(new Set([
          ...(text.match(patterns.hash_md5) || []),
          ...(text.match(patterns.hash_sha1) || []),
          ...(text.match(patterns.hash_sha256) || [])
        ]))
      };

      // Filter out private IPs from domains
      const urlDomains = extractedIOCs.urls.map(url => {
        const match = url.match(/https?:\/\/([^\/]+)/);
        return match ? match[1] : '';
      }).filter(Boolean);

      extractedIOCs.domains = extractedIOCs.domains.filter(domain => 
        !extractedIOCs.ips.includes(domain) && !urlDomains.includes(domain)
      );

      res.json({
        success: true,
        iocs: extractedIOCs
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to parse IOCs" });
    }
  });

  app.post("/api/iocs/enrich", async (req, res) => {
    try {
      const { iocType, iocValue } = req.body;
      if (!iocType || !iocValue) {
        return res.status(400).json({ error: "IOC type and value required" });
      }

      let enrichmentData = {};

      // Mock enrichment based on IOC type
      if (iocType === 'ip') {
        enrichmentData = {
          source: 'AbuseIPDB',
          reputation: iocValue.startsWith('192.168') || iocValue.startsWith('10.') ? 'Clean' : 'Suspicious',
          abuseConfidence: iocValue.startsWith('192.168') ? 0 : 75,
          country: 'US',
          usageType: iocValue.startsWith('192.168') ? 'Corporate' : 'Data Center'
        };
      } else if (iocType === 'domain') {
        enrichmentData = {
          source: 'VirusTotal',
          reputation: iocValue.includes('suspicious') || iocValue.includes('phish') ? 'Malicious' : 'Clean',
          detectionRatio: iocValue.includes('suspicious') ? '5/89' : '0/89',
          categories: iocValue.includes('phish') ? ['phishing'] : ['legitimate'],
          creationDate: '2023-01-15'
        };
      } else if (iocType === 'url') {
        enrichmentData = {
          source: 'URLScan.io',
          reputation: iocValue.includes('malicious') || iocValue.includes('phish') ? 'Malicious' : 'Clean',
          screenshotUrl: 'https://urlscan.io/screenshots/example.png',
          redirects: iocValue.includes('redirect') ? 2 : 0,
          technologies: iocValue.includes('php') ? ['Apache', 'PHP'] : ['nginx', 'JavaScript']
        };
      } else if (iocType === 'hash') {
        enrichmentData = {
          source: 'VirusTotal',
          reputation: iocValue.length === 32 ? 'Malicious' : 'Clean',
          detectionRatio: iocValue.length === 32 ? '45/70' : '0/70',
          fileType: iocValue.length === 32 ? 'PE32 executable' : 'Unknown',
          firstSeen: '2023-12-01'
        };
      }

      res.json({
        success: true,
        iocType,
        iocValue,
        enrichment: enrichmentData
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to enrich IOC" });
    }
  });

  // Audit log routes
  app.get("/api/audit-log", async (req, res) => {
    try {
      const logs = await storage.getAuditLog();
      res.json(logs);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch audit log" });
    }
  });

  app.post("/api/audit-log", async (req, res) => {
    try {
      const logData = insertAuditLogSchema.parse(req.body);
      const log = await storage.createAuditEntry(logData);
      res.status(201).json(log);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to create audit log entry" });
    }
  });

  // Metrics routes
  app.get("/api/metrics/:role", async (req, res) => {
    try {
      const { role } = req.params;
      const alerts = await storage.getAlerts();
      
      const criticalCount = alerts.filter(a => a.severity === 'Critical').length;
      const highCount = alerts.filter(a => a.severity === 'High').length;
      const resolvedToday = alerts.filter(a => a.status === 'Resolved').length;
      const avgResponseTime = Math.floor(Math.random() * 30) + 10;

      let metrics = {};

      if (role === 'executive') {
        metrics = {
          title: 'Executive Risk Dashboard',
          metrics: [
            { label: 'Risk Score', value: '78/100', color: 'text-orange-500' },
            { label: 'Business Impact', value: '$2.3M at risk', color: 'text-red-500' },
            { label: 'Compliance Status', value: '92%', color: 'text-green-500' },
            { label: 'Incidents This Month', value: '47', color: 'text-blue-500' }
          ]
        };
      } else if (role === 'manager') {
        metrics = {
          title: 'SOC Operations Dashboard',
          metrics: [
            { label: 'Team Utilization', value: '87%', color: 'text-purple-500' },
            { label: 'Avg Response Time', value: `${avgResponseTime} min`, color: 'text-yellow-500' },
            { label: 'Resolved Today', value: resolvedToday.toString(), color: 'text-green-500' },
            { label: 'Pending Critical', value: criticalCount.toString(), color: 'text-red-500' }
          ]
        };
      } else {
        metrics = {
          title: 'Analyst Operations Center',
          metrics: [
            { label: 'Critical Alerts', value: criticalCount.toString(), color: 'text-red-500' },
            { label: 'High Priority', value: highCount.toString(), color: 'text-orange-500' },
            { label: 'AI Triaged', value: `${Math.floor(alerts.filter(a => a.aiTriaged).length / alerts.length * 100)}%`, color: 'text-purple-500' },
            { label: 'Active Incidents', value: alerts.filter(a => a.status !== 'Resolved').length.toString(), color: 'text-blue-500' }
          ]
        };
      }

      res.json(metrics);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch metrics" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
