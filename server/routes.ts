import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertAlertSchema, insertAuditLogSchema, insertIOCSchema } from "@shared/schema";
import { threatIntelManager } from "./threat-feeds";
import { correlationEngine } from "./correlation-engine";
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
      let intel = await storage.getThreatIntelligence(req.params.alertId);
      
      if (!intel) {
        // Get alert to extract IOCs for enrichment
        const alert = await storage.getAlert(req.params.alertId);
        if (!alert) {
          return res.status(404).json({ error: "Alert not found" });
        }

        // Extract IOCs from alert description for real-time enrichment
        const iocExtractPatterns = {
          ip: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
          domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
          url: /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g,
          hash: /\b[a-fA-F0-9]{32,64}\b/g
        };

        const extractedIOCs: string[] = [];
        const text = `${alert.title} ${alert.description || ''}`;
        
        Object.values(iocExtractPatterns).forEach(pattern => {
          const matches = text.match(pattern);
          if (matches) {
            extractedIOCs.push(...matches);
          }
        });

        // Add some sample IOCs for demonstration if none found
        if (extractedIOCs.length === 0) {
          extractedIOCs.push(
            '45.77.156.22',
            'suspicious-domain.com',
            'a1b2c3d4e5f6789012345678901234567890abcdefghijklmnopqrstuvwxyz1234'
          );
        }

        // Generate real-time threat intelligence
        const intelData = await threatIntelManager.aggregateThreatIntelligence(
          req.params.alertId,
          extractedIOCs
        );

        // Save the enriched data to database
        intel = await storage.createThreatIntelligence(intelData);
      }

      res.json(intel);
    } catch (error) {
      console.error('Threat intelligence error:', error);
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

      // Use real-time threat intelligence enrichment
      const enrichmentData = await threatIntelManager.enrichIOC(iocValue, iocType);
      
      // Return aggregated enrichment data from multiple sources
      const aggregatedData = enrichmentData.length > 0 ? {
        source: enrichmentData.map(d => d.sources).flat().join(', '),
        reputation: enrichmentData[0].reputation,
        maliciousScore: Math.round(enrichmentData.reduce((sum, d) => sum + d.maliciousScore, 0) / enrichmentData.length),
        confidence: Math.round(enrichmentData.reduce((sum, d) => sum + d.confidence, 0) / enrichmentData.length),
        threatActor: enrichmentData.find(d => d.threatActor)?.threatActor || 'Unknown',
        campaign: enrichmentData.find(d => d.campaign)?.campaign || 'Unknown',
        tags: [...new Set(enrichmentData.flatMap(d => d.tags))],
        sources: [...new Set(enrichmentData.flatMap(d => d.sources))],
        firstSeen: new Date(Math.min(...enrichmentData.map(d => d.firstSeen.getTime()))).toISOString(),
        lastSeen: new Date(Math.max(...enrichmentData.map(d => d.lastSeen.getTime()))).toISOString()
      } : {
        source: 'No data available',
        reputation: 'Unknown',
        maliciousScore: 0,
        confidence: 0,
        threatActor: 'Unknown',
        campaign: 'Unknown',
        tags: [],
        sources: [],
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString()
      };

      res.json({
        success: true,
        iocType,
        iocValue,
        enrichment: aggregatedData
      });
    } catch (error) {
      console.error('IOC enrichment error:', error);
      res.status(500).json({ error: "Failed to enrich IOC" });
    }
  });

  // Threat feed management routes
  app.get("/api/threat-feeds/status", async (req, res) => {
    try {
      const feedStatus = threatIntelManager.getFeedStatus();
      res.json({
        success: true,
        feeds: feedStatus,
        totalFeeds: feedStatus.length,
        activeFeeds: feedStatus.filter(f => f.enabled).length
      });
    } catch (error) {
      console.error('Feed status error:', error);
      res.status(500).json({ error: "Failed to get threat feed status" });
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

  // Correlation Engine routes
  app.get("/api/correlations/:alertId", async (req, res) => {
    try {
      const analysis = await correlationEngine.analyzeAlert(req.params.alertId);
      res.json(analysis);
    } catch (error) {
      if (error instanceof Error && error.message.includes("not found")) {
        return res.status(404).json({ error: error.message });
      }
      res.status(500).json({ error: "Failed to analyze correlations" });
    }
  });

  app.get("/api/correlations/:alertId/stored", async (req, res) => {
    try {
      const correlations = await storage.getCorrelations(req.params.alertId);
      res.json(correlations);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch stored correlations" });
    }
  });

  app.post("/api/correlations/batch-analyze", async (req, res) => {
    try {
      await correlationEngine.runBatchCorrelationAnalysis();
      res.json({ success: true, message: "Batch correlation analysis completed" });
    } catch (error) {
      res.status(500).json({ error: "Failed to run batch correlation analysis" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
