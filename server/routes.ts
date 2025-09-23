import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertAlertSchema, insertAuditLogSchema, insertIOCSchema, insertPlaybookSchema, insertPlaybookActionSchema } from "@shared/schema";
import { threatIntelManager } from "./threat-feeds";
import { correlationEngine } from "./correlation-engine";
import { playbookEngine } from "./playbook-engine";
import { emailService } from "./email-service";
import { siemIntegration } from "./siem-integration";
import { emailAnalysisService } from "./email-analysis";
import { mitreAttackService } from "./mitre-attack";
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
      
      // Trigger automated playbook evaluation for new alert
      playbookEngine.evaluateTriggersForAlert(alert).catch(error => {
        console.error("Failed to evaluate playbook triggers:", error);
      });
      
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

  // Playbook routes
  app.get("/api/playbooks", async (req, res) => {
    try {
      const playbooks = await storage.getPlaybooks();
      res.json(playbooks);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch playbooks" });
    }
  });

  app.get("/api/playbooks/:id", async (req, res) => {
    try {
      const playbook = await storage.getPlaybook(req.params.id);
      if (!playbook) {
        return res.status(404).json({ error: "Playbook not found" });
      }
      res.json(playbook);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch playbook" });
    }
  });

  app.post("/api/playbooks", async (req, res) => {
    try {
      const playbookData = insertPlaybookSchema.parse(req.body);
      const playbook = await storage.createPlaybook(playbookData);
      res.status(201).json(playbook);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to create playbook" });
    }
  });

  app.patch("/api/playbooks/:id", async (req, res) => {
    try {
      const playbook = await storage.updatePlaybook(req.params.id, req.body);
      if (!playbook) {
        return res.status(404).json({ error: "Playbook not found" });
      }
      res.json(playbook);
    } catch (error) {
      res.status(500).json({ error: "Failed to update playbook" });
    }
  });

  app.delete("/api/playbooks/:id", async (req, res) => {
    try {
      const success = await storage.deletePlaybook(req.params.id);
      if (!success) {
        return res.status(404).json({ error: "Playbook not found" });
      }
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ error: "Failed to delete playbook" });
    }
  });

  // Playbook Actions routes
  app.get("/api/playbooks/:id/actions", async (req, res) => {
    try {
      const actions = await storage.getPlaybookActions(req.params.id);
      res.json(actions);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch playbook actions" });
    }
  });

  app.post("/api/playbooks/:id/actions", async (req, res) => {
    try {
      const actionData = insertPlaybookActionSchema.parse({
        ...req.body,
        playbookId: req.params.id
      });
      const action = await storage.createPlaybookAction(actionData);
      res.status(201).json(action);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to create playbook action" });
    }
  });

  // Playbook Executions routes
  app.get("/api/playbook-executions", async (req, res) => {
    try {
      const alertId = req.query.alertId as string;
      const executions = await storage.getPlaybookExecutions(alertId);
      res.json(executions);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch playbook executions" });
    }
  });

  // Manual playbook execution
  app.post("/api/playbooks/:id/execute", async (req, res) => {
    try {
      const { alertId } = req.body;
      if (!alertId) {
        return res.status(400).json({ error: "alertId is required" });
      }

      const playbook = await storage.getPlaybook(req.params.id);
      if (!playbook) {
        return res.status(404).json({ error: "Playbook not found" });
      }

      const alert = await storage.getAlert(alertId);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }

      const execution = await playbookEngine.executePlaybook(playbook, alert, "MANUAL");
      res.status(201).json(execution);
    } catch (error) {
      res.status(500).json({ error: "Failed to execute playbook" });
    }
  });

  // Email Notification routes
  app.get("/api/email/config", async (req, res) => {
    try {
      const config = emailService.getConfig();
      res.json({
        ...config,
        hasApiKey: emailService.hasApiKey(),
        enabled: emailService.isEnabled()
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to get email configuration" });
    }
  });

  app.patch("/api/email/config", async (req, res) => {
    try {
      const updateSchema = z.object({
        enabled: z.boolean().optional(),
        fromEmail: z.string().email().optional(),
        defaultRecipients: z.array(z.string().email()).optional(),
        escalationRecipients: z.array(z.string().email()).optional(),
        criticalRecipients: z.array(z.string().email()).optional()
      });

      const updates = updateSchema.parse(req.body);
      emailService.updateConfig(updates);
      
      res.json({
        success: true,
        config: emailService.getConfig()
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to update email configuration" });
    }
  });

  // Send test email
  app.post("/api/email/test", async (req, res) => {
    try {
      const testSchema = z.object({
        to: z.array(z.string().email()),
        subject: z.string().min(1),
        message: z.string().min(1)
      });

      const { to, subject, message } = testSchema.parse(req.body);
      
      const success = await emailService.sendCustomNotification(
        to,
        `TEST: ${subject}`,
        `This is a test email from Cyber-Sentinel Workbench.\n\n${message}`,
        "normal"
      );

      res.json({
        success,
        message: success ? "Test email sent successfully" : "Failed to send test email",
        simulationMode: !emailService.hasApiKey()
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      res.status(500).json({ error: "Failed to send test email" });
    }
  });

  // Send alert notification manually
  app.post("/api/email/alert-notification", async (req, res) => {
    try {
      const { alertId, type } = req.body;
      if (!alertId) {
        return res.status(400).json({ error: "alertId is required" });
      }

      const alert = await storage.getAlert(alertId);
      if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
      }

      let success = false;
      
      switch (type) {
        case "new":
          success = await emailService.sendNewAlertNotification(alert);
          break;
        case "escalated":
          const reason = req.body.reason || "Manual escalation";
          success = await emailService.sendEscalationNotification(alert, reason);
          break;
        default:
          return res.status(400).json({ error: "Invalid notification type. Use 'new' or 'escalated'" });
      }

      res.json({
        success,
        message: success ? `${type} alert notification sent` : "Failed to send notification",
        simulationMode: !emailService.hasApiKey()
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to send alert notification" });
    }
  });

  // SIEM Integration routes
  app.get("/api/siem/status", async (req, res) => {
    try {
      const connectedPlatforms = siemIntegration.getConnectedPlatforms();
      const statistics = siemIntegration.getStatistics();
      
      res.json({
        connectedPlatforms,
        statistics,
        totalPlatforms: connectedPlatforms.length,
        connectedCount: connectedPlatforms.filter(p => p.connected).length
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to get SIEM status" });
    }
  });

  app.post("/api/siem/connect/:platform", async (req, res) => {
    try {
      const platform = req.params.platform;
      const success = await siemIntegration.connectToPlatform(platform as any);
      
      res.json({
        success,
        message: success ? `Connected to ${platform}` : `Failed to connect to ${platform}`,
        platform
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to connect to SIEM platform" });
    }
  });

  app.post("/api/siem/disconnect/:platform", async (req, res) => {
    try {
      const platform = req.params.platform;
      await siemIntegration.disconnectFromPlatform(platform as any);
      
      res.json({
        success: true,
        message: `Disconnected from ${platform}`,
        platform
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to disconnect from SIEM platform" });
    }
  });

  app.get("/api/siem/test-connections", async (req, res) => {
    try {
      const results = await siemIntegration.testAllConnections();
      res.json({ results });
    } catch (error) {
      res.status(500).json({ error: "Failed to test SIEM connections" });
    }
  });

  app.post("/api/siem/fetch-events/:platform", async (req, res) => {
    try {
      const platform = req.params.platform;
      const { limit = 50 } = req.body;
      
      const events = await siemIntegration.fetchHistoricalEvents(platform as any, undefined, limit);
      
      res.json({
        success: true,
        events,
        count: events.length,
        platform
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch SIEM events" });
    }
  });

  // Email Analysis routes
  const emailAnalysisSchema = z.object({
    email_content: z.string().min(1),
    headers: z.record(z.string()).optional()
  });

  app.post("/api/email/analyze", async (req, res) => {
    try {
      const { email_content, headers } = emailAnalysisSchema.parse(req.body);
      
      console.log(`📧 Received email analysis request for ${email_content.length} characters`);
      
      const result = await emailAnalysisService.analyzeEmail({
        emailContent: email_content,
        headers
      });

      console.log(`✅ Email analysis completed with risk level: ${result.analysis?.risk_score?.risk_level}`);

      // Create an audit log entry for the analysis
      await storage.createAuditLog({
        actor: "USER",
        action: "Email analysis performed",
        metadata: { 
          analysisId: result.id,
          riskLevel: result.analysis?.risk_score?.risk_level || "Unknown",
          primaryIntent: result.analysis?.intent?.primary_intent || "Unknown"
        }
      });

      res.json(result);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ error: error.errors });
      }
      console.error("❌ Email analysis route error:", error);
      res.status(500).json({ 
        error: "Email analysis failed", 
        message: error instanceof Error ? error.message : "Unknown error" 
      });
    }
  });

  app.get("/api/email/analysis/:id", async (req, res) => {
    try {
      // In a real implementation, you'd store analysis results
      // For now, return a placeholder response
      res.status(404).json({ error: "Analysis not found - results are not persisted" });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch analysis" });
    }
  });

  // MITRE ATT&CK API routes
  app.get("/api/mitre/technique/:id", async (req, res) => {
    try {
      const technique = await mitreAttackService.getTechnique(req.params.id);
      if (!technique) {
        return res.status(404).json({ error: "Technique not found" });
      }
      res.json(technique);
    } catch (error) {
      console.error("MITRE technique lookup error:", error);
      res.status(500).json({ error: "Failed to fetch technique data" });
    }
  });

  app.get("/api/mitre/tactic/:id", async (req, res) => {
    try {
      const tactic = await mitreAttackService.getTactic(req.params.id);
      if (!tactic) {
        return res.status(404).json({ error: "Tactic not found" });
      }
      res.json(tactic);
    } catch (error) {
      console.error("MITRE tactic lookup error:", error);
      res.status(500).json({ error: "Failed to fetch tactic data" });
    }
  });

  app.get("/api/mitre/tactics", async (req, res) => {
    try {
      const tactics = await mitreAttackService.getAllTactics();
      res.json(tactics);
    } catch (error) {
      console.error("MITRE tactics lookup error:", error);
      res.status(500).json({ error: "Failed to fetch tactics data" });
    }
  });

  app.get("/api/mitre/search", async (req, res) => {
    try {
      const query = req.query.q as string;
      const limit = parseInt(req.query.limit as string) || 10;
      
      if (!query) {
        return res.status(400).json({ error: "Query parameter 'q' is required" });
      }

      const techniques = await mitreAttackService.searchTechniques(query, limit);
      res.json(techniques);
    } catch (error) {
      console.error("MITRE search error:", error);
      res.status(500).json({ error: "Failed to search MITRE data" });
    }
  });

  app.get("/api/mitre/status", async (req, res) => {
    try {
      const status = mitreAttackService.getStatus();
      res.json(status);
    } catch (error) {
      console.error("MITRE status error:", error);
      res.status(500).json({ error: "Failed to get MITRE service status" });
    }
  });

  app.post("/api/mitre/refresh", async (req, res) => {
    try {
      await mitreAttackService.refresh();
      res.json({ message: "MITRE ATT&CK data refreshed successfully" });
    } catch (error) {
      console.error("MITRE refresh error:", error);
      res.status(500).json({ error: "Failed to refresh MITRE data" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
