import { storage } from "./storage";
import { type Alert, type Playbook, type PlaybookAction, type PlaybookExecution } from "@shared/schema";

// Action Types for Automated Incident Response
export interface ActionConfig {
  // Isolation Actions
  isolate_host?: {
    hostId: string;
    duration?: number; // minutes
    notify?: string[];
  };
  
  // Notification Actions
  send_notification?: {
    recipients: string[];
    severity: "low" | "medium" | "high" | "critical";
    template: string;
    customMessage?: string;
  };
  
  // Escalation Actions
  escalate?: {
    to: string;
    escalationLevel: number;
    reason: string;
  };
  
  // Network Security Actions
  block_ip?: {
    ipAddress: string;
    duration?: number; // minutes
    blockType: "firewall" | "waf" | "endpoint";
  };
  
  // File Security Actions
  quarantine_file?: {
    filePath: string;
    hash: string;
    hostId: string;
  };
  
  // Ticketing Actions
  create_ticket?: {
    system: "jira" | "servicenow" | "zendesk";
    priority: "low" | "medium" | "high" | "critical";
    assignee?: string;
    description: string;
  };
}

export interface ActionResult {
  actionId: string;
  actionType: string;
  status: "success" | "failed" | "pending";
  message: string;
  executedAt: Date;
  error?: string;
}

export class PlaybookEngine {
  private async checkTriggerConditions(alert: Alert, playbook: Playbook): Promise<boolean> {
    try {
      const conditions = playbook.triggerConditions as any;
      
      // Check severity match
      if (playbook.severity && playbook.severity !== alert.severity) {
        return false;
      }
      
      // Check alert type match
      if (playbook.alertTypes) {
        const allowedTypes = playbook.alertTypes as string[];
        if (!allowedTypes.includes(alert.type)) {
          return false;
        }
      }
      
      // Check custom conditions
      if (conditions.minConfidence && alert.confidence && alert.confidence < conditions.minConfidence) {
        return false;
      }
      
      if (conditions.businessImpact && alert.businessImpact !== conditions.businessImpact) {
        return false;
      }
      
      if (conditions.affectedAssetsThreshold && alert.affectedAssets && alert.affectedAssets < conditions.affectedAssetsThreshold) {
        return false;
      }
      
      return true;
    } catch (error) {
      console.error("Error checking trigger conditions:", error);
      return false;
    }
  }

  private async executeAction(action: PlaybookAction, alert: Alert): Promise<ActionResult> {
    const config = action.actionConfig as ActionConfig;
    
    try {
      switch (action.actionType) {
        case "isolate_host":
          return await this.executeIsolateHost(action, config.isolate_host!, alert);
        
        case "send_notification":
          return await this.executeSendNotification(action, config.send_notification!, alert);
        
        case "escalate":
          return await this.executeEscalate(action, config.escalate!, alert);
        
        case "block_ip":
          return await this.executeBlockIP(action, config.block_ip!, alert);
        
        case "quarantine_file":
          return await this.executeQuarantineFile(action, config.quarantine_file!, alert);
        
        case "create_ticket":
          return await this.executeCreateTicket(action, config.create_ticket!, alert);
        
        default:
          return {
            actionId: action.id,
            actionType: action.actionType,
            status: "failed",
            message: `Unknown action type: ${action.actionType}`,
            executedAt: new Date(),
            error: "Unsupported action type"
          };
      }
    } catch (error) {
      return {
        actionId: action.id,
        actionType: action.actionType,
        status: "failed",
        message: `Action execution failed: ${error}`,
        executedAt: new Date(),
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  private async executeIsolateHost(action: PlaybookAction, config: ActionConfig["isolate_host"], alert: Alert): Promise<ActionResult> {
    // Simulate host isolation - in real implementation, this would integrate with endpoint security tools
    console.log(`[PLAYBOOK] Isolating host ${config!.hostId} for alert ${alert.id}`);
    
    return {
      actionId: action.id,
      actionType: "isolate_host",
      status: "success",
      message: `Host ${config!.hostId} isolated successfully for ${config!.duration || 60} minutes`,
      executedAt: new Date()
    };
  }

  private async executeSendNotification(action: PlaybookAction, config: ActionConfig["send_notification"], alert: Alert): Promise<ActionResult> {
    // Simulate sending notification - in real implementation, this would integrate with email/SMS services
    console.log(`[PLAYBOOK] Sending ${config!.severity} notification for alert ${alert.id} to:`, config!.recipients);
    
    return {
      actionId: action.id,
      actionType: "send_notification",
      status: "success",
      message: `Notification sent to ${config!.recipients.length} recipients`,
      executedAt: new Date()
    };
  }

  private async executeEscalate(action: PlaybookAction, config: ActionConfig["escalate"], alert: Alert): Promise<ActionResult> {
    // Simulate escalation - in real implementation, this would update assignment and notify managers
    console.log(`[PLAYBOOK] Escalating alert ${alert.id} to ${config!.to} at level ${config!.escalationLevel}`);
    
    // Update alert assignee
    await storage.updateAlert(alert.id, { assignee: config!.to });
    
    return {
      actionId: action.id,
      actionType: "escalate",
      status: "success",
      message: `Alert escalated to ${config!.to} - ${config!.reason}`,
      executedAt: new Date()
    };
  }

  private async executeBlockIP(action: PlaybookAction, config: ActionConfig["block_ip"], alert: Alert): Promise<ActionResult> {
    // Simulate IP blocking - in real implementation, this would integrate with firewall/WAF APIs
    console.log(`[PLAYBOOK] Blocking IP ${config!.ipAddress} via ${config!.blockType} for alert ${alert.id}`);
    
    return {
      actionId: action.id,
      actionType: "block_ip",
      status: "success",
      message: `IP ${config!.ipAddress} blocked via ${config!.blockType} for ${config!.duration || 60} minutes`,
      executedAt: new Date()
    };
  }

  private async executeQuarantineFile(action: PlaybookAction, config: ActionConfig["quarantine_file"], alert: Alert): Promise<ActionResult> {
    // Simulate file quarantine - in real implementation, this would integrate with endpoint security
    console.log(`[PLAYBOOK] Quarantining file ${config!.filePath} (${config!.hash}) on host ${config!.hostId}`);
    
    return {
      actionId: action.id,
      actionType: "quarantine_file",
      status: "success",
      message: `File ${config!.filePath} quarantined on host ${config!.hostId}`,
      executedAt: new Date()
    };
  }

  private async executeCreateTicket(action: PlaybookAction, config: ActionConfig["create_ticket"], alert: Alert): Promise<ActionResult> {
    // Simulate ticket creation - in real implementation, this would integrate with ticketing systems
    const ticketId = `TICKET-${Date.now()}`;
    console.log(`[PLAYBOOK] Creating ${config!.priority} ticket ${ticketId} in ${config!.system} for alert ${alert.id}`);
    
    return {
      actionId: action.id,
      actionType: "create_ticket",
      status: "success",
      message: `Ticket ${ticketId} created in ${config!.system} with priority ${config!.priority}`,
      executedAt: new Date()
    };
  }

  async executePlaybook(playbook: Playbook, alert: Alert, triggeredBy: string = "AUTO"): Promise<PlaybookExecution> {
    console.log(`[PLAYBOOK] Starting execution of playbook "${playbook.name}" for alert ${alert.id}`);
    
    // Create execution record
    const execution = await storage.createPlaybookExecution({
      playbookId: playbook.id,
      alertId: alert.id,
      status: "Running",
      triggeredBy,
      executionResults: { results: [] }
    });

    try {
      // Get playbook actions in order
      const actions = await storage.getPlaybookActions(playbook.id);
      const results: ActionResult[] = [];

      // Execute actions sequentially
      for (const action of actions) {
        console.log(`[PLAYBOOK] Executing action ${action.actionOrder}: ${action.actionType}`);
        
        // Check if action requires manual approval
        if (!action.isAutomated) {
          console.log(`[PLAYBOOK] Action ${action.actionType} requires manual approval`);
          await storage.updatePlaybookExecution(execution.id, {
            status: "Pending_Approval",
            executionResults: { results, pendingAction: action.id }
          });
          return execution;
        }

        const result = await this.executeAction(action, alert);
        results.push(result);

        // If action failed and it's critical, stop execution
        if (result.status === "failed") {
          console.error(`[PLAYBOOK] Action ${action.actionType} failed:`, result.error);
          await storage.updatePlaybookExecution(execution.id, {
            status: "Failed",
            completedAt: new Date(),
            executionResults: { results },
            errorMessage: result.error
          });
          return execution;
        }
      }

      // Mark execution as completed
      await storage.updatePlaybookExecution(execution.id, {
        status: "Completed",
        completedAt: new Date(),
        executionResults: { results }
      });

      console.log(`[PLAYBOOK] Successfully completed playbook "${playbook.name}" for alert ${alert.id}`);
      
      // Log audit entry
      await storage.createAuditEntry({
        actor: "SYSTEM",
        action: `Executed playbook "${playbook.name}" with ${results.length} actions`,
        alertId: alert.id,
        metadata: { playbookId: playbook.id, executionId: execution.id }
      });

      return execution;
    } catch (error) {
      console.error(`[PLAYBOOK] Execution failed for playbook "${playbook.name}":`, error);
      
      await storage.updatePlaybookExecution(execution.id, {
        status: "Failed",
        completedAt: new Date(),
        errorMessage: error instanceof Error ? error.message : String(error)
      });
      
      return execution;
    }
  }

  async evaluateTriggersForAlert(alert: Alert): Promise<PlaybookExecution[]> {
    try {
      // Get all enabled playbooks
      const playbooks = await storage.getPlaybooks();
      const enabledPlaybooks = playbooks.filter(p => p.enabled);
      
      console.log(`[PLAYBOOK] Evaluating ${enabledPlaybooks.length} playbooks for alert ${alert.id}`);
      
      const executions: PlaybookExecution[] = [];
      
      // Check each playbook's trigger conditions
      for (const playbook of enabledPlaybooks) {
        if (await this.checkTriggerConditions(alert, playbook)) {
          console.log(`[PLAYBOOK] Trigger conditions met for playbook "${playbook.name}"`);
          const execution = await this.executePlaybook(playbook, alert, "AUTO");
          executions.push(execution);
        }
      }
      
      console.log(`[PLAYBOOK] Triggered ${executions.length} playbooks for alert ${alert.id}`);
      return executions;
    } catch (error) {
      console.error("[PLAYBOOK] Error evaluating triggers:", error);
      return [];
    }
  }

  async initializeSamplePlaybooks(): Promise<void> {
    try {
      // Check if playbooks already exist
      const existingPlaybooks = await storage.getPlaybooks();
      if (existingPlaybooks.length > 0) return;

      console.log("[PLAYBOOK] Initializing sample playbooks...");

      // Critical Alert Response Playbook
      const criticalPlaybook = await storage.createPlaybook({
        name: "Critical Alert Response",
        description: "Automated response for critical security alerts including isolation and escalation",
        triggerConditions: { minConfidence: 90 },
        enabled: true,
        severity: "Critical",
        alertTypes: ["Malware Detection", "Data Exfiltration Attempt"],
        createdBy: "SYSTEM"
      });

      // Add actions to critical playbook
      await storage.createPlaybookAction({
        playbookId: criticalPlaybook.id,
        actionType: "send_notification",
        actionOrder: 1,
        actionConfig: {
          send_notification: {
            recipients: ["security-team@company.com", "soc-manager@company.com"],
            severity: "critical",
            template: "critical_alert",
            customMessage: "Critical security alert detected requiring immediate attention"
          }
        },
        isAutomated: true
      });

      await storage.createPlaybookAction({
        playbookId: criticalPlaybook.id,
        actionType: "isolate_host",
        actionOrder: 2,
        actionConfig: {
          isolate_host: {
            hostId: "AUTO_DETECT",
            duration: 120,
            notify: ["security-team@company.com"]
          }
        },
        isAutomated: true
      });

      await storage.createPlaybookAction({
        playbookId: criticalPlaybook.id,
        actionType: "escalate",
        actionOrder: 3,
        actionConfig: {
          escalate: {
            to: "Security Manager",
            escalationLevel: 2,
            reason: "Critical alert requires manager review"
          }
        },
        isAutomated: true
      });

      // Phishing Response Playbook
      const phishingPlaybook = await storage.createPlaybook({
        name: "Phishing Response",
        description: "Automated response for phishing attacks including user notification and email blocking",
        triggerConditions: { minConfidence: 80 },
        enabled: true,
        severity: "High",
        alertTypes: ["Phishing Email Campaign"],
        createdBy: "SYSTEM"
      });

      await storage.createPlaybookAction({
        playbookId: phishingPlaybook.id,
        actionType: "send_notification",
        actionOrder: 1,
        actionConfig: {
          send_notification: {
            recipients: ["security-team@company.com"],
            severity: "high",
            template: "phishing_alert",
            customMessage: "Phishing campaign detected - investigating and blocking"
          }
        },
        isAutomated: true
      });

      await storage.createPlaybookAction({
        playbookId: phishingPlaybook.id,
        actionType: "block_ip",
        actionOrder: 2,
        actionConfig: {
          block_ip: {
            ipAddress: "AUTO_DETECT",
            duration: 240,
            blockType: "firewall"
          }
        },
        isAutomated: true
      });

      await storage.createPlaybookAction({
        playbookId: phishingPlaybook.id,
        actionType: "create_ticket",
        actionOrder: 3,
        actionConfig: {
          create_ticket: {
            system: "jira",
            priority: "high",
            assignee: "Security Analyst",
            description: "Phishing campaign detected - full investigation required"
          }
        },
        isAutomated: true
      });

      console.log("[PLAYBOOK] Sample playbooks initialized successfully");
    } catch (error) {
      console.error("[PLAYBOOK] Error initializing sample playbooks:", error);
    }
  }
}

export const playbookEngine = new PlaybookEngine();