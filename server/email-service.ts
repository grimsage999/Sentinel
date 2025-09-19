// Email service for cybersecurity workbench notifications
// Based on SendGrid integration blueprint

import { type Alert, type PlaybookExecution } from "@shared/schema";

// SendGrid integration - gracefully handles missing API key
let mailService: any = null;
try {
  if (process.env.SENDGRID_API_KEY) {
    const { MailService } = require('@sendgrid/mail');
    mailService = new MailService();
    mailService.setApiKey(process.env.SENDGRID_API_KEY);
  }
} catch (error) {
  console.log("[EMAIL] SendGrid not available, using simulation mode");
}

export interface EmailParams {
  to: string | string[];
  from: string;
  subject: string;
  text?: string;
  html?: string;
  priority?: "low" | "normal" | "high" | "critical";
}

export interface NotificationConfig {
  enabled: boolean;
  fromEmail: string;
  defaultRecipients: string[];
  escalationRecipients: string[];
  criticalRecipients: string[];
}

class EmailNotificationService {
  private config: NotificationConfig = {
    enabled: true,
    fromEmail: "security-alerts@cyber-sentinel.com",
    defaultRecipients: ["security-team@company.com"],
    escalationRecipients: ["security-manager@company.com", "incident-response@company.com"],
    criticalRecipients: ["security-team@company.com", "security-manager@company.com", "ciso@company.com"]
  };

  private async sendEmail(params: EmailParams): Promise<boolean> {
    if (!this.config.enabled) {
      console.log("[EMAIL] Email notifications disabled");
      return false;
    }

    // Convert single recipient to array
    const recipients = Array.isArray(params.to) ? params.to : [params.to];

    try {
      if (mailService && process.env.SENDGRID_API_KEY) {
        // Real SendGrid email sending
        console.log(`[EMAIL] Sending ${params.priority || 'normal'} priority email to:`, recipients);
        
        for (const recipient of recipients) {
          await mailService.send({
            to: recipient,
            from: params.from,
            subject: params.subject,
            text: params.text,
            html: params.html,
          });
        }
        
        console.log(`[EMAIL] Successfully sent email to ${recipients.length} recipients`);
        return true;
      } else {
        // Simulation mode - log the email content
        console.log(`[EMAIL] SIMULATION MODE - Email would be sent:`);
        console.log(`  To: ${recipients.join(', ')}`);
        console.log(`  From: ${params.from}`);
        console.log(`  Subject: ${params.subject}`);
        console.log(`  Priority: ${params.priority || 'normal'}`);
        if (params.text) {
          console.log(`  Text Content:\n${params.text}`);
        }
        return true;
      }
    } catch (error) {
      console.error('[EMAIL] Failed to send email:', error);
      return false;
    }
  }

  private generateAlertEmailTemplate(alert: Alert, type: 'new' | 'escalated' | 'resolved'): { subject: string; text: string; html: string } {
    const severityEmoji = {
      'Critical': '🔴',
      'High': '🟠', 
      'Medium': '🟡',
      'Low': '🔵'
    }[alert.severity] || '⚪';

    const typeEmoji = {
      'Malware Detection': '🦠',
      'Phishing Email Campaign': '🎣',
      'Data Exfiltration Attempt': '📤',
      'Suspicious Login Activity': '🔐',
      'Network Intrusion': '🌐',
      'Ransomware': '💰'
    }[alert.type] || '⚠️';

    let subject: string;
    let actionText: string;
    
    switch (type) {
      case 'new':
        subject = `${severityEmoji} NEW ${alert.severity.toUpperCase()} ALERT: ${alert.title}`;
        actionText = 'A new security alert has been detected and requires investigation.';
        break;
      case 'escalated':
        subject = `${severityEmoji} ESCALATED: ${alert.title}`;
        actionText = 'This security alert has been escalated and requires immediate attention.';
        break;
      case 'resolved':
        subject = `✅ RESOLVED: ${alert.title}`;
        actionText = 'This security alert has been resolved.';
        break;
    }

    const text = `
CYBER-SENTINEL WORKBENCH ALERT

${actionText}

ALERT DETAILS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Alert ID: ${alert.id}
Type: ${typeEmoji} ${alert.type}
Severity: ${severityEmoji} ${alert.severity}
Status: ${alert.status}
Source: ${alert.source}
Timestamp: ${alert.timestamp}

Title: ${alert.title}
Description: ${alert.description || 'No description available'}

IMPACT ASSESSMENT:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Business Impact: ${alert.businessImpact || 'Unknown'}
Affected Assets: ${alert.affectedAssets || 'Unknown'}
AI Confidence: ${alert.confidence || 'Unknown'}%
Assigned To: ${alert.assignee || 'Unassigned'}
AI Triaged: ${alert.aiTriaged ? 'Yes' : 'No'}

NEXT STEPS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Review alert details in the Cyber-Sentinel Workbench
2. Investigate associated IOCs and threat intelligence
3. Check correlation analysis for related incidents
4. Follow appropriate incident response procedures

Access the full alert details at: [Dashboard Link]

This is an automated notification from Cyber-Sentinel Workbench.
Do not reply to this email.
    `.trim();

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #1e40af, #3b82f6); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .alert-badge { display: inline-block; padding: 8px 16px; border-radius: 20px; font-weight: bold; margin: 10px 0; }
        .critical { background: #dc2626; color: white; }
        .high { background: #ea580c; color: white; }
        .medium { background: #d97706; color: white; }
        .low { background: #2563eb; color: white; }
        .details { background: #f8fafc; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #3b82f6; }
        .impact { background: #fef3c7; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f59e0b; }
        .actions { background: #ecfdf5; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #10b981; }
        .footer { color: #6b7280; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; }
        .emoji { font-size: 1.2em; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        td { padding: 8px 0; border-bottom: 1px solid #e5e7eb; }
        .label { font-weight: bold; width: 30%; color: #4b5563; }
    </style>
</head>
<body>
    <div class="header">
        <h1>${severityEmoji} Cyber-Sentinel Workbench Alert</h1>
        <p><strong>${actionText}</strong></p>
    </div>

    <div class="alert-badge ${alert.severity.toLowerCase()}">
        ${typeEmoji} ${alert.severity.toUpperCase()} PRIORITY
    </div>

    <div class="details">
        <h2>Alert Details</h2>
        <table>
            <tr><td class="label">Alert ID:</td><td><strong>${alert.id}</strong></td></tr>
            <tr><td class="label">Type:</td><td>${typeEmoji} ${alert.type}</td></tr>
            <tr><td class="label">Severity:</td><td>${severityEmoji} ${alert.severity}</td></tr>
            <tr><td class="label">Status:</td><td>${alert.status}</td></tr>
            <tr><td class="label">Source:</td><td>${alert.source}</td></tr>
            <tr><td class="label">Timestamp:</td><td>${alert.timestamp}</td></tr>
        </table>
        
        <h3>Description</h3>
        <p><strong>${alert.title}</strong></p>
        <p>${alert.description || 'No description available'}</p>
    </div>

    <div class="impact">
        <h2>Impact Assessment</h2>
        <table>
            <tr><td class="label">Business Impact:</td><td>${alert.businessImpact || 'Unknown'}</td></tr>
            <tr><td class="label">Affected Assets:</td><td>${alert.affectedAssets || 'Unknown'}</td></tr>
            <tr><td class="label">AI Confidence:</td><td>${alert.confidence || 'Unknown'}%</td></tr>
            <tr><td class="label">Assigned To:</td><td>${alert.assignee || 'Unassigned'}</td></tr>
            <tr><td class="label">AI Triaged:</td><td>${alert.aiTriaged ? 'Yes' : 'No'}</td></tr>
        </table>
    </div>

    <div class="actions">
        <h2>Next Steps</h2>
        <ol>
            <li>Review alert details in the Cyber-Sentinel Workbench</li>
            <li>Investigate associated IOCs and threat intelligence</li>
            <li>Check correlation analysis for related incidents</li>
            <li>Follow appropriate incident response procedures</li>
        </ol>
    </div>

    <div class="footer">
        <p>This is an automated notification from Cyber-Sentinel Workbench.<br>
        Do not reply to this email.</p>
    </div>
</body>
</html>
    `.trim();

    return { subject, text, html };
  }

  private generatePlaybookExecutionTemplate(execution: PlaybookExecution, alert: Alert, playbookName: string): { subject: string; text: string; html: string } {
    const statusEmoji = {
      'Running': '⏳',
      'Completed': '✅',
      'Failed': '❌',
      'Pending_Approval': '⏸️'
    }[execution.status] || '❓';

    const subject = `${statusEmoji} Playbook ${execution.status}: ${playbookName} for Alert ${alert.id}`;

    const text = `
AUTOMATED PLAYBOOK EXECUTION NOTIFICATION

${statusEmoji} Playbook Status: ${execution.status}

EXECUTION DETAILS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Playbook: ${playbookName}
Alert ID: ${alert.id}
Alert Title: ${alert.title}
Execution ID: ${execution.id}
Triggered By: ${execution.triggeredBy}
Started At: ${execution.startedAt}
${execution.completedAt ? `Completed At: ${execution.completedAt}` : ''}
${execution.errorMessage ? `Error: ${execution.errorMessage}` : ''}

AUTOMATED ACTIONS PERFORMED:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${execution.executionResults ? 
  JSON.stringify(execution.executionResults, null, 2) : 
  'No execution results available'
}

This automated response was triggered to help contain and investigate the security incident.

Access the full details at: [Dashboard Link]

This is an automated notification from Cyber-Sentinel Workbench.
Do not reply to this email.
    `.trim();

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #059669, #10b981); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .status { display: inline-block; padding: 10px 20px; border-radius: 25px; font-weight: bold; margin: 10px 0; }
        .running { background: #fbbf24; color: white; }
        .completed { background: #10b981; color: white; }
        .failed { background: #dc2626; color: white; }
        .pending { background: #6b7280; color: white; }
        .details { background: #f8fafc; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #10b981; }
        .actions { background: #ecfdf5; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #10b981; }
        .footer { color: #6b7280; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        td { padding: 8px 0; border-bottom: 1px solid #e5e7eb; }
        .label { font-weight: bold; width: 30%; color: #4b5563; }
        pre { background: #f3f4f6; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🤖 Automated Playbook Execution</h1>
        <p>Incident response automation has been triggered</p>
    </div>

    <div class="status ${execution.status.toLowerCase()}">
        ${statusEmoji} ${execution.status.toUpperCase()}
    </div>

    <div class="details">
        <h2>Execution Details</h2>
        <table>
            <tr><td class="label">Playbook:</td><td><strong>${playbookName}</strong></td></tr>
            <tr><td class="label">Alert ID:</td><td>${alert.id}</td></tr>
            <tr><td class="label">Alert Title:</td><td>${alert.title}</td></tr>
            <tr><td class="label">Execution ID:</td><td>${execution.id}</td></tr>
            <tr><td class="label">Triggered By:</td><td>${execution.triggeredBy}</td></tr>
            <tr><td class="label">Started At:</td><td>${execution.startedAt}</td></tr>
            ${execution.completedAt ? `<tr><td class="label">Completed At:</td><td>${execution.completedAt}</td></tr>` : ''}
            ${execution.errorMessage ? `<tr><td class="label">Error:</td><td style="color: #dc2626;">${execution.errorMessage}</td></tr>` : ''}
        </table>
    </div>

    <div class="actions">
        <h2>Automated Actions Performed</h2>
        <pre>${execution.executionResults ? 
          JSON.stringify(execution.executionResults, null, 2) : 
          'No execution results available'
        }</pre>
        <p><em>This automated response was triggered to help contain and investigate the security incident.</em></p>
    </div>

    <div class="footer">
        <p>This is an automated notification from Cyber-Sentinel Workbench.<br>
        Do not reply to this email.</p>
    </div>
</body>
</html>
    `.trim();

    return { subject, text, html };
  }

  // Public methods for different notification types
  async sendNewAlertNotification(alert: Alert): Promise<boolean> {
    const template = this.generateAlertEmailTemplate(alert, 'new');
    
    let recipients: string[];
    if (alert.severity === 'Critical') {
      recipients = this.config.criticalRecipients;
    } else {
      recipients = this.config.defaultRecipients;
    }

    return await this.sendEmail({
      to: recipients,
      from: this.config.fromEmail,
      subject: template.subject,
      text: template.text,
      html: template.html,
      priority: alert.severity === 'Critical' ? 'critical' : 
               alert.severity === 'High' ? 'high' : 'normal'
    });
  }

  async sendEscalationNotification(alert: Alert, reason: string): Promise<boolean> {
    const template = this.generateAlertEmailTemplate(alert, 'escalated');
    
    // Add escalation reason to the template
    template.text += `\n\nESCALATION REASON:\n${reason}`;
    template.html = template.html.replace(
      '<div class="footer">',
      `<div style="background: #fef2f2; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #dc2626;">
        <h3 style="color: #dc2626; margin-top: 0;">Escalation Reason</h3>
        <p>${reason}</p>
      </div><div class="footer">`
    );

    return await this.sendEmail({
      to: this.config.escalationRecipients,
      from: this.config.fromEmail,
      subject: template.subject,
      text: template.text,
      html: template.html,
      priority: 'high'
    });
  }

  async sendPlaybookExecutionNotification(execution: PlaybookExecution, alert: Alert, playbookName: string): Promise<boolean> {
    const template = this.generatePlaybookExecutionTemplate(execution, alert, playbookName);

    return await this.sendEmail({
      to: this.config.defaultRecipients,
      from: this.config.fromEmail,
      subject: template.subject,
      text: template.text,
      html: template.html,
      priority: execution.status === 'Failed' ? 'high' : 'normal'
    });
  }

  async sendCustomNotification(recipients: string[], subject: string, message: string, priority: EmailParams['priority'] = 'normal'): Promise<boolean> {
    return await this.sendEmail({
      to: recipients,
      from: this.config.fromEmail,
      subject: `[Cyber-Sentinel] ${subject}`,
      text: message,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: #1e40af; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
            <h1>Cyber-Sentinel Workbench</h1>
          </div>
          <div style="background: #f8fafc; padding: 20px; border-radius: 8px; border-left: 4px solid #3b82f6;">
            <p style="white-space: pre-line;">${message}</p>
          </div>
          <div style="color: #6b7280; font-size: 12px; margin-top: 20px;">
            <p>This is an automated notification from Cyber-Sentinel Workbench.</p>
          </div>
        </div>
      `,
      priority
    });
  }

  // Configuration methods
  updateConfig(newConfig: Partial<NotificationConfig>): void {
    this.config = { ...this.config, ...newConfig };
    console.log("[EMAIL] Email configuration updated:", this.config);
  }

  getConfig(): NotificationConfig {
    return { ...this.config };
  }

  isEnabled(): boolean {
    return this.config.enabled;
  }

  hasApiKey(): boolean {
    return !!process.env.SENDGRID_API_KEY;
  }
}

export const emailService = new EmailNotificationService();