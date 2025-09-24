import { Plus, Share, Download, Globe, Users, BarChart3, Copy, Mail, FileDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";
import type { AuditLog } from "@shared/schema";

interface RightPanelProps {
  auditLog: AuditLog[];
}

export default function RightPanel({ auditLog }: RightPanelProps) {
  const { toast } = useToast();
  const [isExporting, setIsExporting] = useState(false);

  const systemStatus = [
    { name: "Email Gateway", status: "Online", color: "bg-green-500" },
    { name: "SIEM Platform", status: "Online", color: "bg-green-500" },
    { name: "EDR Agents", status: "98.2%", color: "bg-yellow-500" }
  ];

  const handleCreateIncident = async () => {
    try {
      const incidentData = {
        title: `Security Incident ${new Date().toISOString().split('T')[0]}`,
        description: "New security incident created from dashboard",
        severity: "High",
        assignee: "Alex Chen",
        tags: ["urgent", "dashboard-created"],
        relatedAlerts: auditLog.slice(0, 3).map(log => log.id)
      };

      const response = await fetch('/api/incidents', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(incidentData)
      });

      if (!response.ok) {
        throw new Error('Failed to create incident');
      }

      const incident = await response.json();

      toast({
        title: "🚨 Incident Created Successfully",
        description: `Incident "${incident.title}" (#${incident.id.split('-')[1]}) has been assigned to ${incident.assignee}.`,
      });
      
    } catch (error) {
      console.error('Failed to create incident:', error);
      toast({
        title: "❌ Creation Failed",
        description: "Unable to create security incident. Please verify system connectivity and try again.",
        variant: "destructive",
      });
    }
  };

  const handleShareAlert = async () => {
    try {
      const currentUrl = window.location.href;
      const shareData = {
        type: "dashboard",
        resourceId: "current-view",
        shareUrl: currentUrl,
        sharedWith: ["team@company.com"],
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      };

      // Call API to log the share action
      const response = await fetch('/api/share', {
        method: 'POST', 
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(shareData)
      });

      if (response.ok) {
        await navigator.clipboard.writeText(currentUrl);
        
        toast({
          title: "🔗 Dashboard Shared Successfully", 
          description: "Link copied to clipboard and shared with your security team. Expires in 7 days.",
        });
      } else {
        throw new Error('Share API failed');
      }
    } catch (error) {
      // Fallback if API or clipboard fails
      console.error('Share failed:', error);
      toast({
        title: "📋 Share Link Ready",
        description: `Copy this link: ${window.location.href}`,
      });
    }
  };

  const handleExportData = async () => {
    setIsExporting(true);
    try {
      // Determine export type based on current context
      const exportType = auditLog.length > 0 ? 'full' : 'alerts';
      const format = 'json'; // Could be made configurable

      const response = await fetch(`/api/export?type=${exportType}&format=${format}`, {
        method: 'GET',
        headers: {
          'Accept': format === 'json' ? 'application/json' : 'text/csv'
        }
      });

      if (!response.ok) {
        throw new Error('Export API failed');
      }

      // Get filename from Content-Disposition header
      const contentDisposition = response.headers.get('content-disposition');
      const filename = contentDisposition 
        ? contentDisposition.split('filename=')[1].replace(/"/g, '')
        : `cognito-${exportType}-${new Date().toISOString().split('T')[0]}.${format}`;

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      toast({
        title: "📊 Export Completed Successfully",
        description: `Downloaded ${filename} with ${exportType} security data and audit logs.`,
      });
    } catch (error) {
      console.error('Export failed:', error);
      toast({
        title: "❌ Export Failed", 
        description: "Unable to export security data. Please check connectivity and try again.",
        variant: "destructive",
      });
    } finally {
      setIsExporting(false);
    }
  };

  const liveThreatFeed = [
    {
      title: "CVE-2024-1234",
      description: "Critical RCE vulnerability in Apache Struts discovered",
      timeAgo: "2 min ago",
      severity: "bg-red-500"
    },
    {
      title: "Ransomware Campaign",
      description: "New BlackCat variant targeting healthcare sector",
      timeAgo: "15 min ago",
      severity: "bg-orange-500"
    },
    {
      title: "Phishing Trend",
      description: "Increase in LinkedIn-themed phishing emails",
      timeAgo: "32 min ago",
      severity: "bg-yellow-500"
    }
  ];

  return (
    <div className="w-1/4 bg-card overflow-y-auto scroll-area">
      <div className="p-4">
        {/* Quick Actions */}
        <div className="mb-6">
          <h3 className="text-sm font-semibold text-muted-foreground mb-3">Quick Actions</h3>
          <div className="space-y-2">
            <Button 
              className="w-full justify-start" 
              size="sm" 
              onClick={handleCreateIncident}
              data-testid="button-create-incident"
            >
              <Plus className="w-4 h-4 mr-2" />
              Create Incident
            </Button>
            <Button 
              variant="secondary" 
              className="w-full justify-start" 
              size="sm"
              onClick={handleShareAlert}
              data-testid="button-share-alert"
            >
              <Share className="w-4 h-4 mr-2" />
              Share Alert
            </Button>
            <Button 
              variant="secondary" 
              className="w-full justify-start" 
              size="sm"
              onClick={handleExportData}
              disabled={isExporting}
              data-testid="button-export-data"
            >
              {isExporting ? (
                <>
                  <FileDown className="w-4 h-4 mr-2 animate-pulse" />
                  Exporting...
                </>
              ) : (
                <>
                  <Download className="w-4 h-4 mr-2" />
                  Export Data
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Live Threat Feed */}
        <div className="mb-6">
          <h3 className="text-sm font-semibold text-muted-foreground mb-3">Live Threat Feed</h3>
          <div className="space-y-2">
            {liveThreatFeed.map((threat, idx) => (
              <div key={idx} className="p-3 bg-background rounded-lg border border-border">
                <div className="flex items-center space-x-2 mb-1">
                  <div className={`w-2 h-2 ${threat.severity} rounded-full status-pulse`}></div>
                  <span className="text-xs font-semibold" data-testid={`text-threat-title-${idx}`}>
                    {threat.title}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground" data-testid={`text-threat-description-${idx}`}>
                  {threat.description}
                </p>
                <span className="text-xs text-muted-foreground">{threat.timeAgo}</span>
              </div>
            ))}
          </div>
        </div>

        {/* System Status */}
        <div className="mb-6">
          <h3 className="text-sm font-semibold text-muted-foreground mb-3">System Status</h3>
          <div className="space-y-2">
            {systemStatus.map((system, idx) => (
              <div key={idx} className="flex items-center justify-between p-2 bg-background rounded border border-border">
                <span className="text-xs" data-testid={`text-system-name-${idx}`}>{system.name}</span>
                <div className="flex items-center space-x-1">
                  <div className={`w-2 h-2 ${system.color} rounded-full`}></div>
                  <span className={`text-xs ${system.color.replace('bg-', 'text-')}`} data-testid={`text-system-status-${idx}`}>
                    {system.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Activity / Audit Log */}
        <div>
          <h3 className="text-sm font-semibold text-muted-foreground mb-3">Recent Activity</h3>
          <div className="space-y-2">
            {auditLog.slice(0, 10).map((entry) => (
              <div key={entry.id} className="p-2 bg-background rounded border border-border">
                <div className="flex justify-between items-start mb-1">
                  <span className={`text-xs font-semibold ${
                    entry.actor === 'AI' ? 'text-purple-400' :
                    entry.actor === 'SYSTEM' ? 'text-blue-400' :
                    'text-primary'
                  }`} data-testid={`text-audit-actor-${entry.id}`}>
                    {entry.actor}
                  </span>
                  <span className="text-xs text-muted-foreground" data-testid={`text-audit-time-${entry.id}`}>
                    {new Date(entry.timestamp || 0).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground" data-testid={`text-audit-action-${entry.id}`}>
                  {entry.action}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
