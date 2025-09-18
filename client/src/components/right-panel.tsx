import { Plus, Share, Download, Globe, Users, BarChart3 } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { AuditLog } from "@shared/schema";

interface RightPanelProps {
  auditLog: AuditLog[];
}

export default function RightPanel({ auditLog }: RightPanelProps) {
  const systemStatus = [
    { name: "Email Gateway", status: "Online", color: "bg-green-500" },
    { name: "SIEM Platform", status: "Online", color: "bg-green-500" },
    { name: "EDR Agents", status: "98.2%", color: "bg-yellow-500" }
  ];

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
            <Button className="w-full justify-start" size="sm" data-testid="button-create-incident">
              <Plus className="w-4 h-4 mr-2" />
              Create Incident
            </Button>
            <Button variant="secondary" className="w-full justify-start" size="sm" data-testid="button-share-alert">
              <Share className="w-4 h-4 mr-2" />
              Share Alert
            </Button>
            <Button variant="secondary" className="w-full justify-start" size="sm" data-testid="button-export-data">
              <Download className="w-4 h-4 mr-2" />
              Export Data
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
