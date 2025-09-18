import { useState } from "react";
import { Search, Filter, AlertCircle, Clock, CheckCircle, Brain } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import type { Alert } from "@shared/schema";
import type { AlertSeverity } from "@/types";

interface AlertsListProps {
  alerts: Alert[];
  selectedAlert: Alert | null;
  onAlertSelect: (alert: Alert) => void;
  isLoading: boolean;
}

export default function AlertsList({ alerts, selectedAlert, onAlertSelect, isLoading }: AlertsListProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;
    const matchesSearch = 
      alert.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.title.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  const getSeverityColor = (severity: AlertSeverity) => {
    const colors = {
      'Critical': 'text-red-500 bg-red-500/10 border-red-500/20',
      'High': 'text-orange-500 bg-orange-500/10 border-orange-500/20',
      'Medium': 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20',
      'Low': 'text-blue-500 bg-blue-500/10 border-blue-500/20'
    };
    return colors[severity] || 'text-gray-500';
  };

  const getStatusIcon = (status: string) => {
    const icons: Record<string, JSX.Element> = {
      'New': <AlertCircle className="w-4 h-4" />,
      'Triaging': <Clock className="w-4 h-4" />,
      'Investigating': <Search className="w-4 h-4" />,
      'Resolved': <CheckCircle className="w-4 h-4" />
    };
    return icons[status] || null;
  };

  if (isLoading) {
    return (
      <div className="w-1/3 bg-card border-r border-border">
        <div className="p-4 border-b border-border">
          <Skeleton className="h-10 mb-3" />
          <Skeleton className="h-6 w-32" />
        </div>
        <div className="space-y-4 p-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="w-1/3 bg-card border-r border-border overflow-y-auto scroll-area">
      <div className="p-4 border-b border-border sticky top-0 bg-card z-10">
        <div className="flex items-center space-x-2 mb-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search alerts..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
              data-testid="input-search-alerts"
            />
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-40" data-testid="select-severity-filter">
              <SelectValue placeholder="All Severities" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              <SelectItem value="Critical">Critical</SelectItem>
              <SelectItem value="High">High</SelectItem>
              <SelectItem value="Medium">Medium</SelectItem>
              <SelectItem value="Low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span data-testid="text-total-alerts">{filteredAlerts.length} alerts</span>
          <span data-testid="text-new-alerts">
            {alerts.filter(a => a.status === 'New').length} new
          </span>
        </div>
      </div>

      <div className="divide-y divide-border">
        {filteredAlerts.map((alert) => (
          <div
            key={alert.id}
            onClick={() => onAlertSelect(alert)}
            className={`p-4 hover:bg-secondary/50 cursor-pointer transition-colors ${
              selectedAlert?.id === alert.id ? 'bg-secondary/50 border-l-4 border-accent' : 'border-l-4 border-transparent'
            }`}
            data-testid={`alert-item-${alert.id}`}
          >
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center space-x-2">
                <span className={`px-2 py-1 text-xs rounded-full border ${getSeverityColor(alert.severity as AlertSeverity)}`}>
                  {alert.severity}
                </span>
                {alert.aiTriaged && (
                  <span className="px-2 py-1 text-xs rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20">
                    <Brain className="w-3 h-3 inline mr-1" />
                    AI
                  </span>
                )}
              </div>
              <span className="text-xs text-muted-foreground">
                {new Date(alert.timestamp).toLocaleTimeString()}
              </span>
            </div>
            <h3 className="font-semibold text-sm mb-1" data-testid={`text-alert-title-${alert.id}`}>
              {alert.title}
            </h3>
            <p className="text-xs text-muted-foreground mb-2" data-testid={`text-alert-description-${alert.id}`}>
              {alert.description}
            </p>
            <p className="text-xs text-muted-foreground mb-2">
              {alert.id} • {alert.source}
            </p>
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center space-x-2 text-muted-foreground">
                {getStatusIcon(alert.status)}
                <span>{alert.status}</span>
              </div>
              <span className="text-muted-foreground">{alert.assignee}</span>
            </div>
            {alert.confidence && (
              <div className="mt-2">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-muted-foreground">AI Confidence</span>
                  <span className="text-accent">{alert.confidence}%</span>
                </div>
                <div className="w-full bg-secondary rounded-full h-1">
                  <div
                    className="bg-gradient-to-r from-primary to-accent h-1 rounded-full"
                    style={{ width: `${alert.confidence}%` }}
                  />
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
