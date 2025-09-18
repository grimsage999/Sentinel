import { useQuery } from "@tanstack/react-query";
import { Shield, Globe, Zap, CheckCircle, ChevronRight, Flag, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { Alert, ThreatIntelligence } from "@shared/schema";

interface AlertDetailsProps {
  alert: Alert | null;
  onIOCEnrichment: () => void;
}

export default function AlertDetails({ alert, onIOCEnrichment }: AlertDetailsProps) {
  const { data: threatIntel, isLoading: threatIntelLoading } = useQuery({
    queryKey: ["/api/threat-intelligence", alert?.id],
    queryFn: () => api.getThreatIntelligence(alert!.id),
    enabled: !!alert
  });

  if (!alert) {
    return (
      <div className="flex-1 bg-background border-r border-border overflow-y-auto scroll-area">
        <div className="flex items-center justify-center h-full">
          <div className="text-center">
            <Shield className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-xl font-semibold mb-2">Select an Alert to Investigate</h3>
            <p className="text-muted-foreground">Choose an alert from the left panel to begin your investigation</p>
          </div>
        </div>
      </div>
    );
  }

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      'Critical': 'bg-red-500/10 text-red-500 border-red-500/20',
      'High': 'bg-orange-500/10 text-orange-500 border-orange-500/20',
      'Medium': 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
      'Low': 'bg-blue-500/10 text-blue-500 border-blue-500/20'
    };
    return colors[severity] || 'bg-gray-500/10 text-gray-500';
  };

  const workflowSteps = [
    { title: 'Initial Triage', description: 'Verify alert authenticity and gather initial context', completed: true },
    { title: 'Threat Intelligence', description: 'Enrich with external threat data', active: true },
    { title: 'Impact Assessment', description: 'Determine business impact and affected systems', pending: true },
    { title: 'Containment', description: 'Isolate affected systems if necessary', pending: true },
    { title: 'Documentation', description: 'Document findings and generate report', pending: true }
  ];

  return (
    <div className="flex-1 bg-background border-r border-border overflow-y-auto scroll-area">
      <div className="p-6">
        {/* Alert Header */}
        <div className="border-b border-border pb-4 mb-6">
          <div className="flex items-start justify-between mb-4">
            <div>
              <div className="flex items-center space-x-3 mb-2">
                <span className={`px-3 py-1 text-sm rounded-full border ${getSeverityColor(alert.severity)}`}>
                  {alert.severity}
                </span>
                <span className="px-3 py-1 text-sm rounded-full bg-secondary text-secondary-foreground">
                  {alert.status}
                </span>
                <span className="font-mono text-sm text-muted-foreground" data-testid={`text-alert-id-${alert.id}`}>
                  {alert.id}
                </span>
              </div>
              <h1 className="text-2xl font-bold mb-2" data-testid={`text-alert-title-details-${alert.id}`}>
                {alert.title}
              </h1>
              <p className="text-muted-foreground" data-testid={`text-alert-description-details-${alert.id}`}>
                {alert.description}
              </p>
            </div>
            <div className="flex space-x-2">
              <Button onClick={onIOCEnrichment} variant="outline" data-testid="button-ioc-enrichment">
                <Search className="w-4 h-4 mr-2" />
                IOC Enrichment
              </Button>
              <Button data-testid="button-escalate">
                <Flag className="w-4 h-4 mr-2" />
                Escalate
              </Button>
            </div>
          </div>
          
          {/* Alert Metadata */}
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-card p-3 rounded-lg border border-border">
              <p className="text-xs text-muted-foreground">Source</p>
              <p className="font-semibold" data-testid={`text-alert-source-${alert.id}`}>{alert.source}</p>
            </div>
            <div className="bg-card p-3 rounded-lg border border-border">
              <p className="text-xs text-muted-foreground">Confidence</p>
              <p className="font-semibold text-green-500" data-testid={`text-alert-confidence-${alert.id}`}>
                {alert.confidence}%
              </p>
            </div>
            <div className="bg-card p-3 rounded-lg border border-border">
              <p className="text-xs text-muted-foreground">Affected Assets</p>
              <p className="font-semibold" data-testid={`text-alert-assets-${alert.id}`}>
                {alert.affectedAssets} users
              </p>
            </div>
            <div className="bg-card p-3 rounded-lg border border-border">
              <p className="text-xs text-muted-foreground">Business Impact</p>
              <p className={`font-semibold ${alert.businessImpact === 'High' ? 'text-red-500' : 'text-orange-500'}`}>
                {alert.businessImpact}
              </p>
            </div>
          </div>
        </div>

        {/* Investigation Workflow */}
        <div className="mb-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center">
            <Zap className="w-5 h-5 mr-2 text-primary" />
            AI-Guided Response Workflow
          </h2>
          <div className="space-y-3">
            {workflowSteps.map((step, idx) => (
              <div
                key={idx}
                className={`flex items-center space-x-3 p-3 rounded-lg transition-colors ${
                  step.completed ? 'bg-green-500/10 border border-green-500/30' :
                  step.active ? 'bg-primary/10 border border-primary/30' :
                  'bg-secondary border border-border'
                }`}
                data-testid={`workflow-step-${idx}`}
              >
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                  step.completed ? 'bg-green-500 text-white' :
                  step.active ? 'bg-primary text-primary-foreground' :
                  'bg-muted text-muted-foreground'
                }`}>
                  {step.completed ? <CheckCircle className="w-5 h-5" /> : <span>{idx + 1}</span>}
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold">{step.title}</h3>
                  <p className="text-xs text-muted-foreground">{step.description}</p>
                </div>
                <ChevronRight className="w-4 h-4 text-muted-foreground" />
              </div>
            ))}
          </div>
        </div>

        {/* Threat Intelligence */}
        {threatIntelLoading ? (
          <div className="mb-6">
            <Skeleton className="h-6 w-48 mb-4" />
            <div className="grid grid-cols-2 gap-4">
              <Skeleton className="h-32" />
              <Skeleton className="h-32" />
            </div>
          </div>
        ) : threatIntel ? (
          <div className="mb-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center">
              <Globe className="w-5 h-5 mr-2 text-primary" />
              Threat Intelligence Enrichment
            </h2>
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div className="bg-card p-4 rounded-lg border border-border">
                <p className="text-xs text-muted-foreground mb-1">Malicious Score</p>
                <p className="text-2xl font-bold text-red-400" data-testid="text-malicious-score">
                  {threatIntel.maliciousScore}/100
                </p>
              </div>
              <div className="bg-card p-4 rounded-lg border border-border">
                <p className="text-xs text-muted-foreground mb-1">Previous Sightings</p>
                <p className="text-2xl font-bold text-yellow-400" data-testid="text-previous-sightings">
                  {threatIntel.previousSightings}
                </p>
              </div>
              <div className="bg-card p-4 rounded-lg border border-border">
                <p className="text-xs text-muted-foreground mb-1">Threat Actor</p>
                <p className="text-lg font-bold text-purple-400" data-testid="text-threat-actor">
                  {threatIntel.threatActor}
                </p>
              </div>
            </div>
            
            {/* IOCs */}
            {threatIntel.iocs && Array.isArray(threatIntel.iocs) && (
              <div>
                <p className="text-sm text-muted-foreground mb-2">Indicators of Compromise (IOCs)</p>
                <div className="space-y-2">
                  {(threatIntel.iocs as Array<{type: string, value: string, reputation: string}>).map((ioc, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-card rounded p-3 text-sm border border-border">
                      <div className="flex items-center space-x-3">
                        <span className="text-muted-foreground">{ioc.type}:</span>
                        <code className="text-primary">{ioc.value}</code>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs ${
                        ioc.reputation === 'Malicious' ? 'bg-red-500/20 text-red-400' :
                        ioc.reputation === 'Suspicious' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>
                        {ioc.reputation}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : null}

        {/* Evidence Timeline */}
        <div>
          <h2 className="text-lg font-semibold mb-4">Evidence Timeline</h2>
          <div className="space-y-3">
            <div className="flex items-start space-x-3 p-3 bg-card rounded-lg border border-border">
              <div className="w-2 h-2 bg-red-500 rounded-full mt-2"></div>
              <div className="flex-1">
                <div className="flex justify-between items-start">
                  <div>
                    <h4 className="font-semibold text-sm">Initial Email Detected</h4>
                    <p className="text-xs text-muted-foreground">
                      Suspicious email with phishing indicators blocked by gateway
                    </p>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            </div>
            
            <div className="flex items-start space-x-3 p-3 bg-card rounded-lg border border-border">
              <div className="w-2 h-2 bg-orange-500 rounded-full mt-2"></div>
              <div className="flex-1">
                <div className="flex justify-between items-start">
                  <div>
                    <h4 className="font-semibold text-sm">Additional Variants Found</h4>
                    <p className="text-xs text-muted-foreground">
                      {alert.affectedAssets} similar emails identified targeting different executives
                    </p>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {new Date(Date.now() - 180000).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
