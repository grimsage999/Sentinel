import { useQuery } from "@tanstack/react-query";
import { Globe, Zap, CheckCircle, ChevronRight, Flag, Search, Link2, AlertTriangle, Mail, ExternalLink, Eye, Target, Database } from "lucide-react";
import logoImg from "@assets/unnamed_1758744382590.png";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { Alert, ThreatIntelligence } from "@shared/schema";

interface CorrelationResult {
  correlation: {
    id: string;
    primaryAlertId: string;
    relatedAlertId: string;
    correlationType: string;
    confidence: number;
    correlationData: any;
    createdAt: Date;
  };
  primaryAlert: Alert;
  relatedAlert: Alert;
  correlationStrength: number;
}

interface CorrelationAnalysis {
  alertId: string;
  correlations: CorrelationResult[];
  totalScore: number;
  riskLevel: "Low" | "Medium" | "High" | "Critical";
  patterns: string[];
}

// Type guard for metadata
type PhishingMetadata = {
  emailFrom?: string;
  emailTo?: string;
  subject?: string;
  emailContent?: string;
  attachments?: string[];
  vtAnalysis?: any;
  maliciousUrls?: string[];
  suspiciousIPs?: string[];
  mitreAttack?: any;
  phishingTechniques?: any[];
  riskFactors?: any[];
};

const isPhishingMetadata = (metadata: unknown): metadata is PhishingMetadata => {
  return typeof metadata === 'object' && metadata !== null;
};

// Helper function to safely access metadata properties
const getMetadataProperty = (metadata: unknown, property: string): any => {
  if (isPhishingMetadata(metadata)) {
    return (metadata as any)[property];
  }
  return undefined;
};

// Helper function to safely check if value is a valid array
const isValidArray = (value: unknown): value is Array<any> => {
  return Array.isArray(value);
};

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

  const { data: correlationAnalysis, isLoading: correlationLoading } = useQuery<CorrelationAnalysis>({
    queryKey: ["/api/correlations", alert?.id],
    queryFn: () => api.getCorrelationAnalysis(alert!.id),
    enabled: !!alert
  });

  if (!alert) {
    return (
      <div className="flex-1 bg-background border-r border-border overflow-y-auto scroll-area">
        <div className="flex items-center justify-center h-full">
          <div className="text-center">
            <img src={logoImg} alt="Cognito Logo" className="w-16 h-16 mx-auto mb-4 rounded-lg opacity-60" />
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

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return 'text-green-500'; // High confidence
    if (confidence >= 60) return 'text-yellow-500'; // Medium confidence
    return 'text-red-500'; // Low confidence
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
              <p className={`font-semibold ${getConfidenceColor(alert.confidence || 0)}`} data-testid={`text-alert-confidence-${alert.id}`}>
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
                  {threatIntel.maliciousScore || 0}/100
                </p>
              </div>
              <div className="bg-card p-4 rounded-lg border border-border">
                <p className="text-xs text-muted-foreground mb-1">Previous Sightings</p>
                <p className="text-2xl font-bold text-yellow-400" data-testid="text-previous-sightings">
                  {threatIntel.previousSightings || 0}
                </p>
              </div>
              <div className="bg-card p-4 rounded-lg border border-border">
                <p className="text-xs text-muted-foreground mb-1">Threat Actor</p>
                <p className="text-lg font-bold text-purple-400" data-testid="text-threat-actor">
                  {threatIntel.threatActor || 'Unknown'}
                </p>
              </div>
            </div>
            
            {/* IOCs */}
            {isValidArray(threatIntel.iocs) && (
              <div>
                <p className="text-sm text-muted-foreground mb-2">Indicators of Compromise (IOCs)</p>
                <div className="space-y-2">
                  {threatIntel.iocs.map((ioc: any, idx: number) => (
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

        {/* Correlation Analysis */}
        <div className="mb-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center">
            <Link2 className="w-5 h-5 mr-2 text-primary" />
            Correlation Analysis
          </h2>
          {correlationLoading ? (
            <div className="space-y-3">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : correlationAnalysis ? (
            <div className="space-y-4">
              {/* Risk Assessment */}
              <div className="bg-card p-4 rounded-lg border border-border">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-semibold">Risk Assessment</h3>
                  <div className="flex items-center space-x-3">
                    <Badge 
                      variant={
                        correlationAnalysis.riskLevel === "Critical" ? "destructive" :
                        correlationAnalysis.riskLevel === "High" ? "secondary" : 
                        "outline"
                      }
                      data-testid={`text-risk-level-${alert.id}`}
                    >
                      <AlertTriangle className="w-3 h-3 mr-1" />
                      {correlationAnalysis.riskLevel} Risk
                    </Badge>
                    <span className="text-sm text-muted-foreground" data-testid={`text-total-score-${alert.id}`}>
                      Score: {correlationAnalysis.totalScore}/100
                    </span>
                  </div>
                </div>
                
                {correlationAnalysis.patterns && correlationAnalysis.patterns.length > 0 && (
                  <div>
                    <p className="text-sm text-muted-foreground mb-2">Detected Patterns:</p>
                    <ul className="space-y-1">
                      {correlationAnalysis.patterns.map((pattern, idx) => (
                        <li key={idx} className="text-sm text-amber-400 flex items-center">
                          <ChevronRight className="w-3 h-3 mr-1" />
                          {pattern}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* Related Alerts */}
              {correlationAnalysis.correlations && correlationAnalysis.correlations.length > 0 ? (
                <div>
                  <h3 className="font-semibold mb-3">Related Alerts ({correlationAnalysis.correlations.length})</h3>
                  <div className="space-y-3">
                    {correlationAnalysis.correlations.slice(0, 5).map((correlation, idx) => (
                      <div key={idx} className="bg-card p-3 rounded-lg border border-border">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <Badge variant="outline" className="text-xs">
                              {correlation.correlation.correlationType.replace('_', ' ').toUpperCase()}
                            </Badge>
                            <span className="font-mono text-xs text-muted-foreground">
                              {correlation.relatedAlert.id}
                            </span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-xs text-muted-foreground">
                              Confidence: {correlation.correlation.confidence}%
                            </span>
                            <div className={`w-2 h-2 rounded-full ${
                              correlation.correlation.confidence >= 80 ? 'bg-green-500' :
                              correlation.correlation.confidence >= 60 ? 'bg-yellow-500' :
                              'bg-red-500'
                            }`}></div>
                          </div>
                        </div>
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <h4 className="text-sm font-medium">{correlation.relatedAlert.title}</h4>
                            <p className="text-xs text-muted-foreground mt-1">
                              {correlation.relatedAlert.source} • {correlation.relatedAlert.severity}
                            </p>
                            {correlation.correlation.correlationData && (
                              <div className="mt-2 text-xs text-muted-foreground">
                                {JSON.stringify(correlation.correlation.correlationData, null, 2).substring(0, 100)}...
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                  
                  {correlationAnalysis.correlations.length > 5 && (
                    <Button variant="outline" size="sm" className="w-full mt-3">
                      View All {correlationAnalysis.correlations.length} Correlations
                    </Button>
                  )}
                </div>
              ) : (
                <div className="bg-card p-4 rounded-lg border border-border text-center">
                  <p className="text-sm text-muted-foreground">No correlations found for this alert.</p>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-card p-4 rounded-lg border border-border text-center">
              <p className="text-sm text-muted-foreground">Click to analyze correlations</p>
              <Button variant="outline" size="sm" className="mt-2">
                Run Correlation Analysis
              </Button>
            </div>
          )}
        </div>

        {/* Contextual Analysis Section */}
        {alert.type === "Phishing Email Campaign" && alert.metadata && isPhishingMetadata(alert.metadata) && (
          <div className="mb-6">
            <div className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-950/20 dark:to-purple-950/20 p-4 rounded-lg border border-blue-200 dark:border-blue-800 mb-4">
              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                <div className="flex items-center space-x-3">
                  <div className="bg-blue-600 p-2 rounded-full flex-shrink-0">
                    <Mail className="w-5 h-5 text-white" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <h2 className="text-lg lg:text-xl font-bold text-blue-900 dark:text-blue-100 break-words">
                      🧠 AI-Powered Contextual Analysis
                    </h2>
                    <p className="text-sm text-blue-700 dark:text-blue-300 break-words">
                      Rich threat intelligence and attack context to accelerate investigation
                    </p>
                  </div>
                </div>
                <div className="text-left lg:text-right flex-shrink-0">
                  <div className="bg-green-100 dark:bg-green-900/30 px-3 py-1 rounded-full inline-block">
                    <span className="text-xs font-medium text-green-800 dark:text-green-200 whitespace-nowrap">
                      ⚡ Instant Context
                    </span>
                  </div>
                  <p className="text-xs text-blue-600 dark:text-blue-400 mt-1 whitespace-nowrap">
                    Investigation time: 30 seconds vs 15+ minutes
                  </p>
                </div>
              </div>
            </div>
            
            <Tabs defaultValue="email-details" className="w-full">
              <TabsList className="grid w-full grid-cols-2 lg:grid-cols-5 gap-1">
                <TabsTrigger value="email-details" className="flex flex-col items-center p-2 min-w-0">
                  <Mail className="w-4 h-4 mb-1 flex-shrink-0" />
                  <span className="text-xs text-center leading-tight">Email</span>
                </TabsTrigger>
                <TabsTrigger value="iocs" className="flex flex-col items-center p-2 min-w-0">
                  <Database className="w-4 h-4 mb-1 flex-shrink-0" />
                  <span className="text-xs text-center leading-tight">IOCs</span>
                </TabsTrigger>
                <TabsTrigger value="mitre-attack" className="flex flex-col items-center p-2 min-w-0">
                  <Target className="w-4 h-4 mb-1 flex-shrink-0" />
                  <span className="text-xs text-center leading-tight">MITRE</span>
                </TabsTrigger>
                <TabsTrigger value="techniques" className="flex flex-col items-center p-2 min-w-0">
                  <Eye className="w-4 h-4 mb-1 flex-shrink-0" />
                  <span className="text-xs text-center leading-tight">Methods</span>
                </TabsTrigger>
                <TabsTrigger value="risk-factors" className="flex flex-col items-center p-2 min-w-0">
                  <AlertTriangle className="w-4 h-4 mb-1 flex-shrink-0" />
                  <span className="text-xs text-center leading-tight">Risks</span>
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="email-details" className="space-y-4">
                <div className="bg-blue-50 dark:bg-blue-950/20 p-3 rounded-lg border-l-4 border-blue-500 mb-4">
                  <p className="text-sm text-blue-800 dark:text-blue-200 break-words">
                    <strong className="font-semibold">📧 Contextual Intelligence:</strong>{" "}
                    <span className="inline-block">Full email content, headers, and attachments with threat indicators</span>
                  </p>
                </div>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center">
                      <Mail className="w-4 h-4 mr-2" />
                      Email Headers & Content
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">From</p>
                        <p className="font-mono text-sm bg-muted p-2 rounded">{alert.metadata.emailFrom}</p>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">To</p>
                        <p className="font-mono text-sm bg-muted p-2 rounded">{alert.metadata.emailTo}</p>
                      </div>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Subject</p>
                      <p className="font-mono text-sm bg-muted p-2 rounded">{alert.metadata.subject}</p>
                    </div>
                    {alert.metadata.emailContent && (
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">Email Content</p>
                        <div className="bg-muted p-3 rounded-lg border-l-4 border-red-500">
                          <p className="text-sm whitespace-pre-wrap">{alert.metadata.emailContent}</p>
                        </div>
                      </div>
                    )}
                    {alert.metadata.attachments && alert.metadata.attachments.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">Attachments</p>
                        <div className="space-y-1">
                          {alert.metadata.attachments.map((attachment: string, idx: number) => (
                            <div key={idx} className="flex items-center space-x-2 bg-red-50 dark:bg-red-950/20 p-2 rounded">
                              <AlertTriangle className="w-4 h-4 text-red-500" />
                              <span className="font-mono text-sm text-red-900 dark:text-red-100">{attachment}</span>
                              <Badge variant="destructive" className="text-xs">Malicious</Badge>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="iocs" className="space-y-4">
                <div className="bg-green-50 dark:bg-green-950/20 p-3 rounded-lg border-l-4 border-green-500 mb-4">
                  <p className="text-sm text-green-800 dark:text-green-200">
                    <strong>🔍 Live Threat Intelligence:</strong> Real-time VirusTotal analysis with direct links to malicious URL reports
                  </p>
                </div>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center">
                      <Database className="w-4 h-4 mr-2" />
                      Indicators of Compromise & VirusTotal Analysis
                    </CardTitle>
                    <CardDescription>
                      Malicious URLs and IPs with live VirusTotal threat intelligence
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {getMetadataProperty(alert.metadata, 'vtAnalysis') && (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                        <div className="bg-card p-3 rounded-lg border min-w-0">
                          <p className="text-xs text-muted-foreground whitespace-nowrap">Malicious URLs</p>
                          <p className="text-xl font-bold text-red-500">{getMetadataProperty(alert.metadata, 'vtAnalysis')?.maliciousUrls || 0}</p>
                        </div>
                        <div className="bg-card p-3 rounded-lg border min-w-0">
                          <p className="text-xs text-muted-foreground whitespace-nowrap">Suspicious Score</p>
                          <p className="text-xl font-bold text-orange-500">{getMetadataProperty(alert.metadata, 'vtAnalysis')?.suspiciousScore || 0}%</p>
                        </div>
                        <div className="bg-card p-3 rounded-lg border min-w-0">
                          <p className="text-xs text-muted-foreground whitespace-nowrap">VT Reports</p>
                          <p className="text-xl font-bold text-blue-500">{getMetadataProperty(alert.metadata, 'vtAnalysis')?.vtLinks?.length || 0}</p>
                        </div>
                      </div>
                    )}
                    
                    {alert.metadata.maliciousUrls && Array.isArray(alert.metadata.maliciousUrls) && (
                      <div>
                        <h4 className="font-semibold mb-2">Malicious URLs</h4>
                        <div className="space-y-2 max-h-64 overflow-y-auto">
                          {alert.metadata.maliciousUrls.map((url: string, idx: number) => (
                            <div key={idx} className="flex items-center justify-between bg-red-50 dark:bg-red-950/20 p-3 rounded border-l-4 border-red-500 gap-2">
                              <div className="flex-1 min-w-0">
                                <p className="font-mono text-sm break-all text-red-900 dark:text-red-100">{url}</p>
                              </div>
                              {getMetadataProperty(alert.metadata, 'vtAnalysis')?.vtLinks?.[idx] && (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="ml-2 flex-shrink-0"
                                  onClick={() => {
                                    const link = document.createElement('a');
                                    link.href = getMetadataProperty(alert.metadata, 'vtAnalysis').vtLinks[idx];
                                    link.target = '_blank';
                                    link.rel = 'noopener noreferrer';
                                    document.body.appendChild(link);
                                    link.click();
                                    document.body.removeChild(link);
                                  }}
                                >
                                  <ExternalLink className="w-3 h-3 mr-1" />
                                  VT Analysis
                                </Button>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {alert.metadata.suspiciousIPs && Array.isArray(alert.metadata.suspiciousIPs) && (
                      <div>
                        <h4 className="font-semibold mb-2">Suspicious IP Addresses</h4>
                        <div className="space-y-2 max-h-64 overflow-y-auto">
                          {alert.metadata.suspiciousIPs.map((ip: string, idx: number) => (
                            <div key={idx} className="flex items-center justify-between bg-orange-50 dark:bg-orange-950/20 p-3 rounded border-l-4 border-orange-500">
                              <div className="flex items-center space-x-3">
                                <code className="text-sm break-all text-orange-900 dark:text-orange-100">{ip}</code>
                                <Badge variant="outline" className="text-xs">Suspicious IP</Badge>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="mitre-attack" className="space-y-4">
                <div className="bg-purple-50 dark:bg-purple-950/20 p-3 rounded-lg border-l-4 border-purple-500 mb-4">
                  <p className="text-sm text-purple-800 dark:text-purple-200 break-words">
                    <strong className="font-semibold">🎯 Official MITRE Mapping:</strong>{" "}
                    <span className="inline-block">Real techniques and tactics from the official MITRE ATT&CK framework with direct links</span>
                  </p>
                </div>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center">
                      <Target className="w-4 h-4 mr-2" />
                      MITRE ATT&CK Framework Mapping
                    </CardTitle>
                    <CardDescription>
                      Official MITRE techniques and tactics identified in this attack
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {alert.metadata.mitreAttack?.techniques && (
                      <div>
                        <h4 className="font-semibold mb-3">Attack Techniques</h4>
                        <div className="grid gap-3">
                          {alert.metadata.mitreAttack.techniques.map((technique: string, idx: number) => (
                            <div key={idx} className="flex items-center justify-between bg-card p-3 rounded-lg border">
                              <div className="flex items-center space-x-3">
                                <Badge variant="secondary" className="font-mono">{technique}</Badge>
                                <div>
                                  <p className="font-medium text-sm">
                                    {technique === "T1566.002" ? "Phishing: Spearphishing Link" :
                                     technique === "T1598.003" ? "Phishing for Information: Spearphishing Link" :
                                     technique === "T1566.001" ? "Phishing: Spearphishing Attachment" :
                                     technique === "T1204.002" ? "User Execution: Malicious File" :
                                     technique === "T1598.002" ? "Phishing for Information: Spearphishing Attachment" :
                                     `MITRE ${technique}`}
                                  </p>
                                  <p className="text-xs text-muted-foreground">
                                    {technique === "T1566.002" ? "Adversaries may send spearphishing emails with a malicious link" :
                                     technique === "T1598.003" ? "Adversaries may send spearphishing messages to gather credentials" :
                                     technique === "T1566.001" ? "Adversaries may send spearphishing emails with malicious attachments" :
                                     technique === "T1204.002" ? "Adversaries may rely upon a user opening a malicious file" :
                                     technique === "T1598.002" ? "Adversaries may send spearphishing messages with malicious attachments" :
                                     "MITRE ATT&CK technique"}
                                  </p>
                                </div>
                              </div>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => {
                                  const link = document.createElement('a');
                                  link.href = `https://attack.mitre.org/techniques/${technique}`;
                                  link.target = '_blank';
                                  link.rel = 'noopener noreferrer';
                                  document.body.appendChild(link);
                                  link.click();
                                  document.body.removeChild(link);
                                }}
                              >
                                <ExternalLink className="w-3 h-3" />
                              </Button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {alert.metadata.mitreAttack?.tactics && (
                      <div>
                        <h4 className="font-semibold mb-3">Attack Tactics</h4>
                        <div className="flex flex-wrap gap-2">
                          {alert.metadata.mitreAttack.tactics.map((tactic: string, idx: number) => (
                            <Badge key={idx} variant="outline" className="flex items-center space-x-1">
                              <Target className="w-3 h-3" />
                              <span>{tactic}</span>
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="techniques" className="space-y-4">
                <div className="bg-amber-50 dark:bg-amber-950/20 p-3 rounded-lg border-l-4 border-amber-500 mb-4">
                  <p className="text-sm text-amber-800 dark:text-amber-200">
                    <strong>🎭 Attack Psychology:</strong> Social engineering methods and deception tactics used to manipulate victims
                  </p>
                </div>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center">
                      <Eye className="w-4 h-4 mr-2" />
                      Phishing Techniques Identified
                    </CardTitle>
                    <CardDescription>
                      Social engineering and deception methods used in this campaign
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {alert.metadata.phishingTechniques && (
                      <div className="grid gap-3">
                        {alert.metadata.phishingTechniques.map((technique: string, idx: number) => (
                          <div key={idx} className="flex items-center space-x-3 p-3 bg-amber-50 dark:bg-amber-950/20 rounded-lg border-l-4 border-amber-500">
                            <AlertTriangle className="w-5 h-5 text-amber-600" />
                            <div>
                              <p className="font-medium text-sm text-amber-900 dark:text-amber-100">{technique}</p>
                              <p className="text-xs text-amber-700 dark:text-amber-200">
                                {technique === "Urgency Tactics" ? "Creates false sense of urgency to pressure victims" :
                                 technique === "Brand Impersonation" ? "Mimics trusted brands to gain credibility" :
                                 technique === "Account Suspension Threat" ? "Threatens account closure to prompt action" :
                                 technique === "Government Impersonation" ? "Impersonates government agencies" :
                                 technique === "Financial Incentive" ? "Offers fake financial rewards" :
                                 technique === "Account Verification" ? "Requests account verification under false pretenses" :
                                 technique === "Security Alert Impersonation" ? "Mimics legitimate security notifications" :
                                 technique === "Fake Attachments" ? "Uses malicious attachments disguised as legitimate files" :
                                 "Social engineering technique"}
                              </p>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="risk-factors" className="space-y-4">
                <div className="bg-red-50 dark:bg-red-950/20 p-3 rounded-lg border-l-4 border-red-500 mb-4">
                  <p className="text-sm text-red-800 dark:text-red-200">
                    <strong>⚠️ Risk Intelligence:</strong> Technical and behavioral indicators explaining why this attack scored high risk
                  </p>
                </div>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center">
                      <AlertTriangle className="w-4 h-4 mr-2" />
                      Risk Factors & Indicators
                    </CardTitle>
                    <CardDescription>
                      Technical and behavioral indicators that contributed to the high risk score
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {alert.metadata.riskFactors && (
                      <div className="space-y-3">
                        {alert.metadata.riskFactors.map((factor: string, idx: number) => (
                          <div key={idx} className="flex items-start space-x-3 p-3 bg-red-50 dark:bg-red-950/20 rounded-lg border-l-4 border-red-500">
                            <AlertTriangle className="w-4 h-4 text-red-600 mt-0.5" />
                            <div className="flex-1">
                              <p className="text-sm font-medium text-red-900 dark:text-red-100">{factor}</p>
                              <div className="mt-1">
                                <Badge variant="destructive" className="text-xs">High Risk</Badge>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        )}

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
