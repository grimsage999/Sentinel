import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Shield, Mail, Search, FileText } from "lucide-react";
import { api } from "@/lib/api";
import { useToast } from "@/hooks/use-toast";

interface AnalysisResult {
  id: string;
  timestamp: string;
  email_content: string;
  analysis: {
    intent: {
      primary_intent: string;
      confidence: number;
      secondary_intents: Array<{
        intent: string;
        confidence: number;
      }>;
      reasoning: string;
    };
    risk_score: {
      overall_score: number;
      risk_level: string;
      factors: Array<{
        factor: string;
        impact: number;
        description: string;
      }>;
    };
    deception_indicators: Array<{
      type: string;
      severity: string;
      description: string;
      evidence: string;
    }>;
    mitre_attack: {
      techniques: Array<{
        id: string;
        name: string;
        confidence: number;
        description: string;
      }>;
      tactics: Array<{
        id: string;
        name: string;
        description: string;
      }>;
    };
    iocs: {
      urls: string[];
      domains: string[];
      ips: string[];
      emails: string[];
      hashes: string[];
    };
  };
}

export default function EmailAnalysis() {
  const [emailContent, setEmailContent] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const { toast } = useToast();

  const handleAnalyze = async () => {
    if (!emailContent.trim()) {
      toast({
        title: "Error",
        description: "Please enter email content to analyze",
        variant: "destructive"
      });
      return;
    }

    setIsAnalyzing(true);
    try {
      const result = await api.analyzeEmail(emailContent);
      setAnalysisResult(result);
      
      toast({
        title: "Analysis Complete",
        description: `Email analyzed with ${result.analysis.risk_score.risk_level} risk level`,
      });
    } catch (error) {
      toast({
        title: "Analysis Failed", 
        description: "Failed to analyze email. Please try again.",
        variant: "destructive"
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel?.toLowerCase()) {
      case 'high': return 'bg-red-500/20 text-red-400 border-red-500/20';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/20';
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/20';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/20';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'high': return 'bg-red-500/20 text-red-400';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400';
      case 'low': return 'bg-green-500/20 text-green-400';
      default: return 'bg-gray-500/20 text-gray-400';
    }
  };

  const sampleEmail = `From: security@bank-update-center.com
To: user@company.com
Subject: URGENT: Your Account Will Be Suspended

Dear Valued Customer,

We have detected suspicious activity on your account. Your account will be suspended within 24 hours unless you verify your information immediately.

Click here to verify: http://suspicious-bank-site.com/verify-account

Please provide your:
- Full Name
- Account Number  
- Social Security Number
- Password

Failure to respond will result in permanent account closure.

Best regards,
Security Team`;

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-2">
            <Mail className="h-8 w-8 text-blue-500" />
            Email Phishing Analysis
          </h1>
          <p className="text-muted-foreground mt-2">
            Analyze emails for phishing attempts, deception indicators, and security threats
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Email Content
              </CardTitle>
              <CardDescription>
                Paste the email content you want to analyze for threats
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Textarea
                placeholder="Paste email content here..."
                value={emailContent}
                onChange={(e) => setEmailContent(e.target.value)}
                className="min-h-[300px] font-mono text-sm"
              />
              <div className="flex gap-2">
                <Button 
                  onClick={handleAnalyze} 
                  disabled={isAnalyzing}
                  className="flex items-center gap-2"
                >
                  <Search className="h-4 w-4" />
                  {isAnalyzing ? "Analyzing..." : "Analyze Email"}
                </Button>
                <Button 
                  variant="outline" 
                  onClick={() => setEmailContent(sampleEmail)}
                >
                  Load Sample
                </Button>
                <Button 
                  variant="outline" 
                  onClick={() => {
                    setEmailContent("");
                    setAnalysisResult(null);
                  }}
                >
                  Clear
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Results Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Analysis Results
              </CardTitle>
              <CardDescription>
                Detailed threat analysis and risk assessment
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!analysisResult ? (
                <div className="text-center text-muted-foreground py-12">
                  <Mail className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No analysis results yet. Analyze an email to see results.</p>
                </div>
              ) : (
                <Tabs defaultValue="overview" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    <TabsTrigger value="threats">Threats</TabsTrigger>
                    <TabsTrigger value="mitre">MITRE</TabsTrigger>
                    <TabsTrigger value="iocs">IOCs</TabsTrigger>
                  </TabsList>

                  <TabsContent value="overview" className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <h4 className="font-semibold mb-2">Risk Level</h4>
                        <Badge className={getRiskColor(analysisResult.analysis.risk_score.risk_level)}>
                          {analysisResult.analysis.risk_score.risk_level} ({analysisResult.analysis.risk_score.overall_score}/100)
                        </Badge>
                      </div>
                      <div>
                        <h4 className="font-semibold mb-2">Primary Intent</h4>
                        <Badge variant="outline">
                          {analysisResult.analysis.intent.primary_intent} ({Math.round(analysisResult.analysis.intent.confidence * 100)}%)
                        </Badge>
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="font-semibold mb-2">Risk Factors</h4>
                      <div className="space-y-2">
                        {analysisResult.analysis.risk_score.factors.map((factor, index) => (
                          <div key={index} className="flex justify-between items-center p-2 bg-muted rounded">
                            <span className="text-sm">{factor.factor}</span>
                            <Badge variant={factor.impact > 0 ? "destructive" : "secondary"}>
                              {factor.impact > 0 ? "+" : ""}{factor.impact}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Analysis Reasoning</h4>
                      <p className="text-sm text-muted-foreground bg-muted p-3 rounded">
                        {analysisResult.analysis.intent.reasoning}
                      </p>
                    </div>
                  </TabsContent>

                  <TabsContent value="threats" className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2 flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4" />
                        Deception Indicators
                      </h4>
                      {analysisResult.analysis.deception_indicators.length === 0 ? (
                        <p className="text-sm text-muted-foreground">No deception indicators detected.</p>
                      ) : (
                        <div className="space-y-2">
                          {analysisResult.analysis.deception_indicators.map((indicator, index) => (
                            <div key={index} className="border rounded p-3">
                              <div className="flex justify-between items-start mb-2">
                                <span className="font-medium">{indicator.type.replace('_', ' ').toUpperCase()}</span>
                                <Badge className={getSeverityColor(indicator.severity)}>
                                  {indicator.severity}
                                </Badge>
                              </div>
                              <p className="text-sm text-muted-foreground mb-1">{indicator.description}</p>
                              <p className="text-xs text-muted-foreground font-mono bg-muted p-1 rounded">
                                {indicator.evidence}
                              </p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </TabsContent>

                  <TabsContent value="mitre" className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2">MITRE ATT&CK Techniques</h4>
                      {analysisResult.analysis.mitre_attack.techniques.length === 0 ? (
                        <p className="text-sm text-muted-foreground">No MITRE ATT&CK techniques identified.</p>
                      ) : (
                        <div className="space-y-2">
                          {analysisResult.analysis.mitre_attack.techniques.map((technique, index) => (
                            <div key={index} className="border rounded p-3">
                              <div className="flex justify-between items-start mb-2">
                                <span className="font-medium">{technique.id}: {technique.name}</span>
                                <Badge variant="outline">
                                  {Math.round(technique.confidence * 100)}%
                                </Badge>
                              </div>
                              <p className="text-sm text-muted-foreground">{technique.description}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Tactics</h4>
                      <div className="flex flex-wrap gap-2">
                        {analysisResult.analysis.mitre_attack.tactics.map((tactic, index) => (
                          <Badge key={index} variant="secondary">
                            {tactic.id}: {tactic.name}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="iocs" className="space-y-4">
                    {Object.entries(analysisResult.analysis.iocs).map(([type, items]) => (
                      <div key={type}>
                        <h4 className="font-semibold mb-2 capitalize">{type}</h4>
                        {items.length === 0 ? (
                          <p className="text-sm text-muted-foreground">No {type} found.</p>
                        ) : (
                          <div className="space-y-1">
                            {items.map((item: string, index: number) => (
                              <div key={index} className="font-mono text-sm bg-muted p-2 rounded">
                                {item}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </TabsContent>
                </Tabs>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
