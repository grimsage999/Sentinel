import { useState } from "react";
import { X, Search, Loader2 } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { api } from "@/lib/api";
import type { IOCParseResult, IOCEnrichmentResult } from "@/types";

interface IOCEnrichmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  alertId?: string;
}

interface EnrichedIOC {
  type: string;
  value: string;
  enrichment?: IOCEnrichmentResult['enrichment'];
  isEnriching?: boolean;
}

export default function IOCEnrichmentModal({ isOpen, onClose, alertId }: IOCEnrichmentModalProps) {
  const [rawContent, setRawContent] = useState("");
  const [isParsing, setIsParsing] = useState(false);
  const [parsedIOCs, setParsedIOCs] = useState<EnrichedIOC[]>([]);
  const { toast } = useToast();

  const sampleContent = `From: attacker@suspicious-phishing-site.com
To: ceo@company.com
Subject: Urgent Payment Required

Dear Sir/Madam,

Please visit http://suspicious-phishing-site.com/login.php and enter your credentials.

For verification, download the attachment from:
https://malicious-domain.com/file.exe

Hash: a1b2c3d4e5f67890abcdef1234567890

IP Address: 45.77.156.22

Best regards,
Finance Team`;

  const handleParseIOCs = async () => {
    if (!rawContent.trim()) {
      toast({
        title: "Error",
        description: "Please enter some content to parse",
        variant: "destructive"
      });
      return;
    }

    setIsParsing(true);
    try {
      const result: IOCParseResult = await api.parseIOCs(rawContent);
      
      if (result.success) {
        const allIOCs: EnrichedIOC[] = [
          ...result.iocs.ips.map(ip => ({ type: 'ip', value: ip })),
          ...result.iocs.domains.map(domain => ({ type: 'domain', value: domain })),
          ...result.iocs.urls.map(url => ({ type: 'url', value: url })),
          ...result.iocs.hashes.map(hash => ({ type: 'hash', value: hash }))
        ];
        
        setParsedIOCs(allIOCs);
        toast({
          title: "Success",
          description: `Parsed ${allIOCs.length} IOCs successfully`
        });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to parse IOCs",
        variant: "destructive"
      });
    } finally {
      setIsParsing(false);
    }
  };

  const handleEnrichIOC = async (ioc: EnrichedIOC, index: number) => {
    const updatedIOCs = [...parsedIOCs];
    updatedIOCs[index] = { ...ioc, isEnriching: true };
    setParsedIOCs(updatedIOCs);

    try {
      const result: IOCEnrichmentResult = await api.enrichIOC(ioc.type, ioc.value);
      
      if (result.success) {
        updatedIOCs[index] = { 
          ...ioc, 
          enrichment: result.enrichment, 
          isEnriching: false 
        };
        setParsedIOCs(updatedIOCs);
        
        if (alertId) {
          api.createAuditEntry("USER", `Enriched IOC ${ioc.value} for alert ${alertId}`, alertId);
        }
      }
    } catch (error) {
      updatedIOCs[index] = { ...ioc, isEnriching: false };
      setParsedIOCs(updatedIOCs);
      toast({
        title: "Error",
        description: `Failed to enrich ${ioc.type}: ${ioc.value}`,
        variant: "destructive"
      });
    }
  };

  const getReputationColor = (reputation: string) => {
    switch (reputation?.toLowerCase()) {
      case 'malicious':
        return 'bg-red-500/20 text-red-400 border-red-500/20';
      case 'suspicious':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/20';
      case 'clean':
        return 'bg-green-500/20 text-green-400 border-green-500/20';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/20';
    }
  };

  const handleLoadSample = () => {
    setRawContent(sampleContent);
  };

  const handleReset = () => {
    setRawContent("");
    setParsedIOCs([]);
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-6xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center justify-between">
            IOC Enrichment Dashboard
            <Button variant="ghost" size="sm" onClick={onClose} data-testid="button-close-ioc-modal">
              <X className="w-4 h-4" />
            </Button>
          </DialogTitle>
        </DialogHeader>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Section */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold">Raw Email Content</h3>
              <div className="space-x-2">
                <Button variant="outline" size="sm" onClick={handleLoadSample} data-testid="button-load-sample">
                  Load Sample
                </Button>
                <Button variant="outline" size="sm" onClick={handleReset} data-testid="button-reset">
                  Reset
                </Button>
              </div>
            </div>
            <Textarea
              placeholder="Paste the raw email content here..."
              value={rawContent}
              onChange={(e) => setRawContent(e.target.value)}
              className="h-64 font-mono text-sm resize-none"
              data-testid="textarea-raw-content"
            />
            <Button 
              onClick={handleParseIOCs} 
              disabled={isParsing || !rawContent.trim()}
              className="w-full"
              data-testid="button-parse-iocs"
            >
              {isParsing ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Parsing...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 mr-2" />
                  Parse IOCs
                </>
              )}
            </Button>
          </div>

          {/* Results Section */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Extracted IOCs</h3>
            <div className="bg-card rounded-lg p-4 max-h-96 overflow-y-auto scroll-area border border-border">
              {parsedIOCs.length === 0 ? (
                <div className="text-center text-muted-foreground py-8">
                  Parse the email content to extract IOCs
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Group IOCs by type */}
                  {['ip', 'domain', 'url', 'hash'].map(type => {
                    const iocsOfType = parsedIOCs.filter(ioc => ioc.type === type);
                    if (iocsOfType.length === 0) return null;

                    return (
                      <div key={type}>
                        <h4 className="text-sm font-semibold text-muted-foreground mb-3 capitalize">
                          {type === 'ip' ? 'IP Addresses' : 
                           type === 'hash' ? 'File Hashes' : 
                           `${type}s`} ({iocsOfType.length})
                        </h4>
                        <div className="space-y-2">
                          {iocsOfType.map((ioc, idx) => (
                            <div key={`${type}-${idx}`} className="bg-background rounded-lg p-3 border border-border">
                              <div className="flex items-center justify-between mb-2">
                                <span className="font-mono text-sm break-all" data-testid={`text-ioc-value-${type}-${idx}`}>
                                  {ioc.value}
                                </span>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => handleEnrichIOC(ioc, parsedIOCs.indexOf(ioc))}
                                  disabled={ioc.isEnriching || !!ioc.enrichment}
                                  data-testid={`button-enrich-${type}-${idx}`}
                                >
                                  {ioc.isEnriching ? (
                                    <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                                  ) : (
                                    <Search className="w-3 h-3 mr-1" />
                                  )}
                                  {ioc.enrichment ? 'Enriched' : 'Enrich'}
                                </Button>
                              </div>
                              {ioc.enrichment && (
                                <div className="p-2 bg-secondary rounded border-l-4 border-primary">
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="text-xs text-muted-foreground">
                                      Source: {ioc.enrichment.source}
                                    </span>
                                    {ioc.enrichment.reputation && (
                                      <span className={`px-2 py-1 text-xs rounded-full border ${getReputationColor(ioc.enrichment.reputation)}`}>
                                        {ioc.enrichment.reputation}
                                      </span>
                                    )}
                                  </div>
                                  <div className="space-y-1 text-xs text-muted-foreground">
                                    {Object.entries(ioc.enrichment).map(([key, value]) => {
                                      if (key === 'source' || key === 'reputation') return null;
                                      return (
                                        <div key={key}>
                                          <span className="capitalize">{key.replace(/([A-Z])/g, ' $1')}: </span>
                                          <span>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
                                        </div>
                                      );
                                    })}
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
