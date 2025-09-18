import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { AlertTriangle, Shield, Activity, Clock, User, TrendingUp, CheckCircle, XCircle, AlertCircle, ChevronRight, Eye, FileText, Brain, Users, BarChart3, Zap, Lock, Globe, Mail, Database, Terminal, Search, Filter, RefreshCw, Download, Send, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button.jsx';
import './App.css';

// Mock data generation
const generateMockAlerts = () => {
  const alertTypes = ['Phishing Email', 'Suspicious Login', 'Data Exfiltration', 'Malware Detection', 'BEC Attempt', 'Credential Harvesting'];
  const severities = ['Critical', 'High', 'Medium', 'Low'];
  const sources = ['Email Gateway', 'SIEM', 'EDR', 'Network Monitor', 'Cloud Security'];
  
  return Array.from({ length: 50 }, (_, i) => ({
    id: `ALT-${String(i + 1).padStart(5, '0')}`,
    type: alertTypes[Math.floor(Math.random() * alertTypes.length)],
    severity: severities[Math.floor(Math.random() * severities.length)],
    source: sources[Math.floor(Math.random() * sources.length)],
    timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
    status: ['New', 'Triaging', 'Investigating', 'Resolved'][Math.floor(Math.random() * 4)],
    confidence: Math.floor(Math.random() * 40) + 60,
    affectedAssets: Math.floor(Math.random() * 10) + 1,
    businessImpact: ['High', 'Medium', 'Low'][Math.floor(Math.random() * 3)],
    assignee: ['Unassigned', 'John D.', 'Sarah M.', 'Mike R.'][Math.floor(Math.random() * 4)],
    aiTriaged: Math.random() > 0.3
  }));
};

const IOCEnrichmentDashboard = ({ selectedAlert, onClose }) => {
  const [rawText, setRawText] = useState('');
  const [parsedIOCs, setParsedIOCs] = useState(null);
  const [enrichmentResults, setEnrichmentResults] = useState({});
  const [isParsingIOCs, setIsParsingIOCs] = useState(false);
  const [enrichingIOCs, setEnrichingIOCs] = useState(new Set());

  const parseIOCs = async () => {
    if (!rawText.trim()) return;
    
    setIsParsingIOCs(true);
    try {
      const response = await fetch('https://19hninc0xkg1.manus.space/api/parse_iocs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ text: rawText }),
      });
      
      const data = await response.json();
      if (data.success) {
        setParsedIOCs(data.iocs);
      }
    } catch (error) {
      console.error('Error parsing IOCs:', error);
    } finally {
      setIsParsingIOCs(false);
    }
  };

  const enrichIOC = async (iocType, iocValue) => {
    const key = `${iocType}-${iocValue}`;
    setEnrichingIOCs(prev => new Set([...prev, key]));
    
    try {
      const response = await fetch('https://19hninc0xkg1.manus.space/api/enrich_ioc', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          ioc_type: iocType, 
          ioc_value: iocValue 
        }),
      });
      
      const data = await response.json();
      if (data.success) {
        setEnrichmentResults(prev => ({
          ...prev,
          [key]: data.enrichment
        }));
      }
    } catch (error) {
      console.error('Error enriching IOC:', error);
    } finally {
      setEnrichingIOCs(prev => {
        const newSet = new Set(prev);
        newSet.delete(key);
        return newSet;
      });
    }
  };

  const getReputationColor = (reputation) => {
    switch (reputation?.toLowerCase()) {
      case 'malicious':
        return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'suspicious':
        return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'clean':
        return 'text-green-500 bg-green-500/10 border-green-500/20';
      default:
        return 'text-gray-500 bg-gray-500/10 border-gray-500/20';
    }
  };

  const renderIOCSection = (title, iocs, iocType) => {
    if (!iocs || iocs.length === 0) return null;

    return (
      <div className="mb-6">
        <h4 className="text-sm font-semibold text-gray-300 mb-3">{title} ({iocs.length})</h4>
        <div className="space-y-2">
          {iocs.map((ioc, index) => {
            const key = `${iocType}-${ioc}`;
            const enrichment = enrichmentResults[key];
            const isEnriching = enrichingIOCs.has(key);

            return (
              <div key={index} className="bg-gray-800 rounded-lg p-3 border border-gray-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-sm text-gray-300 break-all">{ioc}</span>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => enrichIOC(iocType, ioc)}
                    disabled={isEnriching || enrichment}
                    className="ml-2 flex-shrink-0"
                  >
                    {isEnriching ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : enrichment ? (
                      <CheckCircle className="w-3 h-3" />
                    ) : (
                      <Search className="w-3 h-3" />
                    )}
                    {isEnriching ? 'Enriching...' : enrichment ? 'Enriched' : 'Enrich'}
                  </Button>
                </div>
                
                {enrichment && (
                  <div className="mt-2 p-2 bg-gray-700 rounded border-l-4 border-cyan-500">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-400">Source: {enrichment.source}</span>
                      <span className={`px-2 py-1 text-xs rounded-full border ${getReputationColor(enrichment.reputation)}`}>
                        {enrichment.reputation}
                      </span>
                    </div>
                    
                    {enrichment.detection_ratio && (
                      <div className="text-xs text-gray-400 mb-1">
                        Detection: {enrichment.detection_ratio}
                      </div>
                    )}
                    
                    {enrichment.abuse_confidence && (
                      <div className="text-xs text-gray-400 mb-1">
                        Abuse Confidence: {enrichment.abuse_confidence}%
                      </div>
                    )}
                    
                    {enrichment.country && (
                      <div className="text-xs text-gray-400 mb-1">
                        Country: {enrichment.country}
                      </div>
                    )}
                    
                    {enrichment.categories && (
                      <div className="text-xs text-gray-400">
                        Categories: {enrichment.categories.join(', ')}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-900 rounded-lg p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-white">IOC Enrichment Dashboard</h2>
          <Button variant="ghost" onClick={onClose}>
            <XCircle className="w-5 h-5" />
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input Section */}
          <div>
            <h3 className="text-lg font-semibold text-white mb-4">Raw Email Content</h3>
            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste the raw email content here..."
              className="w-full h-64 p-3 bg-gray-800 border border-gray-700 rounded-lg text-gray-300 font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
            <Button
              onClick={parseIOCs}
              disabled={!rawText.trim() || isParsingIOCs}
              className="mt-3 w-full"
            >
              {isParsingIOCs ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Parsing IOCs...
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
          <div>
            <h3 className="text-lg font-semibold text-white mb-4">Extracted IOCs</h3>
            {parsedIOCs ? (
              <div className="bg-gray-800 rounded-lg p-4 max-h-96 overflow-y-auto">
                {renderIOCSection('IP Addresses', parsedIOCs.ips, 'ip')}
                {renderIOCSection('Domains', parsedIOCs.domains, 'domain')}
                {renderIOCSection('URLs', parsedIOCs.urls, 'url')}
                {renderIOCSection('File Hashes', parsedIOCs.hashes, 'hash')}
                
                {(!parsedIOCs.ips?.length && !parsedIOCs.domains?.length && 
                  !parsedIOCs.urls?.length && !parsedIOCs.hashes?.length) && (
                  <div className="text-center text-gray-400 py-8">
                    No IOCs found in the provided text.
                  </div>
                )}
              </div>
            ) : (
              <div className="bg-gray-800 rounded-lg p-4 text-center text-gray-400">
                Parse the email content to extract IOCs
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const CyberSentinelWorkbench = () => {
  const [alerts, setAlerts] = useState(generateMockAlerts());
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [viewMode, setViewMode] = useState('analyst'); // analyst, manager, executive
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showIOCDashboard, setShowIOCDashboard] = useState(false);
  const [auditLog, setAuditLog] = useState([]);

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      if (Math.random() > 0.7) {
        const newAlert = generateMockAlerts()[0];
        setAlerts(prev => [newAlert, ...prev.slice(0, 49)]);
        addAuditEntry('SYSTEM', `New alert detected: ${newAlert.id}`);
      }
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const addAuditEntry = (actor, action) => {
    setAuditLog(prev => [{
      timestamp: new Date().toISOString(),
      actor,
      action
    }, ...prev]);
  };

  const refreshData = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setAlerts(generateMockAlerts());
      setIsRefreshing(false);
      addAuditEntry('USER', 'Manually refreshed alert dashboard');
    }, 1000);
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter(alert => {
      const matchesSeverity = filterSeverity === 'all' || alert.severity === filterSeverity;
      const matchesSearch = alert.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           alert.type.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesSeverity && matchesSearch;
    });
  }, [alerts, filterSeverity, searchQuery]);

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'text-red-500 bg-red-500/10 border-red-500/20',
      'High': 'text-orange-500 bg-orange-500/10 border-orange-500/20',
      'Medium': 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20',
      'Low': 'text-blue-500 bg-blue-500/10 border-blue-500/20'
    };
    return colors[severity] || 'text-gray-500';
  };

  const getStatusIcon = (status) => {
    const icons = {
      'New': <AlertCircle className="w-4 h-4" />,
      'Triaging': <Clock className="w-4 h-4" />,
      'Investigating': <Search className="w-4 h-4" />,
      'Resolved': <CheckCircle className="w-4 h-4" />
    };
    return icons[status] || null;
  };

  const handleAlertClick = (alert) => {
    setSelectedAlert(alert);
    addAuditEntry('USER', `Opened alert ${alert.id} for investigation`);
  };

  // Role-based dashboard metrics
  const getDashboardMetrics = () => {
    const criticalCount = alerts.filter(a => a.severity === 'Critical').length;
    const highCount = alerts.filter(a => a.severity === 'High').length;
    const resolvedToday = alerts.filter(a => a.status === 'Resolved').length;
    const avgResponseTime = Math.floor(Math.random() * 30) + 10;

    if (viewMode === 'executive') {
      return {
        title: 'Executive Risk Dashboard',
        metrics: [
          { label: 'Risk Score', value: '78/100', icon: <Shield className="w-5 h-5" />, color: 'text-orange-500' },
          { label: 'Business Impact', value: '$2.3M at risk', icon: <TrendingUp className="w-5 h-5" />, color: 'text-red-500' },
          { label: 'Compliance Status', value: '92%', icon: <CheckCircle className="w-5 h-5" />, color: 'text-green-500' },
          { label: 'Incidents This Month', value: '47', icon: <BarChart3 className="w-5 h-5" />, color: 'text-blue-500' }
        ]
      };
    } else if (viewMode === 'manager') {
      return {
        title: 'SOC Operations Dashboard',
        metrics: [
          { label: 'Team Utilization', value: '87%', icon: <Users className="w-5 h-5" />, color: 'text-purple-500' },
          { label: 'Avg Response Time', value: `${avgResponseTime} min`, icon: <Clock className="w-5 h-5" />, color: 'text-yellow-500' },
          { label: 'Resolved Today', value: resolvedToday, icon: <CheckCircle className="w-5 h-5" />, color: 'text-green-500' },
          { label: 'Pending Critical', value: criticalCount, icon: <AlertTriangle className="w-5 h-5" />, color: 'text-red-500' }
        ]
      };
    } else {
      return {
        title: 'Analyst Operations Center',
        metrics: [
          { label: 'Critical Alerts', value: criticalCount, icon: <AlertTriangle className="w-5 h-5" />, color: 'text-red-500' },
          { label: 'High Priority', value: highCount, icon: <Shield className="w-5 h-5" />, color: 'text-orange-500' },
          { label: 'AI Triaged', value: `${Math.floor(alerts.filter(a => a.aiTriaged).length / alerts.length * 100)}%`, icon: <Brain className="w-5 h-5" />, color: 'text-purple-500' },
          { label: 'Active Incidents', value: alerts.filter(a => a.status !== 'Resolved').length, icon: <Activity className="w-5 h-5" />, color: 'text-blue-500' }
        ]
      };
    }
  };

  const dashboardMetrics = getDashboardMetrics();

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex justify-between items-center">
          <div className="flex items-center space-x-4">
            <Shield className="w-8 h-8 text-cyan-500" />
            <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-500 to-blue-500 bg-clip-text text-transparent">
              Cyber-Sentinel Workbench
            </h1>
          </div>
          <div className="flex items-center space-x-4">
            <Button
              onClick={() => setShowIOCDashboard(true)}
              className="bg-cyan-500 hover:bg-cyan-600"
            >
              <Zap className="w-4 h-4 mr-2" />
              IOC Enrichment
            </Button>
            <div className="flex bg-gray-700 rounded-lg p-1">
              <button
                onClick={() => setViewMode('analyst')}
                className={`px-4 py-2 rounded ${viewMode === 'analyst' ? 'bg-cyan-500 text-white' : 'text-gray-400 hover:text-white'}`}
              >
                <Terminal className="w-4 h-4 inline mr-2" />
                Analyst
              </button>
              <button
                onClick={() => setViewMode('manager')}
                className={`px-4 py-2 rounded ${viewMode === 'manager' ? 'bg-cyan-500 text-white' : 'text-gray-400 hover:text-white'}`}
              >
                <Users className="w-4 h-4 inline mr-2" />
                Manager
              </button>
              <button
                onClick={() => setViewMode('executive')}
                className={`px-4 py-2 rounded ${viewMode === 'executive' ? 'bg-cyan-500 text-white' : 'text-gray-400 hover:text-white'}`}
              >
                <BarChart3 className="w-4 h-4 inline mr-2" />
                Executive
              </button>
            </div>
            <button
              onClick={refreshData}
              className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
              disabled={isRefreshing}
            >
              <RefreshCw className={`w-5 h-5 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Metrics Bar */}
      <div className="bg-gray-800/50 px-6 py-4 border-b border-gray-700">
        <h2 className="text-sm font-semibold text-gray-400 mb-3">{dashboardMetrics.title}</h2>
        <div className="grid grid-cols-4 gap-4">
          {dashboardMetrics.metrics.map((metric, idx) => (
            <div key={idx} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400">{metric.label}</p>
                  <p className={`text-2xl font-bold ${metric.color}`}>{metric.value}</p>
                </div>
                <div className={`${metric.color} opacity-50`}>{metric.icon}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex h-[calc(100vh-200px)]">
        {/* Left Panel - Alerts List */}
        <div className="w-1/3 bg-gray-800 border-r border-gray-700 overflow-y-auto">
          <div className="p-4 border-b border-gray-700 sticky top-0 bg-gray-800 z-10">
            <div className="flex items-center space-x-2 mb-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search alerts..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-gray-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
              </div>
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="px-3 py-2 bg-gray-700 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <option value="all">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
            <div className="flex items-center justify-between text-xs text-gray-400">
              <span>{filteredAlerts.length} alerts</span>
              <span>{alerts.filter(a => a.status === 'New').length} new</span>
            </div>
          </div>

          <div className="divide-y divide-gray-700">
            {filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                onClick={() => handleAlertClick(alert)}
                className={`p-4 hover:bg-gray-700 cursor-pointer transition-colors ${
                  selectedAlert?.id === alert.id ? 'bg-gray-700 border-l-4 border-cyan-500' : ''
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-1 text-xs rounded-full border ${getSeverityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                    {alert.aiTriaged && (
                      <span className="px-2 py-1 text-xs rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20">
                        <Brain className="w-3 h-3 inline mr-1" />
                        AI
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-gray-500">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <h3 className="font-semibold text-sm mb-1">{alert.type}</h3>
                <p className="text-xs text-gray-400 mb-2">{alert.id} • {alert.source}</p>
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-2 text-gray-400">
                    {getStatusIcon(alert.status)}
                    <span>{alert.status}</span>
                  </div>
                  <span className="text-gray-500">{alert.assignee}</span>
                </div>
                {alert.confidence && (
                  <div className="mt-2">
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="text-gray-400">AI Confidence</span>
                      <span className="text-cyan-400">{alert.confidence}%</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-1">
                      <div
                        className="bg-gradient-to-r from-cyan-500 to-blue-500 h-1 rounded-full"
                        style={{ width: `${alert.confidence}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Right Panel - Alert Details */}
        <div className="flex-1 overflow-y-auto">
          {selectedAlert ? (
            <div className="p-6">
              <div className="bg-gray-800 rounded-lg p-6 mb-6 border border-gray-700">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <h2 className="text-xl font-bold">{selectedAlert.type}</h2>
                    <span className={`px-3 py-1 text-sm rounded-full border ${getSeverityColor(selectedAlert.severity)}`}>
                      {selectedAlert.severity}
                    </span>
                    <span className="px-3 py-1 text-sm rounded-full bg-gray-700 text-gray-300">
                      {selectedAlert.status}
                    </span>
                  </div>
                  <Button className="bg-cyan-500 hover:bg-cyan-600">
                    Take Ownership
                  </Button>
                </div>

                <div className="grid grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-gray-400">Alert ID:</span>
                    <p className="font-mono">{selectedAlert.id}</p>
                  </div>
                  <div>
                    <span className="text-gray-400">Source:</span>
                    <p>{selectedAlert.source}</p>
                  </div>
                  <div>
                    <span className="text-gray-400">Timestamp:</span>
                    <p>{new Date(selectedAlert.timestamp).toLocaleString()}</p>
                  </div>
                </div>
              </div>

              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-lg font-semibold mb-4">Investigation Details</h3>
                <p className="text-gray-300 mb-4">
                  This {selectedAlert.type.toLowerCase()} alert was detected by {selectedAlert.source} with {selectedAlert.confidence}% confidence.
                  The incident affects {selectedAlert.affectedAssets} asset(s) and has a {selectedAlert.businessImpact.toLowerCase()} business impact.
                </p>
                
                <div className="flex space-x-4">
                  <Button 
                    variant="outline"
                    onClick={() => setShowIOCDashboard(true)}
                  >
                    <Zap className="w-4 h-4 mr-2" />
                    Analyze IOCs
                  </Button>
                  <Button variant="outline">
                    <FileText className="w-4 h-4 mr-2" />
                    Generate Report
                  </Button>
                  <Button variant="outline">
                    <Shield className="w-4 h-4 mr-2" />
                    Contain Threat
                  </Button>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-full">
              <div className="text-center text-gray-400">
                <AlertCircle className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-semibold mb-2">No Alert Selected</h3>
                <p>Select an alert from the list to view details and begin investigation.</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* IOC Enrichment Dashboard Modal */}
      {showIOCDashboard && (
        <IOCEnrichmentDashboard
          selectedAlert={selectedAlert}
          onClose={() => setShowIOCDashboard(false)}
        />
      )}
    </div>
  );
};

function App() {
  return <CyberSentinelWorkbench />;
}

export default App;

