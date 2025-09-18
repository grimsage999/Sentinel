import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { AlertTriangle, Shield, Activity, Clock, User, TrendingUp, CheckCircle, XCircle, AlertCircle, ChevronRight, Eye, FileText, Brain, Users, BarChart3, Zap, Lock, Globe, Mail, Database, Terminal, Search, Filter, RefreshCw, Download } from 'lucide-react';

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

const CyberSentinelWorkbench = () => {
  const [alerts, setAlerts] = useState(generateMockAlerts());
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [viewMode, setViewMode] = useState('analyst'); // analyst, manager, executive
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [workflowStep, setWorkflowStep] = useState(0);
  const [threatIntelData, setThreatIntelData] = useState(null);
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
    setWorkflowStep(0);
    addAuditEntry('USER', `Opened alert ${alert.id} for investigation`);
    
    // Simulate threat intel lookup
    setTimeout(() => {
      setThreatIntelData({
        maliciousScore: Math.floor(Math.random() * 100),
        previousSightings: Math.floor(Math.random() * 50),
        threatActor: ['APT28', 'Lazarus', 'FIN7', 'Unknown'][Math.floor(Math.random() * 4)],
        iocs: [
          { type: 'IP', value: '192.168.1.' + Math.floor(Math.random() * 255), reputation: 'Malicious' },
          { type: 'Domain', value: 'suspicious-domain.com', reputation: 'Suspicious' },
          { type: 'Hash', value: 'a1b2c3d4e5f6...', reputation: 'Clean' }
        ]
      });
    }, 500);
  };

  const workflowSteps = [
    { title: 'Initial Triage', description: 'Verify alert authenticity and gather initial context' },
    { title: 'Threat Intelligence', description: 'Enrich with external threat data' },
    { title: 'Impact Assessment', description: 'Determine business impact and affected systems' },
    { title: 'Containment', description: 'Isolate affected systems if necessary' },
    { title: 'Documentation', description: 'Document findings and generate report' }
  ];

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

        {/* Right Panel - Alert Details & Workflow */}
        <div className="flex-1 overflow-y-auto">
          {selectedAlert ? (
            <div className="p-6">
              {/* Alert Header */}
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
                  <button className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 rounded-lg text-sm font-semibold transition-colors">
                    Take Ownership
                  </button>
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
                  <div>
                    <span className="text-gray-400">Affected Assets:</span>
                    <p>{selectedAlert.affectedAssets} systems</p>
                  </div>
                  <div>
                    <span className="text-gray-400">Business Impact:</span>
                    <p className={selectedAlert.businessImpact === 'High' ? 'text-red-400' : 'text-yellow-400'}>
                      {selectedAlert.businessImpact}
                    </p>
                  </div>
                  <div>
                    <span className="text-gray-400">Assigned To:</span>
                    <p>{selectedAlert.assignee}</p>
                  </div>
                </div>
              </div>

              {/* Threat Intelligence Panel */}
              {threatIntelData && (
                <div className="bg-gray-800 rounded-lg p-6 mb-6 border border-gray-700">
                  <h3 className="text-lg font-semibold mb-4 flex items-center">
                    <Globe className="w-5 h-5 mr-2 text-cyan-500" />
                    Threat Intelligence Enrichment
                  </h3>
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <div className="bg-gray-700 rounded-lg p-3">
                      <p className="text-xs text-gray-400 mb-1">Malicious Score</p>
                      <p className="text-2xl font-bold text-red-400">{threatIntelData.maliciousScore}/100</p>
                    </div>
                    <div className="bg-gray-700 rounded-lg p-3">
                      <p className="text-xs text-gray-400 mb-1">Previous Sightings</p>
                      <p className="text-2xl font-bold text-yellow-400">{threatIntelData.previousSightings}</p>
                    </div>
                    <div className="bg-gray-700 rounded-lg p-3">
                      <p className="text-xs text-gray-400 mb-1">Threat Actor</p>
                      <p className="text-lg font-bold text-purple-400">{threatIntelData.threatActor}</p>
                    </div>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400 mb-2">Indicators of Compromise (IOCs)</p>
                    <div className="space-y-2">
                      {threatIntelData.iocs.map((ioc, idx) => (
                        <div key={idx} className="flex items-center justify-between bg-gray-700 rounded p-2 text-sm">
                          <div className="flex items-center space-x-3">
                            <span className="text-gray-400">{ioc.type}:</span>
                            <code className="text-cyan-400">{ioc.value}</code>
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
                </div>
              )}

              {/* Guided Workflow */}
              <div className="bg-gray-800 rounded-lg p-6 mb-6 border border-gray-700">
                <h3 className="text-lg font-semibold mb-4 flex items-center">
                  <Zap className="w-5 h-5 mr-2 text-cyan-500" />
                  AI-Guided Response Workflow
                </h3>
                <div className="space-y-3">
                  {workflowSteps.map((step, idx) => (
                    <div
                      key={idx}
                      className={`flex items-center space-x-3 p-3 rounded-lg cursor-pointer transition-colors ${
                        idx === workflowStep ? 'bg-cyan-500/10 border border-cyan-500/30' :
                        idx < workflowStep ? 'bg-green-500/10 border border-green-500/30' :
                        'bg-gray-700 hover:bg-gray-600'
                      }`}
                      onClick={() => {
                        setWorkflowStep(idx);
                        addAuditEntry('USER', `Navigated to workflow step: ${step.title}`);
                      }}
                    >
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                        idx < workflowStep ? 'bg-green-500' :
                        idx === workflowStep ? 'bg-cyan-500' :
                        'bg-gray-600'
                      }`}>
                        {idx < workflowStep ? <CheckCircle className="w-5 h-5" /> : <span>{idx + 1}</span>}
                      </div>
                      <div className="flex-1">
                        <p className="font-semibold">{step.title}</p>
                        <p className="text-xs text-gray-400">{step.description}</p>
                      </div>
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    </div>
                  ))}
                </div>
                <div className="mt-4 flex space-x-3">
                  <button
                    onClick={() => {
                      if (workflowStep < workflowSteps.length - 1) {
                        setWorkflowStep(workflowStep + 1);
                        addAuditEntry('AI', `Recommended proceeding to: ${workflowSteps[workflowStep + 1].title}`);
                      }
                    }}
                    className="flex-1 px-4 py-2 bg-cyan-500 hover:bg-cyan-600 rounded-lg font-semibold transition-colors"
                    disabled={workflowStep >= workflowSteps.length - 1}
                  >
                    Continue Workflow
                  </button>
                  <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg font-semibold transition-colors">
                    Generate Report
                  </button>
                </div>
              </div>

              {/* Audit Log */}
              <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h3 className="text-lg font-semibold mb-4 flex items-center">
                  <FileText className="w-5 h-5 mr-2 text-cyan-500" />
                  Audit Trail
                </h3>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {auditLog.slice(0, 10).map((entry, idx) => (
                    <div key={idx} className="flex items-start space-x-3 text-sm">
                      <span className="text-gray-500 text-xs">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </span>
                      <span className={`font-semibold ${
                        entry.actor === 'AI' ? 'text-purple-400' :
                        entry.actor === 'SYSTEM' ? 'text-blue-400' :
                        'text-cyan-400'
                      }`}>
                        {entry.actor}:
                      </span>
                      <span className="text-gray-300">{entry.action}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-400">Select an alert to begin investigation</p>
                <p className="text-sm text-gray-500 mt-2">AI-powered triage and enrichment will activate automatically</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CyberSentinelWorkbench;