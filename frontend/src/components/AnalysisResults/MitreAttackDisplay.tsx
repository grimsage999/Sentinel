import React, { useState } from 'react';
import { MitreAttackEnhanced, MitreAttackAnalysis } from '../../types/analysis.types';

interface MitreAttackDisplayProps {
  mitreData?: MitreAttackEnhanced;
  basicMitreData?: MitreAttackAnalysis;
}

const MitreAttackDisplay: React.FC<MitreAttackDisplayProps> = ({ mitreData, basicMitreData }) => {
  const [activeTab, setActiveTab] = useState<'techniques' | 'narrative' | 'recommendations'>('techniques');

  // Check if we have either enhanced or basic MITRE data
  const hasEnhancedData = mitreData && mitreData.techniquesDetailed.length > 0;
  const hasBasicData = basicMitreData && basicMitreData.techniques.length > 0;

  if (!hasEnhancedData && !hasBasicData) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center space-x-3 mb-4">
          <div className="flex-shrink-0">
            <svg className="h-6 w-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div>
            <h3 className="text-lg font-medium text-gray-900">
              MITRE ATT&CK Analysis
            </h3>
            <p className="text-sm text-gray-500">
              No specific attack techniques identified
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Use enhanced data if available, otherwise fall back to basic data
  const displayData = hasEnhancedData ? mitreData! : null;
  const basicData = hasBasicData ? basicMitreData! : null;

  const getTacticColor = (tactic: string) => {
    const colors: Record<string, string> = {
      'initial-access': 'bg-red-100 text-red-800',
      'execution': 'bg-orange-100 text-orange-800',
      'persistence': 'bg-yellow-100 text-yellow-800',
      'privilege-escalation': 'bg-purple-100 text-purple-800',
      'defense-evasion': 'bg-blue-100 text-blue-800',
      'credential-access': 'bg-pink-100 text-pink-800',
      'discovery': 'bg-green-100 text-green-800',
      'collection': 'bg-indigo-100 text-indigo-800',
      'command-and-control': 'bg-gray-100 text-gray-800',
      'exfiltration': 'bg-red-100 text-red-800',
      'impact': 'bg-red-200 text-red-900'
    };
    return colors[tactic] || 'bg-gray-100 text-gray-800';
  };

  // Render enhanced data if available
  if (hasEnhancedData && displayData) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className="flex-shrink-0">
              <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div>
              <h3 className="text-lg font-medium text-gray-900">
                MITRE ATT&CK Analysis
              </h3>
              <p className="text-sm text-gray-500">
                {displayData.frameworkVersion} • {displayData.techniquesDetailed.length} techniques identified
              </p>
            </div>
          </div>
          
          <a
            href="https://attack.mitre.org/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-blue-600 hover:text-blue-800 font-medium"
          >
            View Framework →
          </a>
        </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'techniques', label: 'Techniques', count: mitreData.techniquesDetailed.length },
            { id: 'narrative', label: 'Attack Chain' },
            { id: 'recommendations', label: 'Recommendations' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.id
                  ? 'border-red-500 text-red-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.label}
              {tab.count && (
                <span className={`ml-2 py-0.5 px-2 rounded-full text-xs ${
                  activeTab === tab.id ? 'bg-red-100 text-red-600' : 'bg-gray-100 text-gray-600'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'techniques' && (
        <div className="space-y-4">
          {mitreData.techniquesDetailed.map((technique, index) => (
            <div key={technique.techniqueId} className="border border-gray-200 rounded-lg p-4">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <span className="font-mono text-sm font-medium text-gray-900">
                      {technique.techniqueId}
                    </span>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getTacticColor(technique.tactic)}`}>
                      {technique.tactic.replace('-', ' ')}
                    </span>
                  </div>
                  
                  <h4 className="text-base font-medium text-gray-900 mb-2">
                    {technique.name}
                  </h4>
                  
                  <p className="text-sm text-gray-600 mb-3">
                    {technique.description}
                  </p>
                  
                  <div className="bg-blue-50 border-l-4 border-blue-400 p-3 mb-3">
                    <p className="text-sm text-blue-800">
                      <span className="font-medium">Context:</span> {technique.context}
                    </p>
                  </div>
                  
                  <p className="text-xs text-gray-500">
                    <span className="font-medium">Tactic:</span> {technique.tacticDescription}
                  </p>
                </div>
                
                <div className="ml-4">
                  <a
                    href={technique.mitreUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center px-3 py-1.5 border border-gray-300 text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50"
                  >
                    View Details
                    <svg className="ml-1 h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                  </a>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'narrative' && (
        <div className="prose prose-sm max-w-none">
          <div className="bg-gray-50 rounded-lg p-4">
            <h4 className="text-sm font-medium text-gray-900 mb-3">Attack Chain Analysis</h4>
            <div className="text-sm text-gray-700 whitespace-pre-line">
              {mitreData.attackNarrativeDetailed || 'No detailed attack narrative available.'}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'recommendations' && (
        <div className="space-y-6">
          {mitreData.recommendations.immediateActions.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-red-900 mb-3 flex items-center">
                <svg className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
                Immediate Actions Required
              </h4>
              <ul className="space-y-2">
                {mitreData.recommendations.immediateActions.map((action, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <span className="flex-shrink-0 h-1.5 w-1.5 bg-red-500 rounded-full mt-2"></span>
                    <span className="text-sm text-gray-700">{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {mitreData.recommendations.securityControls.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-blue-900 mb-3 flex items-center">
                <svg className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Security Controls
              </h4>
              <ul className="space-y-2">
                {mitreData.recommendations.securityControls.map((control, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <span className="flex-shrink-0 h-1.5 w-1.5 bg-blue-500 rounded-full mt-2"></span>
                    <span className="text-sm text-gray-700">{control}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {mitreData.recommendations.userTraining.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-green-900 mb-3 flex items-center">
                <svg className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                </svg>
                User Training
              </h4>
              <ul className="space-y-2">
                {mitreData.recommendations.userTraining.map((training, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <span className="flex-shrink-0 h-1.5 w-1.5 bg-green-500 rounded-full mt-2"></span>
                    <span className="text-sm text-gray-700">{training}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {mitreData.recommendations.monitoring.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-purple-900 mb-3 flex items-center">
                <svg className="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
                Monitoring & Detection
              </h4>
              <ul className="space-y-2">
                {mitreData.recommendations.monitoring.map((monitor, index) => (
                  <li key={index} className="flex items-start space-x-2">
                    <span className="flex-shrink-0 h-1.5 w-1.5 bg-purple-500 rounded-full mt-2"></span>
                    <span className="text-sm text-gray-700">{monitor}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Footer */}
      <div className="mt-6 pt-4 border-t border-gray-200">
        <p className="text-xs text-gray-500">
          Analysis generated on {new Date(mitreData.analysisTimestamp).toLocaleString()} using {mitreData.frameworkVersion}
        </p>
        </div>
      </div>
    );
  }

  // Render basic data if enhanced data is not available
  if (hasBasicData && basicData) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className="flex-shrink-0">
              <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div>
              <h3 className="text-lg font-medium text-gray-900">
                MITRE ATT&CK Analysis
              </h3>
              <p className="text-sm text-gray-500">
                {basicData.techniques.length} techniques identified
              </p>
            </div>
          </div>
          
          <a
            href="https://attack.mitre.org/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-blue-600 hover:text-blue-800 font-medium"
          >
            View Framework →
          </a>
        </div>

        {/* Basic Techniques Display */}
        <div className="space-y-4">
          <div>
            <h4 className="text-sm font-medium text-gray-900 mb-3">Attack Techniques</h4>
            <div className="flex flex-wrap gap-2">
              {basicData.techniques.map((technique, index) => {
                // Convert T1566.002 to T1566/002 for URL path
                const urlPath = technique.replace('.', '/');
                return (
                <a
                  key={technique}
                  href={`https://attack.mitre.org/techniques/${urlPath}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium bg-red-100 text-red-800 hover:bg-red-200 transition-colors"
                >
                  {technique}
                  <svg className="ml-1 h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                </a>
                );
              })}
            </div>
          </div>

          {basicData.tactics.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-3">Tactics</h4>
              <div className="flex flex-wrap gap-2">
                {basicData.tactics.map((tactic, index) => (
                  <span
                    key={tactic}
                    className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getTacticColor(tactic)}`}
                  >
                    {tactic.replace('-', ' ')}
                  </span>
                ))}
              </div>
            </div>
          )}

          {basicData.attackNarrative && (
            <div>
              <h4 className="text-sm font-medium text-gray-900 mb-3">Attack Narrative</h4>
              <div className="bg-gray-50 rounded-lg p-4">
                <p className="text-sm text-gray-700">{basicData.attackNarrative}</p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="mt-6 pt-4 border-t border-gray-200">
          <p className="text-xs text-gray-500">
            Analysis generated using MITRE ATT&CK framework
          </p>
        </div>
      </div>
    );
  }

  return null;
};

export default MitreAttackDisplay;