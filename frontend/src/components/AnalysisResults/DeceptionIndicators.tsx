import React from 'react';
import { DeceptionIndicator, DeceptionIndicatorType, SeverityLevel } from '../../types/analysis.types';

interface DeceptionIndicatorsProps {
  indicators: DeceptionIndicator[];
}

const DeceptionIndicators: React.FC<DeceptionIndicatorsProps> = ({ indicators }) => {
  const getIndicatorIcon = (type: DeceptionIndicatorType): string => {
    const icons: Record<DeceptionIndicatorType, string> = {
      spoofing: '🎭',
      urgency: '⚡',
      authority: '👑',
      suspicious_links: '🔗',
      grammar: '📝'
    };
    return icons[type];
  };

  const getIndicatorLabel = (type: DeceptionIndicatorType): string => {
    const labels: Record<DeceptionIndicatorType, string> = {
      spoofing: 'Sender Spoofing',
      urgency: 'Urgency Tactics',
      authority: 'Authority Impersonation',
      suspicious_links: 'Suspicious Links',
      grammar: 'Grammar/Language Issues'
    };
    return labels[type];
  };

  const getSeverityColor = (severity: SeverityLevel): string => {
    const colors: Record<SeverityLevel, string> = {
      High: 'bg-red-100 text-red-800 border-red-200',
      Medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      Low: 'bg-blue-100 text-blue-800 border-blue-200'
    };
    return colors[severity];
  };

  const getSeverityIcon = (severity: SeverityLevel): string => {
    const icons: Record<SeverityLevel, string> = {
      High: '🔴',
      Medium: '🟡',
      Low: '🔵'
    };
    return icons[severity];
  };

  if (indicators.length === 0) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Deception Indicators
        </h3>
        <div className="text-center py-8">
          <div className="text-4xl mb-2">✅</div>
          <p className="text-gray-600 font-medium">No deception indicators detected</p>
          <p className="text-sm text-gray-500 mt-1">
            The email content appears to be straightforward without obvious social engineering tactics
          </p>
        </div>
      </div>
    );
  }

  const groupedIndicators = indicators.reduce((acc, indicator) => {
    if (!acc[indicator.severity]) {
      acc[indicator.severity] = [];
    }
    acc[indicator.severity].push(indicator);
    return acc;
  }, {} as Record<SeverityLevel, DeceptionIndicator[]>);

  const severityOrder: SeverityLevel[] = ['High', 'Medium', 'Low'];

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">
          Deception Indicators
        </h3>
        <span className="text-sm text-gray-500">
          {indicators.length} indicator{indicators.length !== 1 ? 's' : ''} detected
        </span>
      </div>

      <div className="space-y-4">
        {severityOrder.map(severity => {
          const severityIndicators = groupedIndicators[severity];
          if (!severityIndicators || severityIndicators.length === 0) return null;

          return (
            <div key={severity} className="space-y-3">
              <div className="flex items-center space-x-2">
                <span className="text-lg">{getSeverityIcon(severity)}</span>
                <h4 className="font-medium text-gray-800">
                  {severity} Severity ({severityIndicators.length})
                </h4>
              </div>

              <div className="space-y-3 ml-6">
                {severityIndicators.map((indicator, index) => (
                  <div
                    key={`${severity}-${index}`}
                    className={`border rounded-lg p-4 ${getSeverityColor(indicator.severity)}`}
                  >
                    <div className="flex items-start space-x-3">
                      <span className="text-xl flex-shrink-0 mt-0.5">
                        {getIndicatorIcon(indicator.type)}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-2">
                          <h5 className="font-medium text-gray-900">
                            {getIndicatorLabel(indicator.type)}
                          </h5>
                          <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(indicator.severity)}`}>
                            {indicator.severity}
                          </span>
                        </div>
                        
                        <p className="text-sm text-gray-700 mb-3">
                          {indicator.description}
                        </p>

                        <div className="bg-white bg-opacity-50 rounded p-3">
                          <h6 className="text-xs font-medium text-gray-600 mb-1">
                            Evidence Found:
                          </h6>
                          <p className="text-sm text-gray-800 font-mono bg-gray-100 p-2 rounded break-all">
                            "{indicator.evidence}"
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* Summary */}
      <div className="mt-6 p-4 bg-gray-50 rounded-lg">
        <h4 className="text-sm font-medium text-gray-700 mb-2">
          Analysis Summary:
        </h4>
        <div className="text-sm text-gray-600">
          <p className="mb-2">
            This email contains <strong>{indicators.length}</strong> deception indicator{indicators.length !== 1 ? 's' : ''} 
            commonly used in phishing attacks:
          </p>
          <ul className="list-disc list-inside space-y-1">
            {Object.entries(groupedIndicators).map(([severity, severityIndicators]) => (
              <li key={severity}>
                <strong>{severityIndicators.length}</strong> {severity.toLowerCase()} severity indicator{severityIndicators.length !== 1 ? 's' : ''}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-gray-500">
            These indicators help identify social engineering techniques used to manipulate recipients.
          </p>
        </div>
      </div>
    </div>
  );
};

export default DeceptionIndicators;