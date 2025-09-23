import React from 'react';
import { AnalysisResult, IntentType, ConfidenceLevel } from '../../types/analysis.types';

interface IntentDisplayProps {
  intent: AnalysisResult['intent'];
}

const IntentDisplay: React.FC<IntentDisplayProps> = ({ intent }) => {
  const getIntentLabel = (intentType: IntentType): string => {
    const labels: Record<IntentType, string> = {
      credential_theft: 'Credential Theft',
      wire_transfer: 'Wire Transfer Fraud',
      malware_delivery: 'Malware Delivery',
      reconnaissance: 'Reconnaissance',
      other: 'Other'
    };
    return labels[intentType];
  };

  const getIntentIcon = (intentType: IntentType): string => {
    const icons: Record<IntentType, string> = {
      credential_theft: '🔑',
      wire_transfer: '💰',
      malware_delivery: '🦠',
      reconnaissance: '🔍',
      other: '❓'
    };
    return icons[intentType];
  };

  const getIntentColor = (intentType: IntentType): string => {
    const colors: Record<IntentType, string> = {
      credential_theft: 'bg-red-100 text-red-800 border-red-200',
      wire_transfer: 'bg-orange-100 text-orange-800 border-orange-200',
      malware_delivery: 'bg-purple-100 text-purple-800 border-purple-200',
      reconnaissance: 'bg-blue-100 text-blue-800 border-blue-200',
      other: 'bg-gray-100 text-gray-800 border-gray-200'
    };
    return colors[intentType];
  };

  // const getConfidenceColor = (confidence: ConfidenceLevel): string => {
  //   const colors: Record<ConfidenceLevel, string> = {
  //     High: 'text-green-600',
  //     Medium: 'text-yellow-600',
  //     Low: 'text-red-600'
  //   };
  //   return colors[confidence];
  // };

  const getConfidenceBadgeColor = (confidence: ConfidenceLevel): string => {
    const colors: Record<ConfidenceLevel, string> = {
      High: 'bg-green-100 text-green-800 border-green-200',
      Medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      Low: 'bg-red-100 text-red-800 border-red-200'
    };
    return colors[confidence];
  };

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">
          Threat Intent Analysis
        </h3>
        <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getConfidenceBadgeColor(intent.confidence)}`}>
          {intent.confidence} Confidence
        </span>
      </div>

      {/* Primary Intent */}
      <div className="mb-4">
        <div className="flex items-center space-x-3 mb-2">
          <span className="text-2xl">{getIntentIcon(intent.primary)}</span>
          <div>
            <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getIntentColor(intent.primary)}`}>
              {getIntentLabel(intent.primary)}
            </span>
          </div>
        </div>
        <p className="text-sm text-gray-600 ml-11">
          Primary threat classification based on email content analysis
        </p>
      </div>

      {/* Alternative Intents */}
      {intent.alternatives && intent.alternatives.length > 0 && (
        <div className="border-t border-gray-100 pt-4">
          <h4 className="text-sm font-medium text-gray-700 mb-3">
            Alternative Classifications
          </h4>
          <div className="flex flex-wrap gap-2">
            {intent.alternatives.map((altIntent, index) => (
              <span
                key={index}
                className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium border ${getIntentColor(altIntent)}`}
              >
                <span className="mr-1">{getIntentIcon(altIntent)}</span>
                {getIntentLabel(altIntent)}
              </span>
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-2">
            Secondary threat patterns detected in the analysis
          </p>
        </div>
      )}

      {/* Intent Descriptions */}
      <div className="mt-4 p-3 bg-gray-50 rounded-md">
        <h4 className="text-sm font-medium text-gray-700 mb-2">
          What this means:
        </h4>
        <div className="text-sm text-gray-600">
          {intent.primary === 'credential_theft' && (
            <p>This email appears to be attempting to steal login credentials, passwords, or other authentication information.</p>
          )}
          {intent.primary === 'wire_transfer' && (
            <p>This email appears to be a business email compromise (BEC) attempt targeting financial transactions or wire transfers.</p>
          )}
          {intent.primary === 'malware_delivery' && (
            <p>This email appears to be attempting to deliver malicious software through attachments or links.</p>
          )}
          {intent.primary === 'reconnaissance' && (
            <p>This email appears to be gathering information about the organization or individuals for future attacks.</p>
          )}
          {intent.primary === 'other' && (
            <p>This email contains suspicious elements but doesn't fit standard phishing categories. Manual review recommended.</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default IntentDisplay;