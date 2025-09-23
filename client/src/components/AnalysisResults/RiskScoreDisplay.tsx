import React from 'react';
import { AnalysisResult, ConfidenceLevel } from '../../types/analysis.types';

interface RiskScoreDisplayProps {
  riskScore: AnalysisResult['riskScore'];
}

const RiskScoreDisplay: React.FC<RiskScoreDisplayProps> = ({ riskScore }) => {
  const getRiskLevel = (score: number): { level: string; color: string; bgColor: string } => {
    if (score >= 8) {
      return {
        level: 'Critical',
        color: 'text-red-700',
        bgColor: 'bg-red-50 border-red-200'
      };
    } else if (score >= 6) {
      return {
        level: 'High',
        color: 'text-orange-700',
        bgColor: 'bg-orange-50 border-orange-200'
      };
    } else if (score >= 4) {
      return {
        level: 'Medium',
        color: 'text-yellow-700',
        bgColor: 'bg-yellow-50 border-yellow-200'
      };
    } else if (score >= 2) {
      return {
        level: 'Low',
        color: 'text-blue-700',
        bgColor: 'bg-blue-50 border-blue-200'
      };
    } else {
      return {
        level: 'Minimal',
        color: 'text-green-700',
        bgColor: 'bg-green-50 border-green-200'
      };
    }
  };

  const getConfidenceColor = (confidence: ConfidenceLevel): string => {
    const colors: Record<ConfidenceLevel, string> = {
      High: 'text-green-600',
      Medium: 'text-yellow-600',
      Low: 'text-red-600'
    };
    return colors[confidence];
  };

  const getScoreBarColor = (score: number): string => {
    if (score >= 8) return 'bg-red-500';
    if (score >= 6) return 'bg-orange-500';
    if (score >= 4) return 'bg-yellow-500';
    if (score >= 2) return 'bg-blue-500';
    return 'bg-green-500';
  };

  const risk = getRiskLevel(riskScore.score);
  const percentage = (riskScore.score / 10) * 100;

  return (
    <div className={`rounded-lg border p-6 ${risk.bgColor}`}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-gray-900">
          Risk Assessment
        </h3>
        <div className="flex items-center space-x-2">
          <span className={`text-sm font-medium ${getConfidenceColor(riskScore.confidence)}`}>
            {riskScore.confidence} Confidence
          </span>
        </div>
      </div>

      {/* Risk Score Display */}
      <div className="mb-6">
        <div className="flex items-end space-x-4 mb-3">
          <div className="text-center">
            <div className={`text-4xl font-bold ${risk.color}`}>
              {riskScore.score}
            </div>
            <div className="text-sm text-gray-600">out of 10</div>
          </div>
          <div className="flex-1">
            <div className={`text-lg font-semibold ${risk.color} mb-1`}>
              {risk.level} Risk
            </div>
            <div className="w-full bg-gray-200 rounded-full h-3">
              <div
                className={`h-3 rounded-full transition-all duration-500 ${getScoreBarColor(riskScore.score)}`}
                style={{ width: `${percentage}%` }}
              />
            </div>
            <div className="flex justify-between text-xs text-gray-500 mt-1">
              <span>0</span>
              <span>5</span>
              <span>10</span>
            </div>
          </div>
        </div>
      </div>

      {/* Risk Level Descriptions */}
      <div className="mb-4">
        <h4 className="text-sm font-medium text-gray-700 mb-2">
          Risk Level Guide:
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-500 rounded"></div>
            <span className="text-gray-600">0-1: Minimal Risk</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-blue-500 rounded"></div>
            <span className="text-gray-600">2-3: Low Risk</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-yellow-500 rounded"></div>
            <span className="text-gray-600">4-5: Medium Risk</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-orange-500 rounded"></div>
            <span className="text-gray-600">6-7: High Risk</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-red-500 rounded"></div>
            <span className="text-gray-600">8-10: Critical Risk</span>
          </div>
        </div>
      </div>

      {/* Reasoning */}
      <div className="border-t border-gray-200 pt-4">
        <h4 className="text-sm font-medium text-gray-700 mb-2">
          Risk Assessment Reasoning:
        </h4>
        <p className="text-sm text-gray-600 leading-relaxed">
          {riskScore.reasoning}
        </p>
      </div>

      {/* Action Recommendations */}
      <div className="mt-4 p-3 bg-white bg-opacity-50 rounded-md">
        <h4 className="text-sm font-medium text-gray-700 mb-2">
          Recommended Actions:
        </h4>
        <div className="text-sm text-gray-600">
          {riskScore.score >= 8 && (
            <ul className="list-disc list-inside space-y-1">
              <li>Immediately block sender and quarantine email</li>
              <li>Alert security team and affected users</li>
              <li>Investigate for potential compromise</li>
              <li>Consider threat hunting activities</li>
            </ul>
          )}
          {riskScore.score >= 6 && riskScore.score < 8 && (
            <ul className="list-disc list-inside space-y-1">
              <li>Block sender and quarantine email</li>
              <li>Notify affected users about the threat</li>
              <li>Monitor for similar attacks</li>
              <li>Update security controls if needed</li>
            </ul>
          )}
          {riskScore.score >= 4 && riskScore.score < 6 && (
            <ul className="list-disc list-inside space-y-1">
              <li>Review email content carefully</li>
              <li>Consider blocking sender</li>
              <li>Educate users about this threat type</li>
              <li>Monitor for escalation</li>
            </ul>
          )}
          {riskScore.score >= 2 && riskScore.score < 4 && (
            <ul className="list-disc list-inside space-y-1">
              <li>Monitor sender for suspicious activity</li>
              <li>Document findings for trend analysis</li>
              <li>Consider additional verification</li>
            </ul>
          )}
          {riskScore.score < 2 && (
            <ul className="list-disc list-inside space-y-1">
              <li>Email appears legitimate</li>
              <li>Continue normal monitoring</li>
              <li>Document for baseline analysis</li>
            </ul>
          )}
        </div>
      </div>
    </div>
  );
};

export default RiskScoreDisplay;