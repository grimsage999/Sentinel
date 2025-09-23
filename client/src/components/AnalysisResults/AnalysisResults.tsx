import React from 'react';
import { AnalysisResult } from '../../types/analysis.types';
import IntentDisplay from './IntentDisplay';
import DeceptionIndicators from './DeceptionIndicators';
import RiskScoreDisplay from './RiskScoreDisplay';
import IOCList from '../IOCList/IOCList';
import MitreAttackDisplay from './MitreAttackDisplay';

interface AnalysisResultsProps {
  result: AnalysisResult;
  isLoading?: boolean;
  error?: string | null;
}

const AnalysisResults: React.FC<AnalysisResultsProps> = ({ 
  result, 
  isLoading = false, 
  error = null 
}) => {
  // Loading state
  if (isLoading) {
    return (
      <div className="w-full max-w-6xl mx-auto p-6">
        <div className="animate-pulse">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Loading placeholders */}
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="bg-gray-200 rounded-lg h-64"></div>
            ))}
          </div>
        </div>
        <div className="text-center mt-6">
          <div className="inline-flex items-center space-x-2 text-gray-600">
            <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Analyzing email content...</span>
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="w-full max-w-6xl mx-auto p-6">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6">
          <div className="flex items-center space-x-3">
            <svg className="h-6 w-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <h3 className="text-lg font-medium text-red-800">
                Analysis Failed
              </h3>
              <p className="text-red-700 mt-1">
                {error}
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-6xl mx-auto p-6">
      {/* Header */}
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">
          Email Analysis Results
        </h2>
        <div className="flex items-center space-x-4 text-sm text-gray-600">
          <span>
            Processed in {result.processingTime}ms
          </span>
          <span>•</span>
          <span>
            {new Date(result.timestamp).toLocaleString()}
          </span>
        </div>
      </div>

      {/* Results Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Row - Intent and Risk Score */}
        <div className="lg:col-span-1">
          <IntentDisplay intent={result.intent} />
        </div>
        
        <div className="lg:col-span-1">
          <RiskScoreDisplay riskScore={result.riskScore} />
        </div>

        {/* Bottom Row - Deception Indicators (spans full width) */}
        <div className="lg:col-span-2">
          <DeceptionIndicators indicators={result.deceptionIndicators} />
        </div>

        {/* IOCs Section (spans full width) */}
        <div className="lg:col-span-2">
          <IOCList iocs={result.iocs} />
        </div>

        {/* MITRE ATT&CK Analysis (spans full width) */}
        <div className="lg:col-span-2">
          <MitreAttackDisplay 
            mitreData={result.mitreAttackEnhanced} 
            basicMitreData={result.mitreAttack}
          />
        </div>
      </div>

      {/* Analysis Metadata */}
      <div className="mt-6 p-4 bg-gray-50 rounded-lg">
        <h3 className="text-sm font-medium text-gray-700 mb-2">
          Analysis Metadata
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div>
            <span className="text-gray-500">Processing Time:</span>
            <span className="ml-2 font-medium">{result.processingTime}ms</span>
          </div>
          <div>
            <span className="text-gray-500">Analysis Date:</span>
            <span className="ml-2 font-medium">
              {new Date(result.timestamp).toLocaleDateString()}
            </span>
          </div>
          <div>
            <span className="text-gray-500">Analysis Time:</span>
            <span className="ml-2 font-medium">
              {new Date(result.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>
      </div>

      {/* Export/Actions */}
      <div className="mt-6 flex justify-end space-x-3">
        <button
          onClick={() => {
            const dataStr = JSON.stringify(result, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(dataBlob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `phishing-analysis-${new Date().toISOString().split('T')[0]}.json`;
            link.click();
            URL.revokeObjectURL(url);
          }}
          className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
        >
          Export Results
        </button>
        
        <button
          onClick={() => {
            const printContent = `
              Email Analysis Results
              =====================
              
              Threat Intent: ${result.intent.primary} (${result.intent.confidence} confidence)
              Risk Score: ${result.riskScore.score}/10 (${result.riskScore.confidence} confidence)
              
              Deception Indicators:
              ${result.deceptionIndicators.map(indicator => 
                `- ${indicator.type}: ${indicator.description} (${indicator.severity})`
              ).join('\n')}
              
              Analysis completed: ${new Date(result.timestamp).toLocaleString()}
              Processing time: ${result.processingTime}ms
            `;
            
            const printWindow = window.open('', '_blank');
            if (printWindow) {
              printWindow.document.write(`<pre>${printContent}</pre>`);
              printWindow.document.close();
              printWindow.print();
            }
          }}
          className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
        >
          Print Report
        </button>
      </div>
    </div>
  );
};

export default AnalysisResults;