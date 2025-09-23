import React, { useState } from 'react';
import { IOCItem as IOCItemType, IOCType } from '../../types/analysis.types';

interface IOCItemProps {
  ioc: IOCItemType;
  showContext?: boolean;
}

const IOCItem: React.FC<IOCItemProps> = ({ ioc, showContext = true }) => {
  const [copied, setCopied] = useState(false);

  const getIOCIcon = (type: IOCType): string => {
    const icons: Record<IOCType, string> = {
      url: '🔗',
      ip: '🌐',
      domain: '🏠'
    };
    return icons[type];
  };

  const getIOCTypeLabel = (type: IOCType): string => {
    const labels: Record<IOCType, string> = {
      url: 'URL',
      ip: 'IP Address',
      domain: 'Domain'
    };
    return labels[type];
  };

  const getIOCTypeColor = (type: IOCType): string => {
    const colors: Record<IOCType, string> = {
      url: 'bg-blue-100 text-blue-800 border-blue-200',
      ip: 'bg-green-100 text-green-800 border-green-200',
      domain: 'bg-purple-100 text-purple-800 border-purple-200'
    };
    return colors[type];
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(ioc.value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy IOC:', err);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = ioc.value;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleVirusTotalClick = () => {
    // Open VirusTotal analysis page (automatically submitted via API)
    window.open(ioc.vtLink, '_blank', 'noopener,noreferrer');
  };

  const truncateValue = (value: string, maxLength: number = 50): string => {
    if (value.length <= maxLength) return value;
    return `${value.substring(0, maxLength)}...`;
  };

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow">
      {/* Header with type and actions */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2">
          <span className="text-lg">{getIOCIcon(ioc.type)}</span>
          <span className={`px-2 py-1 rounded text-xs font-medium border ${getIOCTypeColor(ioc.type)}`}>
            {getIOCTypeLabel(ioc.type)}
          </span>
        </div>
        
        <div className="flex items-center space-x-2">
          {/* Copy button */}
          <button
            onClick={handleCopy}
            className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
              copied 
                ? 'bg-green-100 text-green-800 border border-green-200' 
                : 'bg-gray-100 text-gray-700 border border-gray-200 hover:bg-gray-200'
            }`}
            title="Copy to clipboard"
          >
            {copied ? (
              <div className="flex items-center space-x-1">
                <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                </svg>
                <span>Copied</span>
              </div>
            ) : (
              <div className="flex items-center space-x-1">
                <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" />
                  <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z" />
                </svg>
                <span>Copy</span>
              </div>
            )}
          </button>

          {/* VirusTotal button */}
          <button
            onClick={handleVirusTotalClick}
            className="px-2 py-1 bg-blue-600 text-white rounded text-xs font-medium hover:bg-blue-700 transition-colors border border-blue-600"
            title="View VirusTotal analysis (auto-submitted)"
          >
            <div className="flex items-center space-x-1">
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>VirusTotal</span>
            </div>
          </button>
        </div>
      </div>

      {/* IOC Value */}
      <div className="mb-3">
        <div className="font-mono text-sm bg-gray-50 p-2 rounded border break-all">
          <span title={ioc.value}>
            {truncateValue(ioc.value)}
          </span>
        </div>
      </div>

      {/* Context (if available and enabled) */}
      {showContext && ioc.context && (
        <div className="border-t border-gray-100 pt-3">
          <h4 className="text-xs font-medium text-gray-600 mb-1">Context:</h4>
          <p className="text-xs text-gray-700 bg-yellow-50 p-2 rounded border border-yellow-200">
            {ioc.context}
          </p>
        </div>
      )}

      {/* Additional Info */}
      <div className="border-t border-gray-100 pt-3 mt-3">
        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>Click VirusTotal for analysis (auto-submitted)</span>
          <span className="flex items-center space-x-1">
            <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z" clipRule="evenodd" />
            </svg>
            <span>External Link</span>
          </span>
        </div>
      </div>
    </div>
  );
};

export default IOCItem;