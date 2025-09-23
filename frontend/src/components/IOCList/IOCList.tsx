import React, { useState } from 'react';
import { AnalysisResult } from '../../types/analysis.types';
import IOCCategories from './IOCCategories';

interface IOCListProps {
  iocs: AnalysisResult['iocs'];
  isLoading?: boolean;
  error?: string | null;
}

const IOCList: React.FC<IOCListProps> = ({ iocs, isLoading = false, error = null }) => {
  const [showContext, setShowContext] = useState(true);
  // const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set(['urls', 'ips', 'domains']));

  // Calculate total IOCs
  const totalIOCs = iocs.urls.length + iocs.ips.length + iocs.domains.length;

  // Loading state
  if (isLoading) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 rounded w-1/3 mb-4"></div>
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-32 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="text-center">
          <div className="text-red-500 text-4xl mb-2">⚠️</div>
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            IOC Extraction Failed
          </h3>
          <p className="text-gray-600">{error}</p>
        </div>
      </div>
    );
  }

  // No IOCs found
  if (totalIOCs === 0) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="text-center py-8">
          <div className="text-4xl mb-4">🔍</div>
          <h3 className="text-lg font-semibold text-gray-900 mb-2">
            No IOCs Detected
          </h3>
          <p className="text-gray-600 mb-4">
            No indicators of compromise (URLs, IP addresses, or domains) were found in this email.
          </p>
          <div className="text-sm text-gray-500 bg-gray-50 p-3 rounded">
            <p>This could mean:</p>
            <ul className="list-disc list-inside mt-2 space-y-1">
              <li>The email contains only text content</li>
              <li>Any links or references are legitimate</li>
              <li>The threat uses non-technical social engineering</li>
            </ul>
          </div>
        </div>
      </div>
    );
  }

  // const toggleCategory = (category: string) => {
  //   const newExpanded = new Set(expandedCategories);
  //   if (newExpanded.has(category)) {
  //     newExpanded.delete(category);
  //   } else {
  //     newExpanded.add(category);
  //   }
  //   setExpandedCategories(newExpanded);
  // };

  const exportIOCs = () => {
    const allIOCs = [...iocs.urls, ...iocs.ips, ...iocs.domains];
    const iocText = allIOCs.map(ioc => `${ioc.type.toUpperCase()}: ${ioc.value}`).join('\n');
    
    const dataBlob = new Blob([iocText], { type: 'text/plain' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `iocs-${new Date().toISOString().split('T')[0]}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-semibold text-gray-900 mb-1">
            Indicators of Compromise (IOCs)
          </h2>
          <p className="text-sm text-gray-600">
            {totalIOCs} indicator{totalIOCs !== 1 ? 's' : ''} extracted from email content
          </p>
        </div>
        
        <div className="flex items-center space-x-3">
          {/* Context toggle */}
          <label className="flex items-center space-x-2 text-sm">
            <input
              type="checkbox"
              checked={showContext}
              onChange={(e) => setShowContext(e.target.checked)}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-gray-700">Show context</span>
          </label>

          {/* Export button */}
          <button
            onClick={exportIOCs}
            className="px-3 py-1 bg-blue-600 text-white rounded text-sm font-medium hover:bg-blue-700 transition-colors"
          >
            Export IOCs
          </button>
        </div>
      </div>

      {/* IOC Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <span className="text-2xl">🔗</span>
            <div>
              <div className="text-lg font-semibold text-blue-800">{iocs.urls.length}</div>
              <div className="text-sm text-blue-600">URLs</div>
            </div>
          </div>
        </div>
        
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <span className="text-2xl">🌐</span>
            <div>
              <div className="text-lg font-semibold text-green-800">{iocs.ips.length}</div>
              <div className="text-sm text-green-600">IP Addresses</div>
            </div>
          </div>
        </div>
        
        <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <span className="text-2xl">🏠</span>
            <div>
              <div className="text-lg font-semibold text-purple-800">{iocs.domains.length}</div>
              <div className="text-sm text-purple-600">Domains</div>
            </div>
          </div>
        </div>
      </div>

      {/* IOC Categories */}
      <div className="space-y-6">
        {/* URLs */}
        {iocs.urls.length > 0 && (
          <IOCCategories
            iocs={iocs.urls}
            categoryType="url"
            title="URLs"
            icon="🔗"
            showContext={showContext}
          />
        )}

        {/* IP Addresses */}
        {iocs.ips.length > 0 && (
          <IOCCategories
            iocs={iocs.ips}
            categoryType="ip"
            title="IP Addresses"
            icon="🌐"
            showContext={showContext}
          />
        )}

        {/* Domains */}
        {iocs.domains.length > 0 && (
          <IOCCategories
            iocs={iocs.domains}
            categoryType="domain"
            title="Domains"
            icon="🏠"
            showContext={showContext}
          />
        )}
      </div>

      {/* Footer with instructions */}
      <div className="mt-6 p-4 bg-gray-50 rounded-lg border">
        <h4 className="text-sm font-medium text-gray-700 mb-2">
          How to use IOCs:
        </h4>
        <div className="text-sm text-gray-600 space-y-1">
          <p>• <strong>Copy:</strong> Click the copy button to copy IOCs to your clipboard for further investigation</p>
          <p>• <strong>VirusTotal:</strong> URLs automatically submitted for analysis via API</p>
          <p>• <strong>Export:</strong> Use the export button to download all IOCs as a text file</p>
          <p>• <strong>Context:</strong> Toggle context to see where each IOC was found in the email</p>
        </div>
      </div>
    </div>
  );
};

export default IOCList;