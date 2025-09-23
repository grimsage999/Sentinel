import React from 'react';
import { IOCItem, IOCType } from '../../types/analysis.types';
import IOCItemComponent from './IOCItem';

interface IOCCategoriesProps {
  iocs: IOCItem[];
  categoryType: IOCType;
  title: string;
  icon: string;
  showContext?: boolean;
}

const IOCCategories: React.FC<IOCCategoriesProps> = ({ 
  iocs, 
  categoryType, 
  title, 
  icon, 
  showContext = true 
}) => {
  // Filter IOCs by category type
  const categoryIOCs = iocs.filter(ioc => ioc.type === categoryType);

  if (categoryIOCs.length === 0) {
    return null;
  }

  const getCategoryColor = (type: IOCType): string => {
    const colors: Record<IOCType, string> = {
      url: 'border-blue-200 bg-blue-50',
      ip: 'border-green-200 bg-green-50',
      domain: 'border-purple-200 bg-purple-50'
    };
    return colors[type];
  };

  const getCategoryHeaderColor = (type: IOCType): string => {
    const colors: Record<IOCType, string> = {
      url: 'text-blue-800',
      ip: 'text-green-800',
      domain: 'text-purple-800'
    };
    return colors[type];
  };

  return (
    <div className={`border rounded-lg p-4 ${getCategoryColor(categoryType)}`}>
      {/* Category Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <span className="text-xl">{icon}</span>
          <h3 className={`text-lg font-semibold ${getCategoryHeaderColor(categoryType)}`}>
            {title}
          </h3>
          <span className={`px-2 py-1 rounded-full text-xs font-medium bg-white border ${getCategoryHeaderColor(categoryType)}`}>
            {categoryIOCs.length} found
          </span>
        </div>
      </div>

      {/* Category Description */}
      <div className="mb-4 text-sm text-gray-700">
        {categoryType === 'url' && (
          <p>URLs and web links found in the email content that may be malicious or suspicious.</p>
        )}
        {categoryType === 'ip' && (
          <p>IP addresses extracted from email headers and content that may indicate malicious infrastructure.</p>
        )}
        {categoryType === 'domain' && (
          <p>Domain names found in the email that may be spoofed or associated with malicious activity.</p>
        )}
      </div>

      {/* IOC Items Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {categoryIOCs.map((ioc, index) => (
          <IOCItemComponent 
            key={`${categoryType}-${index}`} 
            ioc={ioc} 
            showContext={showContext}
          />
        ))}
      </div>

      {/* Category Summary */}
      <div className="mt-4 p-3 bg-white bg-opacity-50 rounded border">
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600">
            Total {title.toLowerCase()}: <strong>{categoryIOCs.length}</strong>
          </span>
          <div className="flex items-center space-x-4 text-xs text-gray-500">
            <span>Click any item to copy</span>
            <span>•</span>
            <span>Use VT button for analysis</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IOCCategories;