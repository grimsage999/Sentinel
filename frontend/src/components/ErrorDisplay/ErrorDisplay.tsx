import React from 'react';
import { ApiError } from '../../types/api.types';
import { errorHandlingService } from '../../services/errorHandling';

interface ErrorDisplayProps {
  error: ApiError;
  onRetry?: () => void;
  onDismiss?: () => void;
  className?: string;
  showRetry?: boolean;
  showDismiss?: boolean;
}

/**
 * Reusable error display component for showing API errors with user-friendly messages
 * and appropriate action buttons
 */
export const ErrorDisplay: React.FC<ErrorDisplayProps> = ({
  error,
  onRetry,
  onDismiss,
  className = '',
  showRetry = true,
  showDismiss = false
}) => {
  const userMessage = errorHandlingService.getUserFriendlyMessage(error);
  const shouldShowRetry = showRetry && errorHandlingService.shouldShowRetry(error);

  const getErrorIcon = () => {
    switch (error.code) {
      case 'NETWORK_ERROR':
        return (
          <svg className="h-5 w-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        );
      case 'TIMEOUT':
        return (
          <svg className="h-5 w-5 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        );
      case 'RATE_LIMITED':
        return (
          <svg className="h-5 w-5 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
        );
      default:
        return (
          <svg className="h-5 w-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        );
    }
  };

  const getErrorTitle = () => {
    switch (error.code) {
      case 'NETWORK_ERROR':
        return 'Connection Problem';
      case 'TIMEOUT':
        return 'Request Timeout';
      case 'RATE_LIMITED':
        return 'Too Many Requests';
      case 'SERVICE_UNAVAILABLE':
        return 'Service Unavailable';
      case 'VALIDATION_ERROR':
        return 'Invalid Input';
      default:
        return 'Error';
    }
  };

  const getBorderColor = () => {
    switch (error.code) {
      case 'TIMEOUT':
        return 'border-yellow-200';
      case 'RATE_LIMITED':
        return 'border-orange-200';
      default:
        return 'border-red-200';
    }
  };

  const getBackgroundColor = () => {
    switch (error.code) {
      case 'TIMEOUT':
        return 'bg-yellow-50';
      case 'RATE_LIMITED':
        return 'bg-orange-50';
      default:
        return 'bg-red-50';
    }
  };

  const getTextColor = () => {
    switch (error.code) {
      case 'TIMEOUT':
        return 'text-yellow-800';
      case 'RATE_LIMITED':
        return 'text-orange-800';
      default:
        return 'text-red-800';
    }
  };

  const getDetailTextColor = () => {
    switch (error.code) {
      case 'TIMEOUT':
        return 'text-yellow-700';
      case 'RATE_LIMITED':
        return 'text-orange-700';
      default:
        return 'text-red-700';
    }
  };

  return (
    <div className={`rounded-md ${getBackgroundColor()} p-4 border ${getBorderColor()} ${className}`}>
      <div className="flex">
        <div className="flex-shrink-0">
          {getErrorIcon()}
        </div>
        <div className="ml-3 flex-1">
          <h3 className={`text-sm font-medium ${getTextColor()}`}>
            {getErrorTitle()}
          </h3>
          <div className={`mt-2 text-sm ${getDetailTextColor()}`}>
            <p>{userMessage}</p>
            {error.details && error.details !== userMessage && (
              <p className="mt-1 text-xs opacity-75">{error.details}</p>
            )}
          </div>
          
          {(shouldShowRetry || showDismiss) && (
            <div className="mt-4">
              <div className="-mx-2 -my-1.5 flex space-x-2">
                {shouldShowRetry && onRetry && (
                  <button
                    type="button"
                    onClick={onRetry}
                    className={`${getBackgroundColor()} px-2 py-1.5 rounded-md text-sm font-medium ${getTextColor()} hover:opacity-75 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-${getBackgroundColor().split('-')[1]}-50 focus:ring-${getTextColor().split('-')[1]}-600`}
                  >
                    Try Again
                  </button>
                )}
                {showDismiss && onDismiss && (
                  <button
                    type="button"
                    onClick={onDismiss}
                    className={`${getBackgroundColor()} px-2 py-1.5 rounded-md text-sm font-medium ${getTextColor()} hover:opacity-75 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-${getBackgroundColor().split('-')[1]}-50 focus:ring-${getTextColor().split('-')[1]}-600`}
                  >
                    Dismiss
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};