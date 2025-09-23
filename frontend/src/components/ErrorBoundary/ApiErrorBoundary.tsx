import React, { Component, ErrorInfo, ReactNode } from 'react';
import { ApiError } from '../../types/api.types';
import { errorHandlingService } from '../../services/errorHandling';

interface Props {
  children: ReactNode;
  onError?: (error: ApiError) => void;
  showRetry?: boolean;
  retryAction?: () => void;
}

interface State {
  hasError: boolean;
  apiError: ApiError | null;
}

/**
 * Specialized error boundary for API-related errors
 * Provides user-friendly error messages and retry functionality
 */
export class ApiErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      apiError: null
    };
  }

  static getDerivedStateFromError(error: any): State {
    // Check if this is an API error
    const apiError = errorHandlingService.handleApiError(error, { logError: false });
    
    return {
      hasError: true,
      apiError
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const apiError = errorHandlingService.handleApiError(error);
    
    this.setState({ apiError });

    // Call optional error handler
    if (this.props.onError) {
      this.props.onError(apiError);
    }
  }

  handleRetry = () => {
    this.setState({
      hasError: false,
      apiError: null
    });

    // Call retry action if provided
    if (this.props.retryAction) {
      this.props.retryAction();
    }
  };

  render() {
    if (this.state.hasError && this.state.apiError) {
      const { apiError } = this.state;
      const userMessage = errorHandlingService.getUserFriendlyMessage(apiError);
      const shouldShowRetry = this.props.showRetry !== false && 
                             errorHandlingService.shouldShowRetry(apiError);

      return (
        <div className="rounded-md bg-red-50 p-4 border border-red-200">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg
                className="h-5 w-5 text-red-400"
                viewBox="0 0 20 20"
                fill="currentColor"
              >
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                  clipRule="evenodd"
                />
              </svg>
            </div>
            <div className="ml-3 flex-1">
              <h3 className="text-sm font-medium text-red-800">
                {apiError.code === 'NETWORK_ERROR' ? 'Connection Error' : 'Analysis Error'}
              </h3>
              <div className="mt-2 text-sm text-red-700">
                <p>{userMessage}</p>
                {apiError.details && apiError.details !== userMessage && (
                  <p className="mt-1 text-xs text-red-600">{apiError.details}</p>
                )}
              </div>
              
              {shouldShowRetry && (
                <div className="mt-4">
                  <div className="-mx-2 -my-1.5 flex">
                    <button
                      type="button"
                      onClick={this.handleRetry}
                      className="bg-red-50 px-2 py-1.5 rounded-md text-sm font-medium text-red-800 hover:bg-red-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-red-50 focus:ring-red-600"
                    >
                      Try Again
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}