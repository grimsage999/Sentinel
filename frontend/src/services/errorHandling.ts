import { ApiError } from '../types/api.types';

export interface ErrorHandlingOptions {
  showToast?: boolean;
  logError?: boolean;
  retryable?: boolean;
}

export const errorHandlingService = {
  /**
   * Handles API errors with consistent formatting and user feedback
   * @param error - The error to handle
   * @param options - Error handling options
   * @returns Formatted error for display
   */
  handleApiError: (error: any, options: ErrorHandlingOptions = {}): ApiError => {
    const { logError = true } = options;

    let apiError: ApiError;

    if (error?.apiError) {
      // Already formatted API error
      apiError = error.apiError;
    } else if (error?.response) {
      // Axios response error
      apiError = {
        code: error.response.data?.error?.code || 'API_ERROR',
        message: error.response.data?.error?.message || 'Server error occurred',
        details: error.response.data?.error?.details || error.message,
        retryable: error.response.status >= 500 || error.response.status === 429
      };
    } else if (error?.request) {
      // Network error
      apiError = {
        code: 'NETWORK_ERROR',
        message: 'Unable to connect to the server',
        details: 'Please check your internet connection and try again',
        retryable: true
      };
    } else if (error?.code) {
      // Already an API error format
      apiError = error;
    } else {
      // Unknown error
      apiError = {
        code: 'UNKNOWN_ERROR',
        message: 'An unexpected error occurred',
        details: error?.message || 'Please try again',
        retryable: false
      };
    }

    if (logError) {
      console.error('API Error:', apiError, error);
    }

    return apiError;
  },

  /**
   * Gets user-friendly error message based on error code
   * @param error - API error
   * @returns User-friendly message
   */
  getUserFriendlyMessage: (error: ApiError): string => {
    switch (error.code) {
      case 'NETWORK_ERROR':
        return 'Connection failed. Please check your internet connection and try again.';
      case 'VALIDATION_ERROR':
        return error.message || 'Please check your input and try again.';
      case 'PARSING_ERROR':
        return 'Unable to process the email content. Please verify the email format and try again.';
      case 'ANALYSIS_FAILED':
      case 'LLM_ERROR':
        return 'Email analysis failed. This may be temporary - please try again.';
      case 'RATE_LIMITED':
        return 'Too many requests. Please wait a moment before trying again.';
      case 'SERVICE_UNAVAILABLE':
        return 'Analysis service is temporarily unavailable. Please try again later.';
      case 'TIMEOUT':
        return 'Analysis is taking longer than expected. Please try again.';
      case 'INVALID_INPUT':
        return 'Invalid email content. Please paste the complete email including headers.';
      case 'IOC_EXTRACTION_ERROR':
        return 'Unable to extract indicators from the email. Analysis will continue without IOCs.';
      default:
        return error.message || 'An error occurred. Please try again.';
    }
  },

  /**
   * Gets detailed recovery suggestions for different error types
   * @param error - API error
   * @returns Array of recovery suggestions
   */
  getRecoverySuggestions: (error: ApiError): string[] => {
    switch (error.code) {
      case 'NETWORK_ERROR':
        return [
          'Check your internet connection',
          'Try refreshing the page',
          'Contact your network administrator if the problem persists'
        ];
      case 'VALIDATION_ERROR':
      case 'INVALID_INPUT':
        return [
          'Ensure you\'ve pasted the complete email including headers',
          'Check that the email content is not corrupted',
          'Try copying the email content again from your email client'
        ];
      case 'PARSING_ERROR':
        return [
          'Verify the email format is correct',
          'Ensure all email headers are included',
          'Try removing any non-standard formatting'
        ];
      case 'RATE_LIMITED':
        return [
          'Wait 30-60 seconds before trying again',
          'Avoid submitting multiple requests simultaneously',
          'Contact support if you need higher rate limits'
        ];
      case 'SERVICE_UNAVAILABLE':
      case 'LLM_ERROR':
        return [
          'Wait a few minutes and try again',
          'Check the system status page',
          'Contact support if the issue persists'
        ];
      case 'TIMEOUT':
        return [
          'Try again with a shorter email',
          'Check your internet connection speed',
          'Wait a moment and retry the analysis'
        ];
      default:
        return [
          'Try refreshing the page',
          'Wait a moment and try again',
          'Contact support if the problem continues'
        ];
    }
  },

  /**
   * Determines if an error should show a retry button
   * @param error - API error
   * @returns Whether retry is recommended
   */
  shouldShowRetry: (error: ApiError): boolean => {
    return error.retryable !== false && [
      'NETWORK_ERROR',
      'ANALYSIS_FAILED',
      'SERVICE_UNAVAILABLE',
      'TIMEOUT',
      'RATE_LIMITED'
    ].includes(error.code);
  },

  /**
   * Gets retry delay in milliseconds based on error type
   * @param error - API error
   * @param attemptNumber - Current retry attempt (1-based)
   * @returns Delay in milliseconds
   */
  getRetryDelay: (error: ApiError, attemptNumber: number = 1): number => {
    const baseDelay = 1000; // 1 second
    const maxDelay = 30000; // 30 seconds

    switch (error.code) {
      case 'RATE_LIMITED':
        return Math.min(baseDelay * Math.pow(2, attemptNumber), maxDelay);
      case 'NETWORK_ERROR':
        return Math.min(baseDelay * attemptNumber, 10000);
      case 'SERVICE_UNAVAILABLE':
        return Math.min(baseDelay * Math.pow(1.5, attemptNumber), maxDelay);
      default:
        return Math.min(baseDelay * attemptNumber, 15000);
    }
  }
};