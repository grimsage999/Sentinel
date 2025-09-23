import React, { useState, useCallback } from 'react';
import { EmailAnalysisFormProps, EmailAnalysisFormState } from './EmailAnalysisForm.types';
import { validationUtils } from '../../utils/validation';
import { useEmailAnalysis, useServiceHealth, useRetryableAction } from '../../hooks/useEmailAnalysis';
import { ErrorDisplay } from '../ErrorDisplay';
import { ApiErrorBoundary } from '../ErrorBoundary';

const EmailAnalysisForm: React.FC<EmailAnalysisFormProps> = ({
  onAnalysisComplete,
  onAnalysisError
}) => {
  const [state, setState] = useState<EmailAnalysisFormState>({
    emailContent: '',
    isAnalyzing: false,
    analysisResult: null,
    error: null,
    validationError: null
  });

  // React Query hooks
  const emailAnalysisMutation = useEmailAnalysis({
    onSuccess: (result) => {
      setState(prev => ({
        ...prev,
        isAnalyzing: false,
        analysisResult: result,
        error: null
      }));
      onAnalysisComplete?.(result);
    },
    onError: (error) => {
      setState(prev => ({
        ...prev,
        isAnalyzing: false,
        error: error
      }));
      onAnalysisError?.(error);
    }
  });

  const { data: isServiceHealthy, isLoading: isCheckingHealth } = useServiceHealth();
  const { shouldRetry, getErrorMessage } = useRetryableAction();

  const handleEmailContentChange = useCallback((event: React.ChangeEvent<HTMLTextAreaElement>) => {
    const content = event.target.value;
    setState(prev => ({
      ...prev,
      emailContent: content,
      validationError: null,
      error: null
    }));
  }, []);

  const handleSubmit = useCallback(async (event: React.FormEvent) => {
    event.preventDefault();
    
    // Clear previous states
    setState(prev => ({
      ...prev,
      error: null,
      validationError: null,
      analysisResult: null
    }));

    // Validate input
    const validation = validationUtils.validateEmailContent(state.emailContent);
    if (!validation.isValid) {
      setState(prev => ({
        ...prev,
        validationError: validation.error || 'Invalid email content'
      }));
      return;
    }

    // Start analysis using React Query mutation
    setState(prev => ({ ...prev, isAnalyzing: true }));
    emailAnalysisMutation.mutate(state.emailContent);
  }, [state.emailContent, emailAnalysisMutation]);

  const handleClear = useCallback(() => {
    setState({
      emailContent: '',
      isAnalyzing: false,
      analysisResult: null,
      error: null,
      validationError: null
    });
    emailAnalysisMutation.reset();
  }, [emailAnalysisMutation]);

  const handleRetry = useCallback(() => {
    if (state.emailContent.trim()) {
      setState(prev => ({ ...prev, error: null, isAnalyzing: true }));
      emailAnalysisMutation.mutate(state.emailContent);
    }
  }, [state.emailContent, emailAnalysisMutation]);

  const getCharacterCount = () => {
    return state.emailContent.length;
  };

  const getCharacterCountColor = () => {
    const count = getCharacterCount();
    const maxSize = 1024 * 1024; // 1MB in characters (approximate)
    
    if (count > maxSize * 0.9) return 'text-red-600';
    if (count > maxSize * 0.7) return 'text-yellow-600';
    return 'text-gray-500';
  };

  return (
    <ApiErrorBoundary retryAction={handleRetry}>
      <div className="w-full max-w-4xl mx-auto p-6 bg-white rounded-lg shadow-lg">
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <h1 className="text-2xl font-bold text-gray-900">
              PhishContext AI - Email Analysis
            </h1>
            
            {/* Service Health Indicator */}
            <div className="flex items-center space-x-2">
              {isCheckingHealth ? (
                <div className="flex items-center text-gray-500">
                  <svg className="animate-spin h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
                  </svg>
                  <span className="text-sm">Checking...</span>
                </div>
              ) : (
                <div className={`flex items-center ${isServiceHealthy ? 'text-green-600' : 'text-red-600'}`}>
                  <div className={`w-2 h-2 rounded-full mr-2 ${isServiceHealthy ? 'bg-green-500' : 'bg-red-500'}`}/>
                  <span className="text-sm">
                    {isServiceHealthy ? 'Service Online' : 'Service Offline'}
                  </span>
                </div>
              )}
            </div>
          </div>
          
          <p className="text-gray-600">
            Paste your raw email content below for AI-powered phishing analysis
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4" role="form">
        <div className="space-y-2">
          <label 
            htmlFor="email-content" 
            className="block text-sm font-medium text-gray-700"
          >
            Email Content
          </label>
          
          <textarea
            id="email-content"
            value={state.emailContent}
            onChange={handleEmailContentChange}
            placeholder="Paste the complete raw email content here, including headers..."
            className={`
              w-full h-64 px-3 py-2 border rounded-md shadow-sm resize-y
              focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500
              ${state.validationError || state.error ? 'border-red-300' : 'border-gray-300'}
              ${state.isAnalyzing ? 'bg-gray-50' : 'bg-white'}
            `}
            disabled={state.isAnalyzing}
            rows={12}
          />
          
          <div className="flex justify-between items-center text-sm">
            <span className={getCharacterCountColor()}>
              {getCharacterCount().toLocaleString()} characters
            </span>
            
            {state.emailContent && (
              <button
                type="button"
                onClick={handleClear}
                className="text-gray-500 hover:text-gray-700 underline"
                disabled={state.isAnalyzing}
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Validation Error */}
        {state.validationError && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-md">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <p className="text-sm text-red-800">{state.validationError}</p>
              </div>
            </div>
          </div>
        )}

        {/* API Error */}
        {state.error && (
          <ErrorDisplay
            error={state.error}
            onRetry={handleRetry}
            showRetry={shouldRetry(state.error) && !emailAnalysisMutation.isPending}
          />
        )}

        {/* Submit Button */}
        <div className="flex justify-center space-x-4">
          <button
            type="submit"
            disabled={emailAnalysisMutation.isPending || !state.emailContent.trim() || !isServiceHealthy}
            className={`
              px-8 py-3 rounded-md font-medium text-white transition-colors duration-200
              ${emailAnalysisMutation.isPending || !state.emailContent.trim() || !isServiceHealthy
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2'
              }
            `}
            title={!isServiceHealthy ? 'Service is currently offline' : ''}
          >
            {emailAnalysisMutation.isPending ? (
              <div className="flex items-center">
                <svg 
                  className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" 
                  xmlns="http://www.w3.org/2000/svg" 
                  fill="none" 
                  viewBox="0 0 24 24"
                >
                  <circle 
                    className="opacity-25" 
                    cx="12" 
                    cy="12" 
                    r="10" 
                    stroke="currentColor" 
                    strokeWidth="4"
                  />
                  <path 
                    className="opacity-75" 
                    fill="currentColor" 
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
                Analyzing...
              </div>
            ) : (
              'Analyze Email'
            )}
          </button>
        </div>
      </form>

      {/* Success Message */}
      {state.analysisResult && (
        <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-md">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-green-800">
                Analysis Complete
              </h3>
              <p className="text-sm text-green-700 mt-1">
                Email analysis completed successfully in {state.analysisResult.processingTime}ms
              </p>
            </div>
          </div>
        </div>
      )}
      </div>
    </ApiErrorBoundary>
  );
};

export default EmailAnalysisForm;