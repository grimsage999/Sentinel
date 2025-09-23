import { useState } from 'react';
import { QueryClientProvider } from '@tanstack/react-query';
import EmailAnalysisForm from './components/EmailAnalysisForm/EmailAnalysisForm';
import AnalysisResults from './components/AnalysisResults/AnalysisResults';
import { DevTools } from './components/DevTools';
import { ErrorBoundary } from './components/ErrorBoundary';
import { queryClient } from './services/queryClient';
import { AnalysisResult } from './types/analysis.types';
import { ApiError } from './types/api.types';

function App() {
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);

  const handleAnalysisComplete = (result: AnalysisResult) => {
    setAnalysisResult(result);
  };

  const handleAnalysisError = (_error: ApiError) => {
    setAnalysisResult(null);
  };

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <div className="min-h-screen bg-gray-50">
          <div className="container mx-auto px-4 py-8">
            <ErrorBoundary>
              <EmailAnalysisForm
                onAnalysisComplete={handleAnalysisComplete}
                onAnalysisError={handleAnalysisError}
              />
            </ErrorBoundary>
            
            {analysisResult && (
              <div className="mt-8">
                <ErrorBoundary>
                  <AnalysisResults result={analysisResult} />
                </ErrorBoundary>
              </div>
            )}
          </div>
        </div>
        <DevTools />
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;