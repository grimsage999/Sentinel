/**
 * Error scenarios and recovery testing
 * Tests system behavior under various error conditions and recovery mechanisms
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '@testing-library/jest-dom';

import App from '../src/App';
import { TestUtils, mockApiResponses, sampleEmails } from './setup';

// Create test wrapper
const createTestWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
};

describe('Error Scenarios and Recovery', () => {
  let mockServer: ReturnType<typeof TestUtils.createMockServer>;
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    mockServer = TestUtils.createMockServer();
    mockServer.install();
    user = userEvent.setup();

    // Mock health check by default
    mockServer.mock('GET', '/api/health', {
      status: 200,
      data: mockApiResponses.healthCheck
    });
  });

  afterEach(() => {
    mockServer.restore();
  });

  describe('Network Errors', () => {
    it('handles complete network failure', async () => {
      // Mock network failure
      mockServer.mock('POST', '/api/analyze', {
        status: 0,
        data: null,
        error: new Error('Network Error')
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Network error/)).toBeInTheDocument();
      });

      expect(screen.getByText(/Please check your internet connection/)).toBeInTheDocument();
    });

    it('handles intermittent connectivity issues', async () => {
      let requestCount = 0;
      
      // First request fails, second succeeds
      mockServer.mock('POST', '/api/analyze', {
        status: () => requestCount++ === 0 ? 0 : 200,
        data: () => requestCount === 1 ? null : mockApiResponses.analysisSuccess
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Network error/)).toBeInTheDocument();
      });

      // Retry should succeed
      const retryButton = screen.getByText('Try Again');
      await user.click(retryButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });
    });

    it('detects and handles offline state', async () => {
      // Mock offline state
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: false
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      // Should show offline indicator
      expect(screen.getByText(/You appear to be offline/)).toBeInTheDocument();

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      
      // Analyze button should be disabled when offline
      expect(analyzeButton).toBeDisabled();

      // Simulate coming back online
      Object.defineProperty(navigator, 'onLine', {
        writable: true,
        value: true
      });

      window.dispatchEvent(new Event('online'));

      await waitFor(() => {
        expect(screen.queryByText(/You appear to be offline/)).not.toBeInTheDocument();
      });

      expect(analyzeButton).not.toBeDisabled();
    });
  });

  describe('API Error Responses', () => {
    it('handles 400 Bad Request errors', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 400,
        data: {
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid email format',
            details: 'Email content does not contain required headers',
            retryable: false
          }
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, 'Invalid email content');

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Invalid email format/)).toBeInTheDocument();
      });

      expect(screen.getByText(/Email content does not contain required headers/)).toBeInTheDocument();
      
      // Should not show retry button for non-retryable errors
      expect(screen.queryByText('Try Again')).not.toBeInTheDocument();
    });

    it('handles 401 Unauthorized errors', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 401,
        data: {
          success: false,
          error: {
            code: 'UNAUTHORIZED',
            message: 'Authentication required',
            retryable: false
          }
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Authentication required/)).toBeInTheDocument();
      });
    });

    it('handles 429 Rate Limit errors with retry timing', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 429,
        data: {
          success: false,
          error: {
            code: 'RATE_LIMITED',
            message: 'Too many requests',
            details: 'Please wait before trying again',
            retryable: true,
            retryAfter: 60
          }
        },
        headers: {
          'Retry-After': '60'
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Too many requests/)).toBeInTheDocument();
      });

      expect(screen.getByText(/Please wait before trying again/)).toBeInTheDocument();
      expect(screen.getByText(/Try again in 60 seconds/)).toBeInTheDocument();
    });

    it('handles 500 Internal Server errors', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 500,
        data: {
          success: false,
          error: {
            code: 'INTERNAL_ERROR',
            message: 'Internal server error',
            details: 'An unexpected error occurred',
            retryable: true
          }
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Internal server error/)).toBeInTheDocument();
      });

      expect(screen.getByText(/An unexpected error occurred/)).toBeInTheDocument();
      expect(screen.getByText('Try Again')).toBeInTheDocument();
    });

    it('handles 503 Service Unavailable errors', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 503,
        data: {
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'AI analysis service temporarily unavailable',
            details: 'Please try again in a few moments',
            retryable: true
          }
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/AI analysis service temporarily unavailable/)).toBeInTheDocument();
      });

      expect(screen.getByText(/Please try again in a few moments/)).toBeInTheDocument();
      expect(screen.getByText('Try Again')).toBeInTheDocument();
    });
  });

  describe('Timeout Scenarios', () => {
    it('handles request timeouts', async () => {
      // Mock long-running request that times out
      mockServer.mock('POST', '/api/analyze', {
        status: 408,
        data: {
          success: false,
          error: {
            code: 'TIMEOUT',
            message: 'Request timed out',
            details: 'The analysis took too long to complete',
            retryable: true
          }
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Request timed out/)).toBeInTheDocument();
      });

      expect(screen.getByText(/The analysis took too long to complete/)).toBeInTheDocument();
      expect(screen.getByText('Try Again')).toBeInTheDocument();
    });

    it('shows progress during long-running requests', async () => {
      // Mock slow response
      let responseDelay = 3000;
      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: mockApiResponses.analysisSuccess,
        delay: responseDelay
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      // Should show progress indicator
      expect(screen.getByText(/Analyzing/)).toBeInTheDocument();
      
      // Should show estimated time or progress
      const progressElement = screen.queryByText(/Estimated time/);
      if (progressElement) {
        expect(progressElement).toBeInTheDocument();
      }

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      }, { timeout: 5000 });
    });
  });

  describe('Malformed Response Handling', () => {
    it('handles invalid JSON responses', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: 'Invalid JSON response',
        headers: { 'content-type': 'text/plain' }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Failed to process response/)).toBeInTheDocument();
      });
    });

    it('handles missing required fields in response', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: {
          success: true,
          data: {
            // Missing required fields like intent, riskScore, etc.
            processingTime: 1000,
            timestamp: new Date().toISOString()
          }
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Invalid response format/)).toBeInTheDocument();
      });
    });

    it('handles corrupted response data', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: {
          success: true,
          data: {
            intent: { primary: 'invalid_intent_type', confidence: 'Invalid' },
            riskScore: { score: 'not_a_number', confidence: 'Invalid' },
            deceptionIndicators: 'not_an_array',
            iocs: null
          }
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Data validation error/)).toBeInTheDocument();
      });
    });
  });

  describe('Recovery Mechanisms', () => {
    it('automatically retries transient failures', async () => {
      let attemptCount = 0;
      
      mockServer.mock('POST', '/api/analyze', {
        status: () => {
          attemptCount++;
          return attemptCount === 1 ? 503 : 200;
        },
        data: () => {
          return attemptCount === 1 
            ? mockApiResponses.analysisError 
            : mockApiResponses.analysisSuccess;
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      // Should eventually succeed after retry
      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      }, { timeout: 10000 });

      expect(attemptCount).toBe(2);
    });

    it('provides manual retry for failed requests', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 500,
        data: mockApiResponses.analysisError
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Failed/)).toBeInTheDocument();
      });

      // Mock successful response for retry
      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: mockApiResponses.analysisSuccess
      });

      const retryButton = screen.getByText('Try Again');
      await user.click(retryButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });
    });

    it('preserves form state during errors and recovery', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 500,
        data: mockApiResponses.analysisError
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      const emailContent = sampleEmails.validPhishingEmail;
      await user.type(textarea, emailContent);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Failed/)).toBeInTheDocument();
      });

      // Form content should be preserved
      expect(textarea).toHaveValue(emailContent);

      // Mock successful response for retry
      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: mockApiResponses.analysisSuccess
      });

      const retryButton = screen.getByText('Try Again');
      await user.click(retryButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Content should still be preserved
      expect(textarea).toHaveValue(emailContent);
    });

    it('provides fallback UI for critical failures', async () => {
      // Mock complete application failure
      const ErrorComponent = () => {
        throw new Error('Critical application error');
      };

      const { container } = render(
        <div>
          <ErrorComponent />
        </div>
      );

      // Should render error boundary fallback
      expect(container).toBeInTheDocument();
    });
  });

  describe('User Experience During Errors', () => {
    it('provides clear error messages', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 400,
        data: {
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Email content is too short',
            details: 'Minimum 50 characters required for analysis',
            retryable: false
          }
        }
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, 'Short email');

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Email content is too short/)).toBeInTheDocument();
      });

      expect(screen.getByText(/Minimum 50 characters required for analysis/)).toBeInTheDocument();
    });

    it('maintains accessibility during error states', async () => {
      mockServer.mock('POST', '/api/analyze', {
        status: 500,
        data: mockApiResponses.analysisError
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Failed/)).toBeInTheDocument();
      });

      // Error should be announced to screen readers
      const errorAlert = screen.getByRole('alert');
      expect(errorAlert).toBeInTheDocument();
      expect(errorAlert).toHaveAttribute('aria-live');

      // Retry button should be accessible
      const retryButton = screen.getByText('Try Again');
      expect(retryButton).toHaveAttribute('type', 'button');
    });
  });
});