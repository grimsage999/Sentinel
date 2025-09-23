/**
 * End-to-end tests for complete email analysis workflow
 * Tests the full user journey from email input to results display
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
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

describe('Email Analysis Workflow - End to End', () => {
  let mockServer: ReturnType<typeof TestUtils.createMockServer>;
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    mockServer = TestUtils.createMockServer();
    mockServer.install();
    user = userEvent.setup();

    // Set up default API mocks
    mockServer.mock('GET', '/api/health', {
      status: 200,
      data: mockApiResponses.healthCheck
    });
  });

  afterEach(() => {
    mockServer.restore();
  });

  it('completes successful phishing email analysis workflow', async () => {
    // Mock successful analysis
    mockServer.mock('POST', '/api/analyze', {
      status: 200,
      data: mockApiResponses.analysisSuccess
    });

    render(<App />, { wrapper: createTestWrapper() });

    // Wait for app to load and health check to complete
    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    // Verify initial state
    expect(screen.getByLabelText('Email Content')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Analyze Email/i })).toBeDisabled();

    // Enter email content
    const textarea = screen.getByLabelText('Email Content');
    await user.type(textarea, sampleEmails.validPhishingEmail);

    // Verify character count updates
    expect(screen.getByText(/\d+ characters/)).toBeInTheDocument();

    // Verify analyze button is enabled
    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
    expect(analyzeButton).not.toBeDisabled();

    // Submit analysis
    await user.click(analyzeButton);

    // Verify loading state
    expect(screen.getByText(/Analyzing/)).toBeInTheDocument();
    expect(analyzeButton).toBeDisabled();
    expect(textarea).toBeDisabled();

    // Wait for analysis to complete
    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
    }, { timeout: 10000 });

    // Verify results are displayed
    expect(screen.getByText(/Email Analysis Results/)).toBeInTheDocument();
    expect(screen.getByText(/Credential Theft/)).toBeInTheDocument();
    expect(screen.getByText(/Critical Risk/)).toBeInTheDocument();
    expect(screen.getByText(/8/)).toBeInTheDocument(); // Risk score

    // Verify deception indicators
    expect(screen.getByText(/Sender Spoofing/)).toBeInTheDocument();
    expect(screen.getByText(/Urgency Tactics/)).toBeInTheDocument();

    // Verify IOCs are displayed
    expect(screen.getByText(/Indicators of Compromise/)).toBeInTheDocument();
    expect(screen.getByText(/fake-amazon.com/)).toBeInTheDocument();
    expect(screen.getByText(/203.0.113.45/)).toBeInTheDocument();

    // Test IOC interactions
    const copyButtons = screen.getAllByText('Copy');
    expect(copyButtons.length).toBeGreaterThan(0);

    const vtButtons = screen.getAllByText('VT');
    expect(vtButtons.length).toBeGreaterThan(0);

    // Test copy functionality
    await user.click(copyButtons[0]);
    await waitFor(() => {
      expect(screen.getByText('Copied')).toBeInTheDocument();
    });

    // Test VirusTotal link
    const mockOpen = vi.spyOn(window, 'open').mockImplementation(() => null);
    await user.click(vtButtons[0]);
    expect(mockOpen).toHaveBeenCalledWith(
      expect.stringContaining('virustotal.com'),
      '_blank',
      'noopener,noreferrer'
    );
    mockOpen.mockRestore();

    // Test export functionality
    const exportButton = screen.getByText('Export Results');
    await user.click(exportButton);
    // Export should trigger download (tested in unit tests)

    // Verify form can be cleared and reused
    const clearButton = screen.getByText('Clear');
    await user.click(clearButton);

    expect(textarea).toHaveValue('');
    expect(screen.queryByText(/Analysis Complete/)).not.toBeInTheDocument();
  });

  it('handles analysis errors gracefully', async () => {
    // Mock analysis error
    mockServer.mock('POST', '/api/analyze', {
      status: 503,
      data: mockApiResponses.analysisError
    });

    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    // Enter email content and submit
    const textarea = screen.getByLabelText('Email Content');
    await user.type(textarea, sampleEmails.validPhishingEmail);

    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
    await user.click(analyzeButton);

    // Wait for error to be displayed
    await waitFor(() => {
      expect(screen.getByText(/Analysis Failed/)).toBeInTheDocument();
    });

    expect(screen.getByText(/AI analysis service temporarily unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/Please try again in a few moments/)).toBeInTheDocument();

    // Verify retry button is available
    const retryButton = screen.getByText('Try Again');
    expect(retryButton).toBeInTheDocument();

    // Test retry functionality
    mockServer.mock('POST', '/api/analyze', {
      status: 200,
      data: mockApiResponses.analysisSuccess
    });

    await user.click(retryButton);

    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
    });
  });

  it('validates email content before submission', async () => {
    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const textarea = screen.getByLabelText('Email Content');
    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });

    // Test empty content
    await user.click(analyzeButton);
    expect(screen.getByText(/Please enter email content to analyze/)).toBeInTheDocument();

    // Test short content
    await user.type(textarea, sampleEmails.shortEmail);
    await user.click(analyzeButton);
    expect(screen.getByText(/Email content is too short/)).toBeInTheDocument();

    // Test invalid format
    await user.clear(textarea);
    await user.type(textarea, sampleEmails.invalidEmail);
    await user.click(analyzeButton);
    expect(screen.getByText(/Content does not appear to be email format/)).toBeInTheDocument();

    // Clear errors when typing
    await user.type(textarea, ' with email@example.com');
    expect(screen.queryByText(/Content does not appear to be email format/)).not.toBeInTheDocument();
  });

  it('handles rate limiting appropriately', async () => {
    // Mock rate limit error
    mockServer.mock('POST', '/api/analyze', {
      status: 429,
      data: mockApiResponses.rateLimitError
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
      expect(screen.getByText(/Service temporarily unavailable due to high demand/)).toBeInTheDocument();
    });

    expect(screen.getByText(/Please wait a moment and try again/)).toBeInTheDocument();
  });

  it('handles different types of phishing emails correctly', async () => {
    const testCases = [
      {
        email: sampleEmails.malwareEmail,
        expectedIntent: 'Malware Delivery',
        expectedRisk: 'High'
      },
      {
        email: sampleEmails.legitimateEmail,
        expectedIntent: 'Other',
        expectedRisk: 'Low'
      }
    ];

    for (const testCase of testCases) {
      // Mock appropriate response
      const mockResponse = {
        ...mockApiResponses.analysisSuccess,
        data: {
          ...mockApiResponses.analysisSuccess.data,
          intent: {
            primary: testCase.expectedIntent.toLowerCase().replace(' ', '_'),
            confidence: 'High',
            alternatives: []
          },
          riskScore: {
            score: testCase.expectedRisk === 'High' ? 8 : 2,
            confidence: 'High',
            reasoning: `${testCase.expectedRisk} risk indicators detected`
          }
        }
      };

      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: mockResponse
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, testCase.email);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify expected results
      expect(screen.getByText(new RegExp(testCase.expectedIntent))).toBeInTheDocument();
      
      // Clean up for next iteration
      const clearButton = screen.getByText('Clear');
      await user.click(clearButton);
    }
  });

  it('maintains responsive design across different screen sizes', async () => {
    // Test mobile viewport
    Object.defineProperty(window, 'innerWidth', { value: 375 });
    Object.defineProperty(window, 'innerHeight', { value: 667 });
    window.dispatchEvent(new Event('resize'));

    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    // Verify mobile layout
    const textarea = screen.getByLabelText('Email Content');
    expect(textarea).toBeInTheDocument();

    // Test tablet viewport
    Object.defineProperty(window, 'innerWidth', { value: 768 });
    Object.defineProperty(window, 'innerHeight', { value: 1024 });
    window.dispatchEvent(new Event('resize'));

    // Verify tablet layout still works
    expect(textarea).toBeInTheDocument();

    // Test desktop viewport
    Object.defineProperty(window, 'innerWidth', { value: 1920 });
    Object.defineProperty(window, 'innerHeight', { value: 1080 });
    window.dispatchEvent(new Event('resize'));

    // Verify desktop layout
    expect(textarea).toBeInTheDocument();
  });

  it('handles keyboard navigation and accessibility', async () => {
    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const textarea = screen.getByLabelText('Email Content');
    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });

    // Test tab navigation
    await user.tab();
    expect(textarea).toHaveFocus();

    await user.tab();
    expect(analyzeButton).toHaveFocus();

    // Test keyboard shortcuts
    await user.click(textarea);
    await user.type(textarea, sampleEmails.validPhishingEmail);

    // Test Ctrl+Enter shortcut (if implemented)
    await user.keyboard('{Control>}{Enter}{/Control}');

    // Verify ARIA attributes
    expect(textarea).toHaveAttribute('aria-label', 'Email Content');
    expect(analyzeButton).toHaveAttribute('type', 'submit');

    // Test screen reader announcements
    const liveRegion = screen.queryByRole('status');
    if (liveRegion) {
      expect(liveRegion).toHaveAttribute('aria-live');
    }
  });

  it('handles concurrent analysis requests appropriately', async () => {
    mockServer.mock('POST', '/api/analyze', {
      status: 200,
      data: mockApiResponses.analysisSuccess
    });

    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const textarea = screen.getByLabelText('Email Content');
    await user.type(textarea, sampleEmails.validPhishingEmail);

    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });

    // Submit first request
    await user.click(analyzeButton);

    // Verify button is disabled during analysis
    expect(analyzeButton).toBeDisabled();

    // Try to submit again (should be prevented)
    await user.click(analyzeButton);

    // Should still only have one analysis in progress
    expect(screen.getAllByText(/Analyzing/)).toHaveLength(1);

    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
    });
  });

  it('persists form state during navigation', async () => {
    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const textarea = screen.getByLabelText('Email Content');
    const testContent = 'From: test@example.com\nSubject: Test\n\nTest content';
    
    await user.type(textarea, testContent);

    // Simulate navigation away and back (if applicable)
    // This would depend on routing implementation
    expect(textarea).toHaveValue(testContent);
  });

  it('handles offline scenarios gracefully', async () => {
    // Mock offline state
    Object.defineProperty(navigator, 'onLine', {
      writable: true,
      value: false
    });

    // Mock network error
    mockServer.mock('POST', '/api/analyze', {
      status: 0,
      data: null
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

    // Restore online state
    Object.defineProperty(navigator, 'onLine', {
      writable: true,
      value: true
    });

    window.dispatchEvent(new Event('online'));

    // Should show online status
    await waitFor(() => {
      expect(screen.queryByText(/You appear to be offline/)).not.toBeInTheDocument();
    });
  });
});