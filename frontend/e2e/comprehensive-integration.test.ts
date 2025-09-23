/**
 * Comprehensive Integration Tests for PhishContext AI
 * Tests complete user workflows and validates all requirements
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
  
  return function TestWrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    );
  };
};

describe('Comprehensive Integration Tests - Requirements Validation', () => {
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

    mockServer.mock('POST', '/api/analyze', {
      status: 200,
      data: mockApiResponses.analysisSuccess
    });
  });

  afterEach(() => {
    mockServer.restore();
  });

  describe('Requirement 1: Email Input and Analysis', () => {
    it('validates requirement 1.1: accepts full raw email content including headers', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      
      // Test with complete email including headers
      const fullEmail = `From: attacker@malicious.com
To: victim@company.com
Subject: Urgent Account Verification
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <123@malicious.com>
Reply-To: different@evil.com

Your account has been compromised. Click here: https://fake-bank.com/login`;

      await user.type(textarea, fullEmail);
      expect(textarea).toHaveValue(fullEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      expect(analyzeButton).not.toBeDisabled();
    });

    it('validates requirement 1.2: processes email within 30 seconds', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      
      const startTime = Date.now();
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      }, { timeout: 30000 }); // 30 second timeout as per requirement

      const processingTime = Date.now() - startTime;
      expect(processingTime).toBeLessThan(30000); // Should complete within 30 seconds
    });

    it('validates requirement 1.3: displays analysis in readable format', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify readable format with clear sections
      expect(screen.getByText(/Email Analysis Results/)).toBeInTheDocument();
      expect(screen.getByText(/Intent Classification/)).toBeInTheDocument();
      expect(screen.getByText(/Risk Assessment/)).toBeInTheDocument();
      expect(screen.getByText(/Deception Indicators/)).toBeInTheDocument();
      expect(screen.getByText(/Indicators of Compromise/)).toBeInTheDocument();
    });

    it('validates requirement 1.4: provides clear error messaging for malformed content', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      
      // Test with malformed email
      await user.type(textarea, 'This is not a valid email format');

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      // Should show clear error message
      await waitFor(() => {
        expect(screen.getByText(/Content does not appear to be email format/)).toBeInTheDocument();
      });
    });
  });

  describe('Requirement 2: Intent Classification', () => {
    it('validates requirement 2.1: identifies and displays primary intent', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify intent is displayed
      expect(screen.getByText(/Credential Theft/)).toBeInTheDocument();
      expect(screen.getByText(/Intent Classification/)).toBeInTheDocument();
    });

    it('validates requirement 2.2: ranks multiple intents by likelihood', async () => {
      // Mock response with multiple intents
      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: {
          ...mockApiResponses.analysisSuccess,
          data: {
            ...mockApiResponses.analysisSuccess.data,
            intent: {
              primary: 'credential_theft',
              confidence: 'High',
              alternatives: ['wire_transfer_fraud', 'reconnaissance']
            }
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
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify primary and alternative intents are shown
      expect(screen.getByText(/Credential Theft/)).toBeInTheDocument();
      expect(screen.getByText(/Alternative possibilities/)).toBeInTheDocument();
    });

    it('validates requirement 2.3: indicates uncertainty with confidence levels', async () => {
      // Mock response with low confidence
      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: {
          ...mockApiResponses.analysisSuccess,
          data: {
            ...mockApiResponses.analysisSuccess.data,
            intent: {
              primary: 'other',
              confidence: 'Low',
              alternatives: []
            }
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
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify confidence level is displayed
      expect(screen.getByText(/Low confidence/)).toBeInTheDocument();
    });

    it('validates requirement 2.4: provides brief reasoning for classification', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify reasoning is provided
      expect(screen.getByText(/Based on analysis of/)).toBeInTheDocument();
    });
  });

  describe('Requirement 3: Deception Indicators', () => {
    it('validates requirement 3.1: identifies sender spoofing attempts', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify spoofing detection
      expect(screen.getByText(/Sender Spoofing/)).toBeInTheDocument();
    });

    it('validates requirement 3.2: detects urgency-based language patterns', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify urgency detection
      expect(screen.getByText(/Urgency Tactics/)).toBeInTheDocument();
    });

    it('validates requirement 3.5: provides specific examples from email content', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify specific evidence is shown
      expect(screen.getByText(/Domain mismatch in From field/)).toBeInTheDocument();
    });
  });

  describe('Requirement 4: Risk Scoring', () => {
    it('validates requirement 4.1: provides risk score from 1-10', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify risk score is displayed
      expect(screen.getByText(/8/)).toBeInTheDocument(); // Risk score
      expect(screen.getByText(/Risk Score/)).toBeInTheDocument();
    });

    it('validates requirement 4.2: includes confidence level', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify confidence level is shown
      expect(screen.getByText(/High confidence/)).toBeInTheDocument();
    });

    it('validates requirement 4.4: provides brief justification for score', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify justification is provided
      expect(screen.getByText(/Multiple deception indicators present/)).toBeInTheDocument();
    });
  });

  describe('Requirement 5: IOC Extraction', () => {
    it('validates requirement 5.1: automatically extracts URLs', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify URLs are extracted
      expect(screen.getByText(/fake-amazon.com/)).toBeInTheDocument();
      expect(screen.getByText(/URLs/)).toBeInTheDocument();
    });

    it('validates requirement 5.2: automatically extracts IP addresses', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify IPs are extracted
      expect(screen.getByText(/203.0.113.45/)).toBeInTheDocument();
      expect(screen.getByText(/IP Addresses/)).toBeInTheDocument();
    });

    it('validates requirement 5.4: presents IOCs as clickable VirusTotal links', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify VirusTotal links are present
      const vtButtons = screen.getAllByText('VT');
      expect(vtButtons.length).toBeGreaterThan(0);

      // Test clicking VirusTotal link
      const mockOpen = vi.spyOn(window, 'open').mockImplementation(() => null);
      await user.click(vtButtons[0]);
      expect(mockOpen).toHaveBeenCalledWith(
        expect.stringContaining('virustotal.com'),
        '_blank',
        'noopener,noreferrer'
      );
      mockOpen.mockRestore();
    });
  });

  describe('Requirement 6: User Interface', () => {
    it('validates requirement 6.1: displays large, clearly labeled text area', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      expect(textarea).toBeInTheDocument();
      expect(textarea).toHaveAttribute('placeholder', expect.stringContaining('Paste your email'));
      
      // Verify it's large (should have appropriate CSS classes)
      expect(textarea).toHaveClass('min-h-[300px]');
    });

    it('validates requirement 6.2: provides prominent analyze button', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      expect(analyzeButton).toBeInTheDocument();
      expect(analyzeButton).toHaveClass('bg-blue-600'); // Prominent styling
    });

    it('validates requirement 6.3: displays loading indicator during analysis', async () => {
      // Mock slow response
      mockServer.mock('POST', '/api/analyze', {
        status: 200,
        data: mockApiResponses.analysisSuccess,
        delay: 2000
      });

      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      // Verify loading indicator
      expect(screen.getByText(/Analyzing/)).toBeInTheDocument();
      expect(analyzeButton).toBeDisabled();
    });

    it('validates requirement 6.4: displays results in clearly organized sections', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify organized sections
      expect(screen.getByText(/Intent Classification/)).toBeInTheDocument();
      expect(screen.getByText(/Risk Assessment/)).toBeInTheDocument();
      expect(screen.getByText(/Deception Indicators/)).toBeInTheDocument();
      expect(screen.getByText(/Indicators of Compromise/)).toBeInTheDocument();
    });

    it('validates requirement 6.5: uses consistent formatting and visual hierarchy', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify consistent styling classes are applied
      const sections = screen.getAllByRole('region');
      sections.forEach(section => {
        expect(section).toHaveClass('bg-white', 'rounded-lg', 'border');
      });
    });
  });

  describe('Requirement 7: Performance and Concurrency', () => {
    it('validates requirement 7.1: handles multiple concurrent analyses', async () => {
      // This test simulates multiple users but in a single test environment
      const promises = [];
      
      for (let i = 0; i < 3; i++) {
        promises.push(new Promise(async (resolve) => {
          render(<App />, { wrapper: createTestWrapper() });

          await waitFor(() => {
            expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
          });

          const textarea = screen.getByLabelText('Email Content');
          await user.type(textarea, sampleEmails.validPhishingEmail);

          const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
          await user.click(analyzeButton);

          await waitFor(() => {
            expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
          });

          resolve(true);
        }));
      }

      // All analyses should complete successfully
      const results = await Promise.all(promises);
      expect(results).toHaveLength(3);
      results.forEach(result => expect(result).toBe(true));
    });

    it('validates requirement 7.2: maintains response times under 60 seconds', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      
      const startTime = Date.now();
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      }, { timeout: 60000 }); // 60 second timeout as per requirement

      const processingTime = Date.now() - startTime;
      expect(processingTime).toBeLessThan(60000); // Should complete within 60 seconds
    });
  });

  describe('Requirement 8: Security', () => {
    it('validates requirement 8.1: processes without permanent storage', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      const sensitiveEmail = `From: test@example.com
Subject: Confidential Information
      
This email contains sensitive data: SSN 123-45-6789`;

      await user.type(textarea, sensitiveEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Clear the form
      const clearButton = screen.getByText('Clear');
      await user.click(clearButton);

      // Verify content is cleared from UI
      expect(textarea).toHaveValue('');
      
      // Verify no sensitive data persists in localStorage or sessionStorage
      expect(localStorage.getItem('emailContent')).toBeNull();
      expect(sessionStorage.getItem('emailContent')).toBeNull();
    });

    it('validates requirement 8.3: clears email content from memory after processing', async () => {
      render(<App />, { wrapper: createTestWrapper() });

      await waitFor(() => {
        expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
      });

      const textarea = screen.getByLabelText('Email Content');
      await user.type(textarea, sampleEmails.validPhishingEmail);

      const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // After analysis, the form should still contain the content for user reference
      // but the system should not persist it beyond the session
      expect(textarea).toHaveValue(sampleEmails.validPhishingEmail);
      
      // Clear should remove all traces
      const clearButton = screen.getByText('Clear');
      await user.click(clearButton);
      
      expect(textarea).toHaveValue('');
    });
  });
});

describe('SOC Analyst Usage Patterns', () => {
  let mockServer: ReturnType<typeof TestUtils.createMockServer>;
  let user: ReturnType<typeof userEvent.setup>;

  beforeEach(() => {
    mockServer = TestUtils.createMockServer();
    mockServer.install();
    user = userEvent.setup();

    mockServer.mock('GET', '/api/health', {
      status: 200,
      data: mockApiResponses.healthCheck
    });

    mockServer.mock('POST', '/api/analyze', {
      status: 200,
      data: mockApiResponses.analysisSuccess
    });
  });

  afterEach(() => {
    mockServer.restore();
  });

  it('supports rapid analysis workflow for high-volume environments', async () => {
    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const textarea = screen.getByLabelText('Email Content');
    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
    const clearButton = screen.getByText('Clear');

    // Simulate rapid analysis of multiple emails
    const emails = [
      sampleEmails.validPhishingEmail,
      sampleEmails.malwareEmail,
      sampleEmails.legitimateEmail
    ];

    for (const email of emails) {
      // Clear previous content
      if (textarea.value) {
        await user.click(clearButton);
      }

      // Enter new email
      await user.type(textarea, email);
      
      // Analyze
      await user.click(analyzeButton);
      
      // Wait for results
      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Verify results are displayed
      expect(screen.getByText(/Email Analysis Results/)).toBeInTheDocument();
    }
  });

  it('provides efficient keyboard navigation for power users', async () => {
    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    // Test tab navigation
    await user.tab();
    expect(screen.getByLabelText('Email Content')).toHaveFocus();

    await user.tab();
    expect(screen.getByRole('button', { name: /Analyze Email/i })).toHaveFocus();

    // Test keyboard shortcuts (if implemented)
    const textarea = screen.getByLabelText('Email Content');
    await user.click(textarea);
    await user.type(textarea, sampleEmails.validPhishingEmail);

    // Ctrl+Enter to submit (if implemented)
    await user.keyboard('{Control>}{Enter}{/Control}');
    
    // Should start analysis
    await waitFor(() => {
      expect(screen.getByText(/Analyzing/)).toBeInTheDocument();
    });
  });

  it('handles typical SOC analyst email formats', async () => {
    const socEmailFormats = [
      // Forwarded email
      `---------- Forwarded message ---------
From: user@company.com
Date: Mon, Jan 1, 2024 at 10:00 AM
Subject: Suspicious Email

${sampleEmails.validPhishingEmail}`,
      
      // Email with security headers
      `X-Spam-Score: 5.2
X-Spam-Status: Yes
Authentication-Results: spf=fail
${sampleEmails.validPhishingEmail}`,
      
      // Outlook format
      `From: user@company.com [mailto:user@company.com]
Sent: Monday, January 01, 2024 10:00 AM
To: soc@company.com
Subject: FW: Suspicious Email

${sampleEmails.validPhishingEmail}`
    ];

    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const textarea = screen.getByLabelText('Email Content');
    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });

    for (const emailFormat of socEmailFormats) {
      await user.clear(textarea);
      await user.type(textarea, emailFormat);
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Should successfully analyze all formats
      expect(screen.getByText(/Email Analysis Results/)).toBeInTheDocument();

      // Clear for next test
      const clearButton = screen.getByText('Clear');
      await user.click(clearButton);
    }
  });
});