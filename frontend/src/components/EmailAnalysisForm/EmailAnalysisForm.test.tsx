import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '@testing-library/jest-dom';
import EmailAnalysisForm from './EmailAnalysisForm';
import { emailAnalysisService } from '../../services/emailAnalysis';
import { AnalysisResult } from '../../types/analysis.types';

// Mock the email analysis service
vi.mock('../../services/emailAnalysis', () => ({
  emailAnalysisService: {
    analyzeEmail: vi.fn(),
    checkServiceHealth: vi.fn()
  }
}));

// Test wrapper with QueryClient
const createWrapper = () => {
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

const mockAnalysisResult: AnalysisResult = {
  intent: {
    primary: 'credential_theft',
    confidence: 'High',
    alternatives: ['wire_transfer']
  },
  deceptionIndicators: [
    {
      type: 'spoofing',
      description: 'Sender domain mismatch',
      evidence: 'From header shows different domain',
      severity: 'High'
    }
  ],
  riskScore: {
    score: 8,
    confidence: 'High',
    reasoning: 'Multiple high-risk indicators detected'
  },
  iocs: {
    urls: [
      {
        value: 'https://malicious-site.com',
        type: 'url',
        vtLink: 'https://virustotal.com/gui/url/abc123'
      }
    ],
    ips: [],
    domains: []
  },
  processingTime: 1500,
  timestamp: '2024-01-01T12:00:00Z'
};

describe('EmailAnalysisForm with React Query', () => {
  const mockOnAnalysisComplete = vi.fn();
  const mockOnAnalysisError = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    // Default health check mock
    vi.mocked(emailAnalysisService.checkServiceHealth).mockResolvedValue(true);
  });

  const renderWithQueryClient = (component: React.ReactElement) => {
    return render(component, { wrapper: createWrapper() });
  };

  it('renders the form with all required elements', async () => {
    renderWithQueryClient(<EmailAnalysisForm />);
    
    expect(screen.getByText('PhishContext AI - Email Analysis')).toBeInTheDocument();
    expect(screen.getByLabelText('Email Content')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Paste the complete raw email content/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Analyze Email' })).toBeInTheDocument();
    
    // Wait for health check to complete
    await waitFor(() => {
      expect(screen.getByText(/Service Online/)).toBeInTheDocument();
    });
  });

  it('shows character count as user types', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    await user.type(textarea, 'Test email content');
    
    expect(screen.getByText('18 characters')).toBeInTheDocument();
  });

  it('disables submit button when textarea is empty', () => {
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    expect(submitButton).toBeDisabled();
  });

  it('enables submit button when textarea has content', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    await user.type(textarea, 'From: test@example.com\nSubject: Test\n\nTest email content');
    
    expect(submitButton).not.toBeDisabled();
  });

  it('shows validation error for empty content', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    
    // Add some content first to enable the button
    await user.type(textarea, 'test content with @email.com');
    
    // const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    // Then clear it
    await user.clear(textarea);
    // Try to submit (button should still be enabled briefly)
    fireEvent.submit(screen.getByRole('form'));
    
    await waitFor(() => {
      expect(screen.getByText('Please enter email content to analyze')).toBeInTheDocument();
    });
  });

  it('shows validation error for content that is too short', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    await user.type(textarea, 'short');
    await user.click(submitButton);
    
    expect(screen.getByText(/Email content is too short/)).toBeInTheDocument();
  });

  it('shows validation error for content without email indicators', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    await user.type(textarea, 'This is just plain text without any email indicators at all');
    await user.click(submitButton);
    
    expect(screen.getByText(/Content does not appear to be email format/)).toBeInTheDocument();
  });

  it('calls analysis service with valid email content', async () => {
    const user = userEvent.setup();
    const mockAnalyzeEmail = vi.mocked(emailAnalysisService.analyzeEmail);
    mockAnalyzeEmail.mockResolvedValue(mockAnalysisResult);
    
    renderWithQueryClient(<EmailAnalysisForm onAnalysisComplete={mockOnAnalysisComplete} />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    const emailContent = 'From: test@example.com\nSubject: Test Email\n\nThis is a test email content';
    await user.type(textarea, emailContent);
    await user.click(submitButton);
    
    expect(mockAnalyzeEmail).toHaveBeenCalledWith(emailContent, { includeIOCs: true, confidenceThreshold: 0.5 });
  });

  it('shows loading state during analysis', async () => {
    const user = userEvent.setup();
    const mockAnalyzeEmail = vi.mocked(emailAnalysisService.analyzeEmail);
    
    // Create a promise that we can control
    let resolvePromise: (value: AnalysisResult) => void;
    const analysisPromise = new Promise<AnalysisResult>((resolve) => {
      resolvePromise = resolve;
    });
    mockAnalyzeEmail.mockReturnValue(analysisPromise);
    
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    await user.type(textarea, 'From: test@example.com\nSubject: Test\n\nTest content');
    await user.click(submitButton);
    
    // Should show loading state
    expect(screen.getByText('Analyzing...')).toBeInTheDocument();
    expect(submitButton).toBeDisabled();
    expect(textarea).toBeDisabled();
    
    // Resolve the promise
    resolvePromise!(mockAnalysisResult);
    
    // Wait for loading to complete
    await waitFor(() => {
      expect(screen.queryByText('Analyzing...')).not.toBeInTheDocument();
    });
  });

  it('shows success message after successful analysis', async () => {
    const user = userEvent.setup();
    const mockAnalyzeEmail = vi.mocked(emailAnalysisService.analyzeEmail);
    mockAnalyzeEmail.mockResolvedValue(mockAnalysisResult);
    
    renderWithQueryClient(<EmailAnalysisForm onAnalysisComplete={mockOnAnalysisComplete} />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    await user.type(textarea, 'From: test@example.com\nSubject: Test\n\nTest content');
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Analysis Complete')).toBeInTheDocument();
      expect(screen.getByText(/completed successfully in 1500ms/)).toBeInTheDocument();
    });
    
    expect(mockOnAnalysisComplete).toHaveBeenCalledWith(mockAnalysisResult);
  });

  it('shows error message when analysis fails', async () => {
    const user = userEvent.setup();
    const mockAnalyzeEmail = vi.mocked(emailAnalysisService.analyzeEmail);
    const mockError = {
      code: 'API_ERROR',
      message: 'Analysis service unavailable',
      details: 'Please try again later',
      retryable: true
    };
    mockAnalyzeEmail.mockRejectedValue(mockError);
    
    renderWithQueryClient(<EmailAnalysisForm onAnalysisError={mockOnAnalysisError} />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    await user.type(textarea, 'From: test@example.com\nSubject: Test\n\nTest content');
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Analysis Failed')).toBeInTheDocument();
      expect(screen.getByText('Analysis service unavailable')).toBeInTheDocument();
      expect(screen.getByText('Please try again later')).toBeInTheDocument();
    });
    
    expect(mockOnAnalysisError).toHaveBeenCalledWith(mockError);
  });

  it('clears form when clear button is clicked', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    
    await user.type(textarea, 'From: test@example.com\nTest content');
    
    // Clear button should appear
    const clearButton = screen.getByText('Clear');
    await user.click(clearButton);
    
    expect(textarea).toHaveValue('');
    expect(screen.getByText('0 characters')).toBeInTheDocument();
  });

  it('clears errors when user starts typing again', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    // Trigger validation error
    await user.type(textarea, 'short');
    await user.click(submitButton);
    
    expect(screen.getByText(/Email content is too short/)).toBeInTheDocument();
    
    // Start typing again
    await user.type(textarea, ' and now longer content with email@example.com');
    
    // Error should be cleared
    expect(screen.queryByText(/Email content is too short/)).not.toBeInTheDocument();
  });

  it('shows appropriate character count colors', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    
    // Normal content
    await user.type(textarea, 'Normal content');
    let characterCount = screen.getByText(/characters/);
    expect(characterCount).toHaveClass('text-gray-500');
  });

  it('handles service health check failure', async () => {
    vi.mocked(emailAnalysisService.checkServiceHealth).mockResolvedValue(false);
    
    renderWithQueryClient(<EmailAnalysisForm />);
    
    await waitFor(() => {
      expect(screen.getByText(/Service Offline/)).toBeInTheDocument();
    });
  });

  it('shows retry button after analysis failure', async () => {
    const user = userEvent.setup();
    const mockAnalyzeEmail = vi.mocked(emailAnalysisService.analyzeEmail);
    mockAnalyzeEmail.mockRejectedValue({
      code: 'API_ERROR',
      message: 'Service unavailable',
      retryable: true
    });
    
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    await user.type(textarea, 'From: test@example.com\nSubject: Test\n\nTest content');
    await user.click(submitButton);
    
    await waitFor(() => {
      expect(screen.getByText('Try Again')).toBeInTheDocument();
    });
  });

  it('handles keyboard shortcuts', async () => {
    const user = userEvent.setup();
    const mockAnalyzeEmail = vi.mocked(emailAnalysisService.analyzeEmail);
    mockAnalyzeEmail.mockResolvedValue(mockAnalysisResult);
    
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    
    await user.type(textarea, 'From: test@example.com\nSubject: Test\n\nTest content');
    
    // Test Ctrl+Enter shortcut
    await user.keyboard('{Control>}{Enter}{/Control}');
    
    expect(mockAnalyzeEmail).toHaveBeenCalled();
  });

  it('validates email format more strictly', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    // Content with email address but no proper headers
    await user.type(textarea, 'This email contains user@example.com but has no headers');
    await user.click(submitButton);
    
    expect(screen.getByText(/Content does not appear to be email format/)).toBeInTheDocument();
  });

  it('handles analysis options correctly', async () => {
    const user = userEvent.setup();
    const mockAnalyzeEmail = vi.mocked(emailAnalysisService.analyzeEmail);
    mockAnalyzeEmail.mockResolvedValue(mockAnalysisResult);
    
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    
    await user.type(textarea, 'From: test@example.com\nSubject: Test\n\nTest content');
    
    // Check if there are analysis options (this depends on implementation)
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    await user.click(submitButton);
    
    expect(mockAnalyzeEmail).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        includeIOCs: true,
        confidenceThreshold: 0.5
      })
    );
  });

  it('shows progress indicator during analysis', async () => {
    const user = userEvent.setup();
    const mockAnalyzeEmail = vi.mocked(emailAnalysisService.analyzeEmail);
    
    // Create a promise that we can control
    let resolvePromise: (value: AnalysisResult) => void;
    const analysisPromise = new Promise<AnalysisResult>((resolve) => {
      resolvePromise = resolve;
    });
    mockAnalyzeEmail.mockReturnValue(analysisPromise);
    
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    const submitButton = screen.getByRole('button', { name: 'Analyze Email' });
    
    await user.type(textarea, 'From: test@example.com\nSubject: Test\n\nTest content');
    await user.click(submitButton);
    
    // Should show progress indicator
    expect(screen.getByText('Analyzing...')).toBeInTheDocument();
    
    // Resolve the promise
    resolvePromise!(mockAnalysisResult);
    
    await waitFor(() => {
      expect(screen.queryByText('Analyzing...')).not.toBeInTheDocument();
    });
  });

  it('handles paste events correctly', async () => {
    const user = userEvent.setup();
    renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    
    // Simulate paste event
    const pasteData = 'From: test@example.com\nSubject: Pasted Email\n\nPasted content';
    await user.click(textarea);
    await user.paste(pasteData);
    
    expect(textarea).toHaveValue(pasteData);
    expect(screen.getByText(`${pasteData.length} characters`)).toBeInTheDocument();
  });

  it('maintains form state during component updates', async () => {
    const user = userEvent.setup();
    const { rerender } = renderWithQueryClient(<EmailAnalysisForm />);
    
    const textarea = screen.getByLabelText('Email Content');
    const testContent = 'From: test@example.com\nSubject: Test\n\nTest content';
    
    await user.type(textarea, testContent);
    
    // Rerender component
    rerender(<EmailAnalysisForm />);
    
    // Content should be preserved
    expect(textarea).toHaveValue(testContent);
  });
});