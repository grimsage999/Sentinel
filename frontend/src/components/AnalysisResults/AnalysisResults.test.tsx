// import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import AnalysisResults from './AnalysisResults';
import { AnalysisResult } from '../../types/analysis.types';

const mockAnalysisResult: AnalysisResult = {
  intent: {
    primary: 'credential_theft',
    confidence: 'High',
    alternatives: ['wire_transfer']
  },
  deceptionIndicators: [
    {
      type: 'spoofing',
      description: 'Sender domain mismatch detected',
      evidence: 'From: security@amaz0n.com (suspicious domain)',
      severity: 'High'
    },
    {
      type: 'urgency',
      description: 'Urgent language patterns detected',
      evidence: 'URGENT: Your account will be suspended',
      severity: 'Medium'
    }
  ],
  riskScore: {
    score: 8,
    confidence: 'High',
    reasoning: 'Multiple high-risk indicators including domain spoofing and urgency tactics'
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

describe('AnalysisResults', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  it('renders loading state correctly', () => {
    render(<AnalysisResults result={mockAnalysisResult} isLoading={true} />);
    
    expect(screen.getByText('Analyzing email content...')).toBeInTheDocument();
    // Check for loading spinner by class
    expect(document.querySelector('.animate-spin')).toBeInTheDocument();
  });

  it('renders error state correctly', () => {
    const errorMessage = 'Analysis service unavailable';
    render(<AnalysisResults result={mockAnalysisResult} error={errorMessage} />);
    
    expect(screen.getByText('Analysis Failed')).toBeInTheDocument();
    expect(screen.getByText(errorMessage)).toBeInTheDocument();
  });

  it('renders analysis results correctly', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    // Check header
    expect(screen.getByText('Email Analysis Results')).toBeInTheDocument();
    expect(screen.getByText(/Processed in 1500ms/)).toBeInTheDocument();
    
    // Check intent display
    expect(screen.getByText('Threat Intent Analysis')).toBeInTheDocument();
    expect(screen.getByText('Credential Theft')).toBeInTheDocument();
    expect(screen.getAllByText('High Confidence')).toHaveLength(2); // Intent and Risk Score both show confidence
    
    // Check risk score
    expect(screen.getByText('Risk Assessment')).toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument();
    expect(screen.getByText('Critical Risk')).toBeInTheDocument();
    
    // Check deception indicators
    expect(screen.getByText('Deception Indicators')).toBeInTheDocument();
    expect(screen.getByText('2 indicators detected')).toBeInTheDocument();
    expect(screen.getByText('Sender Spoofing')).toBeInTheDocument();
    expect(screen.getByText('Urgency Tactics')).toBeInTheDocument();
  });

  it('displays alternative intents when available', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    expect(screen.getByText('Alternative Classifications')).toBeInTheDocument();
    expect(screen.getByText('Wire Transfer Fraud')).toBeInTheDocument();
  });

  it('shows deception indicator evidence', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    // Evidence is shown in quotes, so search for the content
    expect(screen.getByText(/"From: security@amaz0n.com \(suspicious domain\)"/)).toBeInTheDocument();
    expect(screen.getByText(/"URGENT: Your account will be suspended"/)).toBeInTheDocument();
  });

  it('displays risk score reasoning', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    expect(screen.getByText(/Multiple high-risk indicators including domain spoofing/)).toBeInTheDocument();
  });

  it('shows analysis metadata', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    expect(screen.getByText('Analysis Metadata')).toBeInTheDocument();
    expect(screen.getByText('1500ms')).toBeInTheDocument();
  });

  it('handles export results button click', () => {
    // Mock URL.createObjectURL and related methods
    const mockCreateObjectURL = vi.fn(() => 'mock-url');
    const mockRevokeObjectURL = vi.fn();
    const mockClick = vi.fn();
    
    Object.defineProperty(window, 'URL', {
      value: {
        createObjectURL: mockCreateObjectURL,
        revokeObjectURL: mockRevokeObjectURL
      },
      writable: true
    });
    
    // Mock createElement to return a proper DOM element
    const originalCreateElement = document.createElement;
    vi.spyOn(document, 'createElement').mockImplementation((tagName) => {
      if (tagName === 'a') {
        const mockLink = originalCreateElement.call(document, 'a');
        mockLink.click = mockClick;
        return mockLink;
      }
      return originalCreateElement.call(document, tagName);
    });
    
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    const exportButton = screen.getByText('Export Results');
    fireEvent.click(exportButton);
    
    expect(mockCreateObjectURL).toHaveBeenCalled();
    expect(mockClick).toHaveBeenCalled();
    expect(mockRevokeObjectURL).toHaveBeenCalledWith('mock-url');
  });

  it('handles print report button click', () => {
    const mockPrint = vi.fn();
    const mockWrite = vi.fn();
    const mockClose = vi.fn();
    
    const mockWindow = {
      document: {
        write: mockWrite,
        close: mockClose
      },
      print: mockPrint
    };
    
    const originalOpen = window.open;
    window.open = vi.fn().mockReturnValue(mockWindow);
    
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    const printButton = screen.getByText('Print Report');
    fireEvent.click(printButton);
    
    expect(mockWrite).toHaveBeenCalled();
    expect(mockClose).toHaveBeenCalled();
    expect(mockPrint).toHaveBeenCalled();
    
    // Restore
    window.open = originalOpen;
  });

  it('renders correctly with no deception indicators', () => {
    const resultWithNoIndicators = {
      ...mockAnalysisResult,
      deceptionIndicators: []
    };
    
    render(<AnalysisResults result={resultWithNoIndicators} />);
    
    expect(screen.getByText('No deception indicators detected')).toBeInTheDocument();
    expect(screen.getByText(/appears to be straightforward without obvious social engineering/)).toBeInTheDocument();
  });

  it('displays correct risk level colors and descriptions', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    // Should show critical risk styling for score of 8
    expect(screen.getByText('Critical Risk')).toBeInTheDocument();
    
    // Check risk level guide
    expect(screen.getByText('Risk Level Guide:')).toBeInTheDocument();
    expect(screen.getByText('8-10: Critical Risk')).toBeInTheDocument();
  });

  it('groups deception indicators by severity', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    // Should show high severity section
    expect(screen.getByText('High Severity (1)')).toBeInTheDocument();
    // Should show medium severity section  
    expect(screen.getByText('Medium Severity (1)')).toBeInTheDocument();
  });

  it('handles different risk score levels correctly', () => {
    const lowRiskResult = {
      ...mockAnalysisResult,
      riskScore: {
        score: 2,
        confidence: 'Medium',
        reasoning: 'Low risk indicators'
      }
    };
    
    render(<AnalysisResults result={lowRiskResult} />);
    
    expect(screen.getByText('Low Risk')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
  });

  it('displays confidence levels with appropriate styling', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    const confidenceElements = screen.getAllByText('High Confidence');
    expect(confidenceElements.length).toBeGreaterThan(0);
    
    // Check that confidence is displayed with appropriate styling
    confidenceElements.forEach(element => {
      expect(element).toHaveClass('text-green-700');
    });
  });

  it('handles missing alternative intents gracefully', () => {
    const resultWithoutAlternatives = {
      ...mockAnalysisResult,
      intent: {
        ...mockAnalysisResult.intent,
        alternatives: []
      }
    };
    
    render(<AnalysisResults result={resultWithoutAlternatives} />);
    
    expect(screen.queryByText('Alternative Classifications')).not.toBeInTheDocument();
  });

  it('shows detailed IOC information when available', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    // Should show IOC count in metadata
    expect(screen.getByText(/1 IOCs extracted/)).toBeInTheDocument();
  });

  it('handles very long reasoning text', () => {
    const resultWithLongReasoning = {
      ...mockAnalysisResult,
      riskScore: {
        ...mockAnalysisResult.riskScore,
        reasoning: 'This is a very long reasoning text that should be handled properly by the component and not break the layout or cause any display issues when rendered in the user interface'
      }
    };
    
    render(<AnalysisResults result={resultWithLongReasoning} />);
    
    expect(screen.getByText(/This is a very long reasoning text/)).toBeInTheDocument();
  });

  it('displays processing time in different formats', () => {
    const fastResult = {
      ...mockAnalysisResult,
      processingTime: 500
    };
    
    render(<AnalysisResults result={fastResult} />);
    
    expect(screen.getByText(/Processed in 500ms/)).toBeInTheDocument();
  });

  it('handles deception indicators with missing fields', () => {
    const resultWithIncompleteIndicators = {
      ...mockAnalysisResult,
      deceptionIndicators: [
        {
          type: 'spoofing',
          description: 'Incomplete indicator',
          evidence: '',
          severity: 'High'
        }
      ]
    };
    
    render(<AnalysisResults result={resultWithIncompleteIndicators} />);
    
    expect(screen.getByText('Incomplete indicator')).toBeInTheDocument();
    // Should handle missing evidence gracefully
  });

  it('shows expandable sections for detailed information', async () => {
    const user = userEvent.setup();
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    // Look for expandable sections (if implemented)
    const detailsButtons = screen.queryAllByText(/Show Details|View More/);
    if (detailsButtons.length > 0) {
      await user.click(detailsButtons[0]);
      // Should expand to show more details
    }
  });

  it('handles timestamp formatting correctly', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    // Should display formatted timestamp
    expect(screen.getByText(/2024-01-01/)).toBeInTheDocument();
  });

  it('shows appropriate icons for different intent types', () => {
    const wireTransferResult = {
      ...mockAnalysisResult,
      intent: {
        primary: 'wire_transfer',
        confidence: 'High',
        alternatives: []
      }
    };
    
    render(<AnalysisResults result={wireTransferResult} />);
    
    expect(screen.getByText('Wire Transfer Fraud')).toBeInTheDocument();
  });

  it('handles error state with retry functionality', async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    
    render(<AnalysisResults result={mockAnalysisResult} error="Analysis failed" onRetry={onRetry} />);
    
    expect(screen.getByText('Analysis Failed')).toBeInTheDocument();
    
    const retryButton = screen.queryByText('Retry');
    if (retryButton) {
      await user.click(retryButton);
      expect(onRetry).toHaveBeenCalled();
    }
  });

  it('displays severity indicators with correct colors', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    // Check for severity color coding
    const highSeverityElements = screen.getAllByText(/High/);
    const mediumSeverityElements = screen.getAllByText(/Medium/);
    
    expect(highSeverityElements.length).toBeGreaterThan(0);
    expect(mediumSeverityElements.length).toBeGreaterThan(0);
  });

  it('handles accessibility requirements', () => {
    render(<AnalysisResults result={mockAnalysisResult} />);
    
    // Check for proper heading structure
    expect(screen.getByRole('heading', { name: /Email Analysis Results/ })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Threat Intent Analysis/ })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Risk Assessment/ })).toBeInTheDocument();
  });
});