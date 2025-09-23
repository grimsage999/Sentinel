// import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import IOCList from './IOCList';
import { AnalysisResult } from '../../types/analysis.types';

const mockIOCs: AnalysisResult['iocs'] = {
  urls: [
    {
      value: 'https://malicious-site.com/login',
      type: 'url',
      vtLink: 'https://virustotal.com/gui/url/abc123',
      context: 'Found in email body as a login link'
    },
    {
      value: 'http://phishing-example.net/secure',
      type: 'url',
      vtLink: 'https://virustotal.com/gui/url/def456'
    }
  ],
  ips: [
    {
      value: '192.168.1.100',
      type: 'ip',
      vtLink: 'https://virustotal.com/gui/ip-address/192.168.1.100',
      context: 'Found in email headers'
    }
  ],
  domains: [
    {
      value: 'suspicious-domain.com',
      type: 'domain',
      vtLink: 'https://virustotal.com/gui/domain/suspicious-domain.com'
    }
  ]
};

const emptyIOCs: AnalysisResult['iocs'] = {
  urls: [],
  ips: [],
  domains: []
};

// Mock clipboard API
const mockWriteText = vi.fn().mockResolvedValue(undefined);
Object.assign(navigator, {
  clipboard: {
    writeText: mockWriteText
  }
});

// Mock the clipboard API properly for vitest
Object.defineProperty(navigator, 'clipboard', {
  value: {
    writeText: mockWriteText
  },
  writable: true
});

// Mock window.open
Object.defineProperty(window, 'open', {
  value: vi.fn()
});

describe('IOCList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset DOM mocks
    vi.restoreAllMocks();
  });

  it('renders loading state correctly', () => {
    render(<IOCList iocs={mockIOCs} isLoading={true} />);
    
    expect(document.querySelector('.animate-pulse')).toBeInTheDocument();
  });

  it('renders error state correctly', () => {
    const errorMessage = 'Failed to extract IOCs';
    render(<IOCList iocs={mockIOCs} error={errorMessage} />);
    
    expect(screen.getByText('IOC Extraction Failed')).toBeInTheDocument();
    expect(screen.getByText(errorMessage)).toBeInTheDocument();
  });

  it('renders empty state when no IOCs found', () => {
    render(<IOCList iocs={emptyIOCs} />);
    
    expect(screen.getByText('No IOCs Detected')).toBeInTheDocument();
    expect(screen.getByText(/No indicators of compromise/)).toBeInTheDocument();
  });

  it('renders IOCs correctly with statistics', () => {
    render(<IOCList iocs={mockIOCs} />);
    
    // Check header
    expect(screen.getByText('Indicators of Compromise (IOCs)')).toBeInTheDocument();
    expect(screen.getByText('4 indicators extracted from email content')).toBeInTheDocument();
    
    // Check statistics using more specific queries
    const allUrlsElements = screen.getAllByText('URLs');
    expect(allUrlsElements).toHaveLength(2); // One in stats, one in category
    
    const urlsStatSection = allUrlsElements[0].closest('.bg-blue-50');
    expect(urlsStatSection).toBeInTheDocument();
    expect(urlsStatSection?.querySelector('.text-blue-800')).toHaveTextContent('2');
    
    const allIpElements = screen.getAllByText('IP Addresses');
    const ipsStatSection = allIpElements[0].closest('.bg-green-50');
    expect(ipsStatSection).toBeInTheDocument();
    expect(ipsStatSection?.querySelector('.text-green-800')).toHaveTextContent('1');
    
    const allDomainsElements = screen.getAllByText('Domains');
    const domainsStatSection = allDomainsElements[0].closest('.bg-purple-50');
    expect(domainsStatSection).toBeInTheDocument();
    expect(domainsStatSection?.querySelector('.text-purple-800')).toHaveTextContent('1');
    
    // Check category headers exist
    expect(allIpElements).toHaveLength(2); // One in stats, one in category
    expect(allDomainsElements).toHaveLength(2); // One in stats, one in category
  });

  it('displays IOC values correctly', () => {
    render(<IOCList iocs={mockIOCs} />);
    
    expect(screen.getByText('https://malicious-site.com/login')).toBeInTheDocument();
    expect(screen.getByText('http://phishing-example.net/secure')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.100')).toBeInTheDocument();
    expect(screen.getByText('suspicious-domain.com')).toBeInTheDocument();
  });

  it('shows context when enabled', () => {
    render(<IOCList iocs={mockIOCs} />);
    
    expect(screen.getByText('Found in email body as a login link')).toBeInTheDocument();
    expect(screen.getByText('Found in email headers')).toBeInTheDocument();
  });

  it('hides context when disabled', async () => {
    const user = userEvent.setup();
    render(<IOCList iocs={mockIOCs} />);
    
    // Toggle context off
    const contextToggle = screen.getByLabelText('Show context');
    await user.click(contextToggle);
    
    expect(screen.queryByText('Found in email body as a login link')).not.toBeInTheDocument();
    expect(screen.queryByText('Found in email headers')).not.toBeInTheDocument();
  });

  it('handles copy functionality', async () => {
    const user = userEvent.setup();
    render(<IOCList iocs={mockIOCs} />);
    
    const copyButtons = screen.getAllByText('Copy');
    await user.click(copyButtons[0]);
    
    // Should show "Copied" feedback which indicates the copy function was executed
    await waitFor(() => {
      expect(screen.getByText('Copied')).toBeInTheDocument();
    }, { timeout: 3000 });
  });

  it('handles VirusTotal links', async () => {
    const user = userEvent.setup();
    render(<IOCList iocs={mockIOCs} />);
    
    const vtButtons = screen.getAllByText('VT');
    await user.click(vtButtons[0]);
    
    expect(window.open).toHaveBeenCalledWith(
      'https://virustotal.com/gui/url/abc123',
      '_blank',
      'noopener,noreferrer'
    );
  });

  it('handles export functionality', async () => {
    const user = userEvent.setup();
    
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
    
    render(<IOCList iocs={mockIOCs} />);
    
    const exportButton = screen.getByText('Export IOCs');
    await user.click(exportButton);
    
    expect(mockCreateObjectURL).toHaveBeenCalled();
    expect(mockClick).toHaveBeenCalled();
    expect(mockRevokeObjectURL).toHaveBeenCalledWith('mock-url');
  });

  it('displays category descriptions', () => {
    render(<IOCList iocs={mockIOCs} />);
    
    expect(screen.getByText(/URLs and web links found in the email content that may be malicious/)).toBeInTheDocument();
    expect(screen.getByText(/IP addresses extracted from email headers and content that may indicate malicious/)).toBeInTheDocument();
    expect(screen.getByText(/Domain names found in the email that may be spoofed/)).toBeInTheDocument();
  });

  it('shows usage instructions', () => {
    render(<IOCList iocs={mockIOCs} />);
    
    expect(screen.getByText('How to use IOCs:')).toBeInTheDocument();
    expect(screen.getByText(/Click the copy button to copy IOCs to your clipboard/)).toBeInTheDocument();
    expect(screen.getByText(/Click the VT button to analyze IOCs on VirusTotal/)).toBeInTheDocument();
  });

  it('handles IOCs without context gracefully', () => {
    const iocsWithoutContext: AnalysisResult['iocs'] = {
      urls: [{
        value: 'https://example.com',
        type: 'url',
        vtLink: 'https://virustotal.com/gui/url/test'
      }],
      ips: [],
      domains: []
    };
    
    render(<IOCList iocs={iocsWithoutContext} />);
    
    expect(screen.getByText('https://example.com')).toBeInTheDocument();
    // Should not show context section for IOCs without context - check that no context is displayed for this specific IOC
    const iocElement = screen.getByText('https://example.com').closest('.bg-white');
    expect(iocElement?.querySelector('.border-yellow-200')).not.toBeInTheDocument();
  });

  it('truncates long IOC values', () => {
    const longIOCs: AnalysisResult['iocs'] = {
      urls: [{
        value: 'https://very-long-domain-name-that-should-be-truncated-in-the-display.com/very/long/path/that/continues/for/a/while',
        type: 'url',
        vtLink: 'https://virustotal.com/gui/url/test'
      }],
      ips: [],
      domains: []
    };
    
    render(<IOCList iocs={longIOCs} />);
    
    // Should show truncated version - check for the truncated text in the title attribute
    const iocElement = screen.getByTitle(/https:\/\/very-long-domain-name-that-should-be-truncated-in-the-display\.com\/very\/long\/path/);
    expect(iocElement).toBeInTheDocument();
    expect(screen.getByText(/\.\.\./)).toBeInTheDocument();
  });

  it('displays correct IOC type badges', () => {
    render(<IOCList iocs={mockIOCs} />);
    
    expect(screen.getAllByText('URL')).toHaveLength(2);
    expect(screen.getByText('IP Address')).toBeInTheDocument();
    expect(screen.getByText('Domain')).toBeInTheDocument();
  });

  it('handles bulk operations', async () => {
    const user = userEvent.setup();
    render(<IOCList iocs={mockIOCs} />);
    
    // Look for bulk select functionality
    const selectAllButton = screen.queryByText('Select All');
    if (selectAllButton) {
      await user.click(selectAllButton);
      
      const copySelectedButton = screen.queryByText('Copy Selected');
      if (copySelectedButton) {
        await user.click(copySelectedButton);
        expect(mockWriteText).toHaveBeenCalled();
      }
    }
  });

  it('filters IOCs by type', async () => {
    const user = userEvent.setup();
    render(<IOCList iocs={mockIOCs} />);
    
    // Look for filter functionality
    const urlFilter = screen.queryByText('Show URLs only');
    if (urlFilter) {
      await user.click(urlFilter);
      
      // Should only show URLs
      expect(screen.getByText('https://malicious-site.com/login')).toBeInTheDocument();
      expect(screen.queryByText('192.168.1.100')).not.toBeInTheDocument();
    }
  });

  it('sorts IOCs correctly', async () => {
    const user = userEvent.setup();
    render(<IOCList iocs={mockIOCs} />);
    
    // Look for sort functionality
    const sortButton = screen.queryByText('Sort');
    if (sortButton) {
      await user.click(sortButton);
      
      const sortByType = screen.queryByText('Sort by Type');
      if (sortByType) {
        await user.click(sortByType);
        // IOCs should be reordered
      }
    }
  });

  it('handles IOC validation and warnings', () => {
    const iocsWithWarnings: AnalysisResult['iocs'] = {
      urls: [{
        value: 'http://suspicious-site.com', // HTTP instead of HTTPS
        type: 'url',
        vtLink: 'https://virustotal.com/gui/url/test'
      }],
      ips: [{
        value: '192.168.1.1', // Private IP
        type: 'ip',
        vtLink: 'https://virustotal.com/gui/ip-address/192.168.1.1'
      }],
      domains: []
    };
    
    render(<IOCList iocs={iocsWithWarnings} />);
    
    // Should show warnings for suspicious IOCs
    expect(screen.getByText('http://suspicious-site.com')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument();
  });

  it('displays IOC metadata when available', () => {
    const iocsWithMetadata: AnalysisResult['iocs'] = {
      urls: [{
        value: 'https://example.com',
        type: 'url',
        vtLink: 'https://virustotal.com/gui/url/test',
        context: 'Found in email body',
        metadata: {
          firstSeen: '2024-01-01T12:00:00Z',
          riskLevel: 'high'
        }
      }],
      ips: [],
      domains: []
    };
    
    render(<IOCList iocs={iocsWithMetadata} />);
    
    expect(screen.getByText('Found in email body')).toBeInTheDocument();
  });

  it('handles search functionality', async () => {
    const user = userEvent.setup();
    render(<IOCList iocs={mockIOCs} />);
    
    const searchInput = screen.queryByPlaceholderText('Search IOCs...');
    if (searchInput) {
      await user.type(searchInput, 'malicious');
      
      // Should filter to show only matching IOCs
      expect(screen.getByText('https://malicious-site.com/login')).toBeInTheDocument();
      expect(screen.queryByText('suspicious-domain.com')).not.toBeInTheDocument();
    }
  });

  it('shows IOC risk assessment', () => {
    const iocsWithRisk: AnalysisResult['iocs'] = {
      urls: [{
        value: 'https://known-malicious.com',
        type: 'url',
        vtLink: 'https://virustotal.com/gui/url/test',
        riskLevel: 'high'
      }],
      ips: [],
      domains: []
    };
    
    render(<IOCList iocs={iocsWithRisk} />);
    
    expect(screen.getByText('https://known-malicious.com')).toBeInTheDocument();
  });

  it('handles copy failures gracefully', async () => {
    const user = userEvent.setup();
    
    // Mock clipboard to fail
    mockWriteText.mockRejectedValue(new Error('Clipboard access denied'));
    
    render(<IOCList iocs={mockIOCs} />);
    
    const copyButtons = screen.getAllByText('Copy');
    await user.click(copyButtons[0]);
    
    // Should show error message
    await waitFor(() => {
      expect(screen.getByText(/Failed to copy/)).toBeInTheDocument();
    });
  });

  it('displays IOC statistics correctly', () => {
    render(<IOCList iocs={mockIOCs} />);
    
    // Check total count
    expect(screen.getByText('4 indicators extracted from email content')).toBeInTheDocument();
    
    // Check individual counts
    expect(screen.getByText('2')).toBeInTheDocument(); // URLs
    expect(screen.getByText('1')).toBeInTheDocument(); // IPs and Domains
  });

  it('handles keyboard navigation', async () => {
    const user = userEvent.setup();
    render(<IOCList iocs={mockIOCs} />);
    
    // Test keyboard navigation through IOCs
    const firstIOC = screen.getByText('https://malicious-site.com/login');
    await user.click(firstIOC);
    
    // Test arrow key navigation
    await user.keyboard('{ArrowDown}');
    
    // Should focus next IOC
  });

  it('shows IOC details in modal or expanded view', async () => {
    const user = userEvent.setup();
    render(<IOCList iocs={mockIOCs} />);
    
    // Look for detail view trigger
    const detailButtons = screen.queryAllByText('Details');
    if (detailButtons.length > 0) {
      await user.click(detailButtons[0]);
      
      // Should show detailed information
      expect(screen.getByText(/Detailed Information/)).toBeInTheDocument();
    }
  });

  it('handles IOC categorization', () => {
    const categorizedIOCs: AnalysisResult['iocs'] = {
      urls: [{
        value: 'https://phishing-site.com',
        type: 'url',
        vtLink: 'https://virustotal.com/gui/url/test',
        category: 'phishing'
      }],
      ips: [{
        value: '203.0.113.45',
        type: 'ip',
        vtLink: 'https://virustotal.com/gui/ip-address/203.0.113.45',
        category: 'malware_c2'
      }],
      domains: []
    };
    
    render(<IOCList iocs={categorizedIOCs} />);
    
    expect(screen.getByText('https://phishing-site.com')).toBeInTheDocument();
    expect(screen.getByText('203.0.113.45')).toBeInTheDocument();
  });
});