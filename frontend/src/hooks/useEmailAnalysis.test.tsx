import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useEmailAnalysis, useServiceHealth } from './useEmailAnalysis';
import { emailAnalysisService } from '../services/emailAnalysis';
import { AnalysisResult } from '../types/analysis.types';
import { ApiError } from '../types/api.types';

// Mock the email analysis service
vi.mock('../services/emailAnalysis', () => ({
  emailAnalysisService: {
    analyzeEmail: vi.fn(),
    checkServiceHealth: vi.fn()
  }
}));

const mockEmailAnalysisService = emailAnalysisService as any;

// Test wrapper with QueryClient
const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  
  const Wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
  
  return Wrapper;
};

describe('useEmailAnalysis', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should successfully analyze email', async () => {
    const mockResult: AnalysisResult = {
      intent: {
        primary: 'credential_theft',
        confidence: 'High',
        alternatives: ['wire_transfer']
      },
      deceptionIndicators: [],
      riskScore: {
        score: 8,
        confidence: 'High',
        reasoning: 'High risk indicators detected'
      },
      iocs: {
        urls: [],
        ips: [],
        domains: []
      },
      processingTime: 1500,
      timestamp: new Date().toISOString()
    };

    mockEmailAnalysisService.analyzeEmail.mockResolvedValue(mockResult);

    const onSuccess = vi.fn();
    const onError = vi.fn();

    const { result } = renderHook(
      () => useEmailAnalysis({ onSuccess, onError }),
      { wrapper: createWrapper() }
    );

    const emailContent = 'Test email content';
    result.current.mutate(emailContent);

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockEmailAnalysisService.analyzeEmail).toHaveBeenCalledWith(
      emailContent,
      { includeIOCs: true, confidenceThreshold: 0.5 }
    );
    expect(onSuccess).toHaveBeenCalledWith(mockResult);
    expect(onError).not.toHaveBeenCalled();
    expect(result.current.data).toEqual(mockResult);
  });

  it('should handle analysis errors', async () => {
    const mockError: ApiError = {
      code: 'ANALYSIS_FAILED',
      message: 'Analysis failed',
      retryable: true
    };

    mockEmailAnalysisService.analyzeEmail.mockRejectedValue(mockError);

    const onSuccess = vi.fn();
    const onError = vi.fn();

    const { result } = renderHook(
      () => useEmailAnalysis({ onSuccess, onError }),
      { wrapper: createWrapper() }
    );

    result.current.mutate('Test email content');

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(onSuccess).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith(mockError);
  });
});

describe('useServiceHealth', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should check service health successfully', async () => {
    mockEmailAnalysisService.checkServiceHealth.mockResolvedValue(true);

    const { result } = renderHook(
      () => useServiceHealth(),
      { wrapper: createWrapper() }
    );

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(result.current.data).toBe(true);
    expect(mockEmailAnalysisService.checkServiceHealth).toHaveBeenCalled();
  });

  it('should handle health check failures', async () => {
    mockEmailAnalysisService.checkServiceHealth.mockResolvedValue(false);

    const { result } = renderHook(
      () => useServiceHealth(),
      { wrapper: createWrapper() }
    );

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(result.current.data).toBe(false);
  });

  it('should handle health check errors', async () => {
    mockEmailAnalysisService.checkServiceHealth.mockRejectedValue(new Error('Network error'));

    const { result } = renderHook(
      () => useServiceHealth(),
      { wrapper: createWrapper() }
    );

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error).toBeInstanceOf(Error);
  });

  it('should refetch health status periodically', async () => {
    mockEmailAnalysisService.checkServiceHealth.mockResolvedValue(true);

    const { result } = renderHook(
      () => useServiceHealth(),
      { wrapper: createWrapper() }
    );

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    // Health check should be called initially
    expect(mockEmailAnalysisService.checkServiceHealth).toHaveBeenCalledTimes(1);
  });
});

describe('useEmailAnalysis - Advanced Scenarios', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should handle analysis with custom options', async () => {
    const mockResult: AnalysisResult = {
      intent: {
        primary: 'malware_delivery',
        confidence: 'Medium',
        alternatives: []
      },
      deceptionIndicators: [],
      riskScore: {
        score: 6,
        confidence: 'Medium',
        reasoning: 'Moderate risk indicators'
      },
      iocs: {
        urls: [],
        ips: [],
        domains: []
      },
      processingTime: 2000,
      timestamp: new Date().toISOString()
    };

    mockEmailAnalysisService.analyzeEmail.mockResolvedValue(mockResult);

    const { result } = renderHook(
      () => useEmailAnalysis(),
      { wrapper: createWrapper() }
    );

    const emailContent = 'Test email content';
    const customOptions = { includeIOCs: false, confidenceThreshold: 0.8 };
    
    result.current.mutate({ emailContent, options: customOptions });

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(mockEmailAnalysisService.analyzeEmail).toHaveBeenCalledWith(
      emailContent,
      customOptions
    );
  });

  it('should handle timeout errors specifically', async () => {
    const timeoutError: ApiError = {
      code: 'TIMEOUT',
      message: 'Request timed out',
      retryable: true
    };

    mockEmailAnalysisService.analyzeEmail.mockRejectedValue(timeoutError);

    const onError = vi.fn();

    const { result } = renderHook(
      () => useEmailAnalysis({ onError }),
      { wrapper: createWrapper() }
    );

    result.current.mutate('Test email content');

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(onError).toHaveBeenCalledWith(timeoutError);
    expect(result.current.error).toEqual(timeoutError);
  });

  it('should handle rate limit errors', async () => {
    const rateLimitError: ApiError = {
      code: 'RATE_LIMITED',
      message: 'Too many requests',
      retryable: true,
      retryAfter: 60
    };

    mockEmailAnalysisService.analyzeEmail.mockRejectedValue(rateLimitError);

    const { result } = renderHook(
      () => useEmailAnalysis(),
      { wrapper: createWrapper() }
    );

    result.current.mutate('Test email content');

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error).toEqual(rateLimitError);
  });

  it('should handle validation errors', async () => {
    const validationError: ApiError = {
      code: 'VALIDATION_ERROR',
      message: 'Invalid email format',
      retryable: false,
      details: 'Email content is too short'
    };

    mockEmailAnalysisService.analyzeEmail.mockRejectedValue(validationError);

    const { result } = renderHook(
      () => useEmailAnalysis(),
      { wrapper: createWrapper() }
    );

    result.current.mutate('short');

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error).toEqual(validationError);
  });

  it('should track loading states correctly', async () => {
    let resolveAnalysis: (value: AnalysisResult) => void;
    const analysisPromise = new Promise<AnalysisResult>((resolve) => {
      resolveAnalysis = resolve;
    });

    mockEmailAnalysisService.analyzeEmail.mockReturnValue(analysisPromise);

    const { result } = renderHook(
      () => useEmailAnalysis(),
      { wrapper: createWrapper() }
    );

    expect(result.current.isPending).toBe(false);

    result.current.mutate('Test email content');

    expect(result.current.isPending).toBe(true);
    expect(result.current.isSuccess).toBe(false);
    expect(result.current.isError).toBe(false);

    const mockResult: AnalysisResult = {
      intent: { primary: 'other', confidence: 'Low', alternatives: [] },
      deceptionIndicators: [],
      riskScore: { score: 3, confidence: 'Low', reasoning: 'Low risk' },
      iocs: { urls: [], ips: [], domains: [] },
      processingTime: 1000,
      timestamp: new Date().toISOString()
    };

    resolveAnalysis!(mockResult);

    await waitFor(() => {
      expect(result.current.isPending).toBe(false);
      expect(result.current.isSuccess).toBe(true);
    });
  });

  it('should reset state between analyses', async () => {
    const mockResult1: AnalysisResult = {
      intent: { primary: 'credential_theft', confidence: 'High', alternatives: [] },
      deceptionIndicators: [],
      riskScore: { score: 8, confidence: 'High', reasoning: 'High risk' },
      iocs: { urls: [], ips: [], domains: [] },
      processingTime: 1500,
      timestamp: new Date().toISOString()
    };

    const mockResult2: AnalysisResult = {
      intent: { primary: 'other', confidence: 'Low', alternatives: [] },
      deceptionIndicators: [],
      riskScore: { score: 2, confidence: 'Low', reasoning: 'Low risk' },
      iocs: { urls: [], ips: [], domains: [] },
      processingTime: 800,
      timestamp: new Date().toISOString()
    };

    mockEmailAnalysisService.analyzeEmail
      .mockResolvedValueOnce(mockResult1)
      .mockResolvedValueOnce(mockResult2);

    const { result } = renderHook(
      () => useEmailAnalysis(),
      { wrapper: createWrapper() }
    );

    // First analysis
    result.current.mutate('First email');

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(result.current.data).toEqual(mockResult1);

    // Reset and second analysis
    result.current.reset();
    result.current.mutate('Second email');

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true);
    });

    expect(result.current.data).toEqual(mockResult2);
  });
});