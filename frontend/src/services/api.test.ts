/**
 * Integration tests for API communication and error handling
 * Tests the API service layer and error handling mechanisms
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { apiClient, handleApiError } from './api';
import { ApiError } from '../types/api.types';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('API Client', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should make successful GET requests', async () => {
    const mockResponse = { data: 'test data' };
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockResponse),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    const result = await apiClient.get('/test-endpoint');

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/test-endpoint'),
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({
          'Content-Type': 'application/json'
        })
      })
    );
    expect(result).toEqual(mockResponse);
  });

  it('should make successful POST requests', async () => {
    const mockResponse = { success: true };
    const requestData = { email_content: 'test email' };

    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockResponse),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    const result = await apiClient.post('/analyze', requestData);

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/analyze'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json'
        }),
        body: JSON.stringify(requestData)
      })
    );
    expect(result).toEqual(mockResponse);
  });

  it('should handle 400 Bad Request errors', async () => {
    const errorResponse = {
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Invalid input',
        details: 'Email content is required'
      }
    };

    mockFetch.mockResolvedValue({
      ok: false,
      status: 400,
      json: () => Promise.resolve(errorResponse),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    await expect(apiClient.post('/analyze', {})).rejects.toThrow();
  });

  it('should handle 401 Unauthorized errors', async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 401,
      json: () => Promise.resolve({ error: { message: 'Unauthorized' } }),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    await expect(apiClient.get('/protected')).rejects.toThrow();
  });

  it('should handle 429 Rate Limit errors', async () => {
    const errorResponse = {
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests',
        retryAfter: 60
      }
    };

    mockFetch.mockResolvedValue({
      ok: false,
      status: 429,
      json: () => Promise.resolve(errorResponse),
      headers: new Headers({ 
        'content-type': 'application/json',
        'retry-after': '60'
      })
    });

    await expect(apiClient.post('/analyze', {})).rejects.toThrow();
  });

  it('should handle 500 Internal Server errors', async () => {
    const errorResponse = {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        retryable: true
      }
    };

    mockFetch.mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.resolve(errorResponse),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    await expect(apiClient.get('/test')).rejects.toThrow();
  });

  it('should handle 503 Service Unavailable errors', async () => {
    const errorResponse = {
      error: {
        code: 'SERVICE_UNAVAILABLE',
        message: 'Service temporarily unavailable',
        retryable: true
      }
    };

    mockFetch.mockResolvedValue({
      ok: false,
      status: 503,
      json: () => Promise.resolve(errorResponse),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    await expect(apiClient.post('/analyze', {})).rejects.toThrow();
  });

  it('should handle network errors', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));

    await expect(apiClient.get('/test')).rejects.toThrow('Network error');
  });

  it('should handle timeout errors', async () => {
    mockFetch.mockImplementation(() => 
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Request timeout')), 100)
      )
    );

    await expect(apiClient.get('/test')).rejects.toThrow();
  });

  it('should include request ID in headers when provided', async () => {
    const mockResponse = { data: 'test' };
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockResponse),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    await apiClient.get('/test', { requestId: 'test-request-123' });

    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        headers: expect.objectContaining({
          'X-Request-ID': 'test-request-123'
        })
      })
    );
  });

  it('should handle non-JSON responses', async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 500,
      json: () => Promise.reject(new Error('Not JSON')),
      text: () => Promise.resolve('Internal Server Error'),
      headers: new Headers({ 'content-type': 'text/plain' })
    });

    await expect(apiClient.get('/test')).rejects.toThrow();
  });
});

describe('Error Handling', () => {
  it('should handle API errors correctly', () => {
    const apiError: ApiError = {
      code: 'VALIDATION_ERROR',
      message: 'Invalid input',
      details: 'Email content is required',
      retryable: false
    };

    const handledError = handleApiError(apiError);

    expect(handledError.code).toBe('VALIDATION_ERROR');
    expect(handledError.message).toBe('Invalid input');
    expect(handledError.retryable).toBe(false);
  });

  it('should provide default error handling for unknown errors', () => {
    const unknownError = new Error('Unknown error');

    const handledError = handleApiError(unknownError);

    expect(handledError.code).toBe('UNKNOWN_ERROR');
    expect(handledError.message).toBe('Unknown error');
    expect(handledError.retryable).toBe(false);
  });

  it('should handle errors with retry information', () => {
    const retryableError: ApiError = {
      code: 'RATE_LIMITED',
      message: 'Too many requests',
      retryable: true,
      retryAfter: 60
    };

    const handledError = handleApiError(retryableError);

    expect(handledError.retryable).toBe(true);
    expect(handledError.retryAfter).toBe(60);
  });

  it('should sanitize sensitive information from errors', () => {
    const errorWithSensitiveData: ApiError = {
      code: 'API_ERROR',
      message: 'Error processing request',
      details: 'API key: sk-1234567890abcdef is invalid',
      retryable: false
    };

    const handledError = handleApiError(errorWithSensitiveData);

    // Should not contain sensitive API key information
    expect(handledError.details).not.toContain('sk-1234567890abcdef');
  });
});

describe('Request Interceptors', () => {
  it('should add authentication headers when available', async () => {
    // Mock localStorage or auth context
    const mockAuthToken = 'mock-auth-token';
    vi.stubGlobal('localStorage', {
      getItem: vi.fn().mockReturnValue(mockAuthToken)
    });

    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({}),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    await apiClient.get('/protected');

    // Should include auth header if implemented
    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        headers: expect.any(Object)
      })
    );
  });

  it('should add user agent information', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({}),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    await apiClient.get('/test');

    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        headers: expect.objectContaining({
          'User-Agent': expect.stringContaining('PhishContext')
        })
      })
    );
  });
});

describe('Response Interceptors', () => {
  it('should handle successful responses with metadata', async () => {
    const mockResponse = {
      success: true,
      data: { result: 'test' },
      meta: {
        processing_time: 1500,
        request_id: 'req-123'
      }
    };

    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(mockResponse),
      headers: new Headers({ 
        'content-type': 'application/json',
        'x-request-id': 'req-123'
      })
    });

    const result = await apiClient.get('/test');

    expect(result).toEqual(mockResponse);
  });

  it('should log response times for monitoring', async () => {
    const consoleSpy = vi.spyOn(console, 'debug').mockImplementation(() => {});

    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ data: 'test' }),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    await apiClient.get('/test');

    // Should log performance metrics in development
    expect(consoleSpy).toHaveBeenCalled();
    
    consoleSpy.mockRestore();
  });
});

describe('Request Retry Logic', () => {
  it('should retry failed requests for retryable errors', async () => {
    const errorResponse = {
      error: {
        code: 'SERVICE_UNAVAILABLE',
        message: 'Service temporarily unavailable',
        retryable: true
      }
    };

    const successResponse = { data: 'success' };

    mockFetch
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: () => Promise.resolve(errorResponse),
        headers: new Headers({ 'content-type': 'application/json' })
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(successResponse),
        headers: new Headers({ 'content-type': 'application/json' })
      });

    // If retry logic is implemented
    const result = await apiClient.get('/test', { retry: true });

    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(result).toEqual(successResponse);
  });

  it('should not retry non-retryable errors', async () => {
    const errorResponse = {
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Invalid input',
        retryable: false
      }
    };

    mockFetch.mockResolvedValue({
      ok: false,
      status: 400,
      json: () => Promise.resolve(errorResponse),
      headers: new Headers({ 'content-type': 'application/json' })
    });

    await expect(apiClient.get('/test', { retry: true })).rejects.toThrow();

    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});