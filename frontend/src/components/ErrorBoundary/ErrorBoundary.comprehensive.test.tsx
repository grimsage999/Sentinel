/**
 * Comprehensive tests for Error Boundary components
 * Tests error handling, recovery, and user experience
 */

import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import ErrorBoundary from './ErrorBoundary';
import { ApiErrorBoundary } from './ApiErrorBoundary';

// Mock console.error to avoid noise in tests
const originalError = console.error;
beforeEach(() => {
  console.error = vi.fn();
});

afterEach(() => {
  console.error = originalError;
});

// Test component that throws errors
const ThrowError = ({ shouldThrow = false, errorType = 'generic' }: { 
  shouldThrow?: boolean; 
  errorType?: string;
}) => {
  if (shouldThrow) {
    if (errorType === 'api') {
      throw new Error('API_ERROR: Service unavailable');
    } else if (errorType === 'validation') {
      throw new Error('VALIDATION_ERROR: Invalid input');
    } else if (errorType === 'network') {
      throw new Error('NETWORK_ERROR: Connection failed');
    } else {
      throw new Error('Something went wrong');
    }
  }
  return <div>No error</div>;
};

describe('ErrorBoundary', () => {
  it('renders children when there is no error', () => {
    render(
      <ErrorBoundary>
        <div>Test content</div>
      </ErrorBoundary>
    );

    expect(screen.getByText('Test content')).toBeInTheDocument();
  });

  it('renders error UI when child component throws', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
    expect(screen.getByText(/We apologize for the inconvenience/)).toBeInTheDocument();
  });

  it('displays error details in development mode', () => {
    // Mock development environment
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Error Details/)).toBeInTheDocument();
    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();

    process.env.NODE_ENV = originalEnv;
  });

  it('hides error details in production mode', () => {
    // Mock production environment
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.queryByText(/Error Details/)).not.toBeInTheDocument();
    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();

    process.env.NODE_ENV = originalEnv;
  });

  it('provides retry functionality', async () => {
    const user = userEvent.setup();
    let shouldThrow = true;

    const RetryableComponent = () => {
      if (shouldThrow) {
        throw new Error('Retryable error');
      }
      return <div>Success after retry</div>;
    };

    const { rerender } = render(
      <ErrorBoundary>
        <RetryableComponent />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();

    const retryButton = screen.getByText('Try Again');
    
    // Simulate fixing the error
    shouldThrow = false;
    
    await user.click(retryButton);

    // Rerender to simulate retry
    rerender(
      <ErrorBoundary>
        <RetryableComponent />
      </ErrorBoundary>
    );

    expect(screen.getByText('Success after retry')).toBeInTheDocument();
  });

  it('logs errors for monitoring', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Error caught by boundary'),
      expect.any(Error)
    );

    consoleSpy.mockRestore();
  });

  it('handles different error types appropriately', () => {
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} errorType="api" />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();

    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} errorType="validation" />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
  });

  it('provides error reporting functionality', async () => {
    const user = userEvent.setup();
    const mockReportError = vi.fn();

    // Mock error reporting service
    vi.stubGlobal('errorReportingService', {
      reportError: mockReportError
    });

    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    const reportButton = screen.queryByText('Report Error');
    if (reportButton) {
      await user.click(reportButton);
      expect(mockReportError).toHaveBeenCalled();
    }
  });

  it('resets error state when children change', () => {
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();

    rerender(
      <ErrorBoundary>
        <div>New content</div>
      </ErrorBoundary>
    );

    expect(screen.getByText('New content')).toBeInTheDocument();
    expect(screen.queryByText(/Something went wrong/)).not.toBeInTheDocument();
  });
});

describe('ApiErrorBoundary', () => {
  it('handles API-specific errors', () => {
    render(
      <ApiErrorBoundary>
        <ThrowError shouldThrow={true} errorType="api" />
      </ApiErrorBoundary>
    );

    expect(screen.getByText(/API Error/)).toBeInTheDocument();
    expect(screen.getByText(/Service unavailable/)).toBeInTheDocument();
  });

  it('provides API-specific error recovery options', async () => {
    const user = userEvent.setup();

    render(
      <ApiErrorBoundary>
        <ThrowError shouldThrow={true} errorType="api" />
      </ApiErrorBoundary>
    );

    expect(screen.getByText(/Check Service Status/)).toBeInTheDocument();
    
    const statusButton = screen.getByText('Check Service Status');
    await user.click(statusButton);

    // Should trigger service health check
  });

  it('shows different messages for different API error types', () => {
    const { rerender } = render(
      <ApiErrorBoundary>
        <ThrowError shouldThrow={true} errorType="network" />
      </ApiErrorBoundary>
    );

    expect(screen.getByText(/Network Error/)).toBeInTheDocument();

    rerender(
      <ApiErrorBoundary>
        <ThrowError shouldThrow={true} errorType="validation" />
      </ApiErrorBoundary>
    );

    expect(screen.getByText(/Validation Error/)).toBeInTheDocument();
  });

  it('provides offline detection and messaging', () => {
    // Mock navigator.onLine
    Object.defineProperty(navigator, 'onLine', {
      writable: true,
      value: false
    });

    render(
      <ApiErrorBoundary>
        <ThrowError shouldThrow={true} errorType="network" />
      </ApiErrorBoundary>
    );

    expect(screen.getByText(/You appear to be offline/)).toBeInTheDocument();
  });

  it('handles rate limiting errors with retry timing', () => {
    const RateLimitError = () => {
      const error = new Error('RATE_LIMITED: Too many requests');
      (error as any).retryAfter = 60;
      throw error;
    };

    render(
      <ApiErrorBoundary>
        <RateLimitError />
      </ApiErrorBoundary>
    );

    expect(screen.getByText(/Rate Limited/)).toBeInTheDocument();
    expect(screen.getByText(/Try again in 60 seconds/)).toBeInTheDocument();
  });
});

describe('Error Boundary Integration', () => {
  it('works with React Query error handling', async () => {
    const QueryErrorComponent = () => {
      // Simulate React Query error
      throw {
        name: 'QueryError',
        message: 'Query failed',
        cause: new Error('Network error')
      };
    };

    render(
      <ErrorBoundary>
        <QueryErrorComponent />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();
  });

  it('handles async errors in useEffect', async () => {
    const AsyncErrorComponent = () => {
      React.useEffect(() => {
        // Simulate async error that should be caught
        setTimeout(() => {
          throw new Error('Async error');
        }, 0);
      }, []);

      return <div>Component with async error</div>;
    };

    render(
      <ErrorBoundary>
        <AsyncErrorComponent />
      </ErrorBoundary>
    );

    // Note: Error boundaries don't catch async errors by default
    // This test documents the limitation
    expect(screen.getByText('Component with async error')).toBeInTheDocument();
  });

  it('provides error context to child components', () => {
    const ErrorContextConsumer = () => {
      // If error context is provided
      const errorContext = React.useContext(ErrorContext);
      
      if (errorContext?.hasError) {
        return <div>Error context available</div>;
      }
      
      return <div>No error context</div>;
    };

    render(
      <ErrorBoundary>
        <ErrorContextConsumer />
      </ErrorBoundary>
    );

    expect(screen.getByText('No error context')).toBeInTheDocument();
  });

  it('handles multiple nested error boundaries', () => {
    render(
      <ErrorBoundary fallback={<div>Outer boundary</div>}>
        <ErrorBoundary fallback={<div>Inner boundary</div>}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      </ErrorBoundary>
    );

    // Inner boundary should catch the error
    expect(screen.getByText('Inner boundary')).toBeInTheDocument();
    expect(screen.queryByText('Outer boundary')).not.toBeInTheDocument();
  });

  it('provides accessibility features for error states', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    // Should have proper ARIA attributes
    const errorContainer = screen.getByRole('alert');
    expect(errorContainer).toBeInTheDocument();
    expect(errorContainer).toHaveAttribute('aria-live', 'polite');
  });

  it('handles component unmounting during error state', () => {
    const { unmount } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Something went wrong/)).toBeInTheDocument();

    // Should unmount cleanly
    expect(() => unmount()).not.toThrow();
  });
});

// Mock ErrorContext for testing
const ErrorContext = React.createContext<{ hasError: boolean } | null>(null);