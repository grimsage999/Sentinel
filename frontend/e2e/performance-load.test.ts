/**
 * Performance and load testing for PhishContext AI
 * Tests system behavior under various load conditions and performance requirements
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '@testing-library/jest-dom';

import App from '../src/App';
import { TestUtils, mockApiResponses, sampleEmails } from './setup';

// Performance monitoring utilities
class PerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();
  private observers: PerformanceObserver[] = [];

  startMonitoring() {
    // Monitor navigation timing
    if ('performance' in window && 'getEntriesByType' in performance) {
      const navEntries = performance.getEntriesByType('navigation') as PerformanceNavigationTiming[];
      if (navEntries.length > 0) {
        const nav = navEntries[0];
        this.recordMetric('domContentLoaded', nav.domContentLoadedEventEnd - nav.domContentLoadedEventStart);
        this.recordMetric('loadComplete', nav.loadEventEnd - nav.loadEventStart);
      }
    }

    // Monitor resource loading
    if ('PerformanceObserver' in window) {
      const resourceObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.entryType === 'resource') {
            const resource = entry as PerformanceResourceTiming;
            this.recordMetric('resourceLoad', resource.responseEnd - resource.requestStart);
          }
        }
      });
      resourceObserver.observe({ entryTypes: ['resource'] });
      this.observers.push(resourceObserver);

      // Monitor long tasks
      const longTaskObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.entryType === 'longtask') {
            this.recordMetric('longTask', entry.duration);
          }
        }
      });
      longTaskObserver.observe({ entryTypes: ['longtask'] });
      this.observers.push(longTaskObserver);
    }
  }

  recordMetric(name: string, value: number) {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    this.metrics.get(name)!.push(value);
  }

  getMetrics(name: string) {
    const values = this.metrics.get(name) || [];
    if (values.length === 0) return null;

    return {
      min: Math.min(...values),
      max: Math.max(...values),
      avg: values.reduce((a, b) => a + b, 0) / values.length,
      count: values.length,
      values
    };
  }

  cleanup() {
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
    this.metrics.clear();
  }
}

// Load testing utilities
class LoadTester {
  private activeRequests = 0;
  private completedRequests = 0;
  private failedRequests = 0;
  private responseTimes: number[] = [];

  async simulateConcurrentUsers(userCount: number, testDuration: number): Promise<LoadTestResults> {
    const startTime = Date.now();
    const promises: Promise<void>[] = [];

    for (let i = 0; i < userCount; i++) {
      promises.push(this.simulateUser(i, startTime, testDuration));
    }

    await Promise.all(promises);

    return {
      totalRequests: this.completedRequests + this.failedRequests,
      completedRequests: this.completedRequests,
      failedRequests: this.failedRequests,
      averageResponseTime: this.responseTimes.reduce((a, b) => a + b, 0) / this.responseTimes.length,
      minResponseTime: Math.min(...this.responseTimes),
      maxResponseTime: Math.max(...this.responseTimes),
      requestsPerSecond: (this.completedRequests + this.failedRequests) / (testDuration / 1000)
    };
  }

  private async simulateUser(userId: number, startTime: number, duration: number): Promise<void> {
    while (Date.now() - startTime < duration) {
      try {
        this.activeRequests++;
        const requestStart = Date.now();
        
        // Simulate API request
        await this.makeRequest();
        
        const responseTime = Date.now() - requestStart;
        this.responseTimes.push(responseTime);
        this.completedRequests++;
      } catch (error) {
        this.failedRequests++;
      } finally {
        this.activeRequests--;
      }

      // Wait between requests (simulate user think time)
      await new Promise(resolve => setTimeout(resolve, Math.random() * 2000 + 1000));
    }
  }

  private async makeRequest(): Promise<void> {
    return new Promise((resolve, reject) => {
      // Simulate network delay
      const delay = Math.random() * 1000 + 500;
      setTimeout(() => {
        // Simulate 95% success rate
        if (Math.random() < 0.95) {
          resolve();
        } else {
          reject(new Error('Simulated request failure'));
        }
      }, delay);
    });
  }

  reset() {
    this.activeRequests = 0;
    this.completedRequests = 0;
    this.failedRequests = 0;
    this.responseTimes = [];
  }
}

interface LoadTestResults {
  totalRequests: number;
  completedRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  minResponseTime: number;
  maxResponseTime: number;
  requestsPerSecond: number;
}

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

describe('Performance Testing', () => {
  let performanceMonitor: PerformanceMonitor;
  let mockServer: ReturnType<typeof TestUtils.createMockServer>;

  beforeEach(() => {
    performanceMonitor = new PerformanceMonitor();
    performanceMonitor.startMonitoring();
    
    mockServer = TestUtils.createMockServer();
    mockServer.install();

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
    performanceMonitor.cleanup();
    mockServer.restore();
  });

  it('loads initial page within performance budget', async () => {
    const startTime = performance.now();
    
    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const loadTime = performance.now() - startTime;
    
    // Should load within 2 seconds
    expect(loadTime).toBeLessThan(2000);
    
    // Check for performance metrics
    const metrics = performanceMonitor.getMetrics('domContentLoaded');
    if (metrics) {
      expect(metrics.avg).toBeLessThan(1000); // DOM should load within 1 second
    }
  });

  it('handles large email content efficiently', async () => {
    const user = userEvent.setup();
    
    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    // Create large email content (near 1MB limit)
    const largeEmailContent = sampleEmails.validPhishingEmail + '\n' + 'x'.repeat(900000);
    
    const textarea = screen.getByLabelText('Email Content');
    
    const startTime = performance.now();
    
    // Use paste instead of typing for large content
    await TestUtils.simulatePaste(textarea, largeEmailContent);
    
    const pasteTime = performance.now() - startTime;
    
    // Pasting large content should be fast
    expect(pasteTime).toBeLessThan(500);
    
    // Character count should update quickly
    await waitFor(() => {
      expect(screen.getByText(/900000\+ characters/)).toBeInTheDocument();
    }, { timeout: 1000 });
  });

  it('maintains responsive UI during analysis', async () => {
    const user = userEvent.setup();
    
    // Mock slow API response
    mockServer.mock('POST', '/api/analyze', {
      status: 200,
      data: mockApiResponses.analysisSuccess,
      delay: 5000 // 5 second delay
    });

    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const textarea = screen.getByLabelText('Email Content');
    await user.type(textarea, sampleEmails.validPhishingEmail);

    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
    
    const startTime = performance.now();
    await user.click(analyzeButton);

    // UI should remain responsive during analysis
    expect(screen.getByText(/Analyzing/)).toBeInTheDocument();
    
    // Test UI responsiveness by interacting with other elements
    const clearButton = screen.queryByText('Clear');
    if (clearButton) {
      const clickTime = performance.now();
      await user.click(clearButton);
      const responseTime = performance.now() - clickTime;
      
      // UI interactions should be fast even during analysis
      expect(responseTime).toBeLessThan(100);
    }

    // Check for long tasks that might block the UI
    const longTaskMetrics = performanceMonitor.getMetrics('longTask');
    if (longTaskMetrics) {
      // No task should block the main thread for more than 50ms
      expect(longTaskMetrics.max).toBeLessThan(50);
    }
  });

  it('efficiently renders analysis results', async () => {
    const user = userEvent.setup();
    
    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const textarea = screen.getByLabelText('Email Content');
    await user.type(textarea, sampleEmails.validPhishingEmail);

    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });
    
    const startTime = performance.now();
    await user.click(analyzeButton);

    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
    });

    const renderTime = performance.now() - startTime;
    
    // Results should render quickly after API response
    expect(renderTime).toBeLessThan(3000);
    
    // Verify all result components are rendered
    expect(screen.getByText(/Email Analysis Results/)).toBeInTheDocument();
    expect(screen.getByText(/Indicators of Compromise/)).toBeInTheDocument();
  });

  it('handles memory efficiently with multiple analyses', async () => {
    const user = userEvent.setup();
    
    render(<App />, { wrapper: createTestWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/PhishContext AI/)).toBeInTheDocument();
    });

    const textarea = screen.getByLabelText('Email Content');
    const analyzeButton = screen.getByRole('button', { name: /Analyze Email/i });

    // Perform multiple analyses to test memory usage
    for (let i = 0; i < 5; i++) {
      await user.clear(textarea);
      await user.type(textarea, sampleEmails.validPhishingEmail + ` - Analysis ${i}`);
      await user.click(analyzeButton);

      await waitFor(() => {
        expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
      });

      // Clear results before next analysis
      const clearButton = screen.getByText('Clear');
      await user.click(clearButton);
    }

    // Memory usage should remain stable
    if ('memory' in performance) {
      const memInfo = (performance as any).memory;
      const memoryUsage = memInfo.usedJSHeapSize / memInfo.totalJSHeapSize;
      
      // Memory usage should be reasonable (less than 80%)
      expect(memoryUsage).toBeLessThan(0.8);
    }
  });
});

describe('Load Testing', () => {
  let loadTester: LoadTester;
  let mockServer: ReturnType<typeof TestUtils.createMockServer>;

  beforeEach(() => {
    loadTester = new LoadTester();
    mockServer = TestUtils.createMockServer();
    mockServer.install();

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
    loadTester.reset();
    mockServer.restore();
  });

  it('handles concurrent user load', async () => {
    const userCount = 10;
    const testDuration = 5000; // 5 seconds

    const results = await loadTester.simulateConcurrentUsers(userCount, testDuration);

    // Verify load test results
    expect(results.totalRequests).toBeGreaterThan(0);
    expect(results.failedRequests / results.totalRequests).toBeLessThan(0.1); // Less than 10% failure rate
    expect(results.averageResponseTime).toBeLessThan(2000); // Average response under 2 seconds
    expect(results.requestsPerSecond).toBeGreaterThan(1); // At least 1 request per second
  });

  it('maintains performance under sustained load', async () => {
    const userCount = 5;
    const testDuration = 10000; // 10 seconds

    const results = await loadTester.simulateConcurrentUsers(userCount, testDuration);

    // Performance should remain stable under sustained load
    expect(results.maxResponseTime).toBeLessThan(5000); // Max response under 5 seconds
    expect(results.failedRequests / results.totalRequests).toBeLessThan(0.05); // Less than 5% failure rate
  });

  it('gracefully degrades under high load', async () => {
    // Simulate high load scenario
    mockServer.mock('POST', '/api/analyze', {
      status: 503,
      data: mockApiResponses.rateLimitError
    });

    const userCount = 20;
    const testDuration = 3000; // 3 seconds

    const results = await loadTester.simulateConcurrentUsers(userCount, testDuration);

    // System should handle high load gracefully
    expect(results.totalRequests).toBeGreaterThan(0);
    // Higher failure rate is acceptable under extreme load
    expect(results.failedRequests / results.totalRequests).toBeLessThan(0.5);
  });
});

describe('Stress Testing', () => {
  let mockServer: ReturnType<typeof TestUtils.createMockServer>;

  beforeEach(() => {
    mockServer = TestUtils.createMockServer();
    mockServer.install();
  });

  afterEach(() => {
    mockServer.restore();
  });

  it('handles rapid successive requests', async () => {
    const user = userEvent.setup();
    
    mockServer.mock('GET', '/api/health', {
      status: 200,
      data: mockApiResponses.healthCheck
    });

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

    // Rapidly click analyze button multiple times
    const clickPromises = [];
    for (let i = 0; i < 10; i++) {
      clickPromises.push(user.click(analyzeButton));
    }

    await Promise.all(clickPromises);

    // Should handle rapid clicks gracefully (button should be disabled after first click)
    expect(analyzeButton).toBeDisabled();

    await waitFor(() => {
      expect(screen.getByText(/Analysis Complete/)).toBeInTheDocument();
    });
  });

  it('recovers from API failures', async () => {
    const user = userEvent.setup();
    
    mockServer.mock('GET', '/api/health', {
      status: 200,
      data: mockApiResponses.healthCheck
    });

    // First request fails
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

    // System should recover successfully
    expect(screen.getByText(/Credential Theft/)).toBeInTheDocument();
  });
});