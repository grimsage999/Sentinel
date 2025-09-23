/**
 * End-to-end test setup and configuration
 * Sets up test environment, mocks, and utilities for e2e testing
 */

import { beforeAll, afterAll, beforeEach, afterEach } from 'vitest';

// Mock API responses for e2e tests
export const mockApiResponses = {
  healthCheck: {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      openai: 'available',
      anthropic: 'available',
      configuration: 'available'
    },
    uptime: 3600
  },

  analysisSuccess: {
    success: true,
    data: {
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
            value: 'https://fake-amazon.com/login',
            type: 'url',
            vtLink: 'https://virustotal.com/gui/url/abc123',
            context: 'Found in email body as login link'
          }
        ],
        ips: [
          {
            value: '203.0.113.45',
            type: 'ip',
            vtLink: 'https://virustotal.com/gui/ip-address/203.0.113.45',
            context: 'Found in email headers'
          }
        ],
        domains: [
          {
            value: 'fake-amazon.com',
            type: 'domain',
            vtLink: 'https://virustotal.com/gui/domain/fake-amazon.com'
          }
        ]
      },
      processingTime: 2500,
      timestamp: new Date().toISOString()
    },
    meta: {
      total_processing_time: 2.5,
      ioc_count: {
        urls: 1,
        ips: 1,
        domains: 1
      },
      email_size_bytes: 1024
    }
  },

  analysisError: {
    success: false,
    error: {
      code: 'LLM_ERROR',
      message: 'AI analysis service temporarily unavailable',
      details: 'Please try again in a few moments.',
      retryable: true
    }
  },

  validationError: {
    success: false,
    error: {
      code: 'VALIDATION_ERROR',
      message: 'Input validation failed',
      details: 'Email content is too short (minimum 50 characters required)',
      retryable: false
    }
  },

  rateLimitError: {
    success: false,
    error: {
      code: 'RATE_LIMITED',
      message: 'Service temporarily unavailable due to high demand',
      details: 'Please wait a moment and try again.',
      retryable: true
    }
  }
};

// Sample email content for testing
export const sampleEmails = {
  validPhishingEmail: `From: security@amaz0n.com
To: victim@company.com
Subject: URGENT: Your Amazon Account Has Been Suspended
Date: Mon, 1 Jan 2024 12:00:00 +0000
Reply-To: noreply@fake-amazon.com

Dear Amazon Customer,

Your account has been suspended due to suspicious activity. 

URGENT ACTION REQUIRED: You have 24 hours to verify your account or it will be permanently closed.

Click here to verify your account immediately:
https://fake-amazon.com/login?verify=account

If you do not take action within 24 hours, your account and all associated services will be terminated.

Thank you,
Amazon Security Team

This email was sent from: 203.0.113.45`,

  shortEmail: 'From: test@example.com\nSubject: Short\n\nShort email',

  invalidEmail: 'This is not an email format at all',

  legitimateEmail: `From: notifications@amazon.com
To: customer@example.com
Subject: Your Order Confirmation
Date: Mon, 1 Jan 2024 12:00:00 +0000

Dear Customer,

Thank you for your recent order. Your order #123456789 has been confirmed and will be shipped within 2-3 business days.

You can track your order at: https://amazon.com/orders/123456789

Best regards,
Amazon Customer Service`,

  malwareEmail: `From: support@company-update.com
To: employee@company.com
Subject: Important Software Update Required
Date: Mon, 1 Jan 2024 12:00:00 +0000

Dear Employee,

Please download and install the attached security update immediately.

Download link: http://malware-site.com/update.exe

This update is mandatory for all employees.

IT Department`
};

// Test utilities
export class TestUtils {
  static async waitForElement(selector: string, timeout = 5000): Promise<Element | null> {
    return new Promise((resolve) => {
      const element = document.querySelector(selector);
      if (element) {
        resolve(element);
        return;
      }

      const observer = new MutationObserver(() => {
        const element = document.querySelector(selector);
        if (element) {
          observer.disconnect();
          resolve(element);
        }
      });

      observer.observe(document.body, {
        childList: true,
        subtree: true
      });

      setTimeout(() => {
        observer.disconnect();
        resolve(null);
      }, timeout);
    });
  }

  static async waitForText(text: string, timeout = 5000): Promise<Element | null> {
    return new Promise((resolve) => {
      const findElement = () => {
        const elements = Array.from(document.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes(text)) || null;
      };

      const element = findElement();
      if (element) {
        resolve(element);
        return;
      }

      const observer = new MutationObserver(() => {
        const element = findElement();
        if (element) {
          observer.disconnect();
          resolve(element);
        }
      });

      observer.observe(document.body, {
        childList: true,
        subtree: true
      });

      setTimeout(() => {
        observer.disconnect();
        resolve(null);
      }, timeout);
    });
  }

  static simulateTyping(element: HTMLElement, text: string, delay = 50): Promise<void> {
    return new Promise((resolve) => {
      let index = 0;
      const type = () => {
        if (index < text.length) {
          const char = text[index];
          element.dispatchEvent(new KeyboardEvent('keydown', { key: char }));
          if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
            element.value += char;
          }
          element.dispatchEvent(new KeyboardEvent('keyup', { key: char }));
          element.dispatchEvent(new Event('input', { bubbles: true }));
          index++;
          setTimeout(type, delay);
        } else {
          resolve();
        }
      };
      type();
    });
  }

  static async simulatePaste(element: HTMLElement, text: string): Promise<void> {
    const clipboardData = new DataTransfer();
    clipboardData.setData('text/plain', text);
    
    const pasteEvent = new ClipboardEvent('paste', {
      clipboardData,
      bubbles: true,
      cancelable: true
    });

    element.dispatchEvent(pasteEvent);

    if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
      element.value = text;
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  static createMockServer() {
    const originalFetch = global.fetch;
    const mockResponses = new Map<string, any>();

    const mockFetch = async (url: string | Request, options?: RequestInit) => {
      const urlString = typeof url === 'string' ? url : url.url;
      const method = options?.method || 'GET';
      const key = `${method} ${urlString}`;

      if (mockResponses.has(key)) {
        const response = mockResponses.get(key);
        return Promise.resolve({
          ok: response.status < 400,
          status: response.status || 200,
          json: () => Promise.resolve(response.data),
          text: () => Promise.resolve(JSON.stringify(response.data)),
          headers: new Headers(response.headers || {})
        });
      }

      // Default to original fetch if no mock found
      return originalFetch(url as any, options);
    };

    return {
      mock: (method: string, url: string, response: any) => {
        mockResponses.set(`${method} ${url}`, response);
      },
      restore: () => {
        global.fetch = originalFetch;
      },
      install: () => {
        global.fetch = mockFetch as any;
      }
    };
  }
}

// Global test setup
let mockServer: ReturnType<typeof TestUtils.createMockServer>;

beforeAll(() => {
  // Set up global mocks
  mockServer = TestUtils.createMockServer();
  mockServer.install();

  // Mock common API endpoints
  mockServer.mock('GET', '/api/health', {
    status: 200,
    data: mockApiResponses.healthCheck
  });

  // Mock console methods to reduce noise in tests
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterAll(() => {
  mockServer?.restore();
  vi.restoreAllMocks();
});

beforeEach(() => {
  // Reset DOM
  document.body.innerHTML = '';
  
  // Reset any global state
  localStorage.clear();
  sessionStorage.clear();
});

afterEach(() => {
  // Clean up after each test
  vi.clearAllMocks();
});

export { TestUtils };