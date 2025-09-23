import axios, { AxiosResponse } from 'axios';
import { AnalyzeEmailRequest, AnalyzeEmailResponse, HealthCheckResponse } from '../types/api.types';

// Create axios instance with default configuration
const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
  timeout: 60000, // 60 seconds timeout for analysis
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for logging
apiClient.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error('API Response Error:', error);
    
    // Transform axios errors to our API error format
    if (error.response) {
      // Server responded with error status
      const apiError = {
        code: error.response.data?.error?.code || 'API_ERROR',
        message: error.response.data?.error?.message || 'An error occurred',
        details: error.response.data?.error?.details || error.message,
        retryable: error.response.status >= 500 || error.response.status === 429
      };
      error.apiError = apiError;
    } else if (error.request) {
      // Network error
      error.apiError = {
        code: 'NETWORK_ERROR',
        message: 'Unable to connect to the server',
        details: 'Please check your internet connection and try again',
        retryable: true
      };
    } else {
      // Other error
      error.apiError = {
        code: 'UNKNOWN_ERROR',
        message: 'An unexpected error occurred',
        details: error.message,
        retryable: false
      };
    }
    
    return Promise.reject(error);
  }
);

export const apiService = {
  /**
   * Analyzes email content using the backend API
   * @param request - Email analysis request
   * @returns Promise with analysis result
   */
  analyzeEmail: async (request: AnalyzeEmailRequest): Promise<AnalyzeEmailResponse> => {
    try {
      const response: AxiosResponse<AnalyzeEmailResponse> = await apiClient.post('/api/analyze', request);
      return response.data;
    } catch (error: any) {
      throw error.apiError || error;
    }
  },

  /**
   * Checks the health status of the API
   * @returns Promise with health check result
   */
  healthCheck: async (): Promise<HealthCheckResponse> => {
    try {
      const response: AxiosResponse<HealthCheckResponse> = await apiClient.get('/api/health');
      return response.data;
    } catch (error: any) {
      throw error.apiError || error;
    }
  }
};