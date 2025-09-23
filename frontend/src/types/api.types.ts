/**
 * API-related types for Sentinel
 */

import { AnalysisResult, EmailAnalysisRequest } from './analysis.types';

export interface ApiResponse<T> {
  data?: T;
  error?: ApiError;
  success: boolean;
}

export interface ApiError {
  code: string;
  message: string;
  details?: string;
  retryable?: boolean;
}

export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  services: {
    openai: 'available' | 'unavailable';
    anthropic: 'available' | 'unavailable';
    google: 'available' | 'unavailable';
    configuration: 'available' | 'unavailable';
    system_resources: 'available' | 'unavailable';
  };
  version: string;
  uptime: number;
}

// API request/response types
export type AnalyzeEmailRequest = EmailAnalysisRequest;
export type AnalyzeEmailResponse = ApiResponse<AnalysisResult>;
export type HealthCheckRequest = void;