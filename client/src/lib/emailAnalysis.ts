import { apiService } from './api';
import { validationUtils } from '../utils/validation';
import { EmailAnalysisRequest, AnalysisResult } from '../types/analysis.types';
import { ApiError } from '../types/api.types';

export const emailAnalysisService = {
  /**
   * Analyzes email content with validation and error handling
   * @param emailContent - Raw email content to analyze
   * @param options - Optional analysis configuration
   * @returns Promise with analysis result
   */
  analyzeEmail: async (
    emailContent: string, 
    options?: { includeIOCs?: boolean; confidenceThreshold?: number }
  ): Promise<AnalysisResult> => {
    // Validate email content
    const validation = validationUtils.validateEmailContent(emailContent);
    if (!validation.isValid) {
      const error: ApiError = {
        code: 'VALIDATION_ERROR',
        message: validation.error || 'Invalid email content',
        retryable: false
      };
      throw error;
    }

    // Sanitize email content
    const sanitizedContent = validationUtils.sanitizeEmailContent(emailContent);

    // Prepare request
    const request: EmailAnalysisRequest = {
      emailContent: sanitizedContent,
      analysisOptions: {
        includeIOCs: options?.includeIOCs ?? true,
        confidenceThreshold: options?.confidenceThreshold ?? 0.5
      }
    };

    try {
      const response = await apiService.analyzeEmail(request);
      
      if (!response.success || !response.data) {
        throw response.error || {
          code: 'ANALYSIS_FAILED',
          message: 'Analysis failed without specific error',
          retryable: true
        };
      }

      return response.data;
    } catch (error) {
      // Re-throw API errors as-is
      throw error;
    }
  },

  /**
   * Checks if the analysis service is available
   * @returns Promise with service availability status
   */
  checkServiceHealth: async (): Promise<boolean> => {
    try {
      const health = await apiService.healthCheck();
      // Check if at least one LLM provider is available
      const hasLLM = health.services.openai === 'available' || 
                    health.services.anthropic === 'available' || 
                    health.services.google === 'available';
      return health.status === 'healthy' && hasLLM;
    } catch (error) {
      console.error('Health check failed:', error);
      return false;
    }
  }
};