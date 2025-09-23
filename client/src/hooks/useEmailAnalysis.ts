import { useMutation, useQuery } from '@tanstack/react-query';
import { emailAnalysisService } from '../services/emailAnalysis';
import { queryKeys } from '../services/queryClient';
import { errorHandlingService } from '../services/errorHandling';
import { AnalysisResult } from '../types/analysis.types';
import { ApiError } from '../types/api.types';

export interface UseEmailAnalysisOptions {
  includeIOCs?: boolean;
  confidenceThreshold?: number;
  onSuccess?: (data: AnalysisResult) => void;
  onError?: (error: ApiError) => void;
}

/**
 * Hook for email analysis mutation with React Query
 */
export const useEmailAnalysis = (options: UseEmailAnalysisOptions = {}) => {
  const {
    includeIOCs = true,
    confidenceThreshold = 0.5,
    onSuccess,
    onError
  } = options;

  return useMutation({
    mutationFn: async (emailContent: string) => {
      return emailAnalysisService.analyzeEmail(emailContent, {
        includeIOCs,
        confidenceThreshold
      });
    },
    onSuccess: (data) => {
      onSuccess?.(data);
    },
    onError: (error: any) => {
      const apiError = errorHandlingService.handleApiError(error);
      onError?.(apiError);
    }
  });
};

/**
 * Hook for checking service health
 */
export const useServiceHealth = (options: { enabled?: boolean } = {}) => {
  const { enabled = true } = options;

  return useQuery({
    queryKey: queryKeys.health,
    queryFn: () => emailAnalysisService.checkServiceHealth(),
    enabled,
    staleTime: 5 * 60 * 1000, // 5 minutes
    refetchInterval: 5 * 60 * 1000, // Refetch every 5 minutes
    refetchOnWindowFocus: true,
    retry: (failureCount) => {
      // Always retry health checks up to 3 times
      return failureCount < 3;
    },
    retryDelay: (attemptIndex) => {
      // Simple exponential backoff for health checks
      return Math.min(1000 * Math.pow(2, attemptIndex), 10000);
    }
  });
};

/**
 * Hook for managing analysis state with caching
 */
export const useAnalysisCache = () => {
  return {
    /**
     * Get cached analysis result for specific email content
     */
    getCachedAnalysis: (_emailContent: string): AnalysisResult | undefined => {
      // Note: We don't actually cache analysis results for security reasons
      // This is a placeholder for potential future caching of non-sensitive metadata
      return undefined;
    },

    /**
     * Clear all cached analysis data
     */
    clearAnalysisCache: () => {
      // Clear any cached analysis data
      // Currently no-op since we don't cache sensitive analysis results
    }
  };
};

/**
 * Hook for retry functionality
 */
export const useRetryableAction = () => {
  return {
    /**
     * Determines if an action should be retryable based on error
     */
    shouldRetry: (error: ApiError): boolean => {
      return errorHandlingService.shouldShowRetry(error);
    },

    /**
     * Gets user-friendly error message
     */
    getErrorMessage: (error: ApiError): string => {
      return errorHandlingService.getUserFriendlyMessage(error);
    },

    /**
     * Gets recommended retry delay
     */
    getRetryDelay: (error: ApiError, attemptNumber: number = 1): number => {
      return errorHandlingService.getRetryDelay(error, attemptNumber);
    }
  };
};