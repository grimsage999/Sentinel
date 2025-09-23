import { QueryClient } from '@tanstack/react-query';
import { errorHandlingService } from './errorHandling';

// Create a query client with default options
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Stale time: 5 minutes for health checks, 0 for analysis (always fresh)
      staleTime: 0,
      // Cache time: 10 minutes
      gcTime: 10 * 60 * 1000,
      // Retry configuration
      retry: (failureCount, error: any) => {
        const apiError = errorHandlingService.handleApiError(error);
        
        // Don't retry validation errors or non-retryable errors
        if (!errorHandlingService.shouldShowRetry(apiError)) {
          return false;
        }
        
        // Retry up to 3 times for retryable errors
        return failureCount < 3;
      },
      // Retry delay with exponential backoff
      retryDelay: (attemptIndex, error: any) => {
        const apiError = errorHandlingService.handleApiError(error);
        return errorHandlingService.getRetryDelay(apiError, attemptIndex + 1);
      },
      // Refetch on window focus for health checks only
      refetchOnWindowFocus: false,
      // Don't refetch on reconnect for analysis results
      refetchOnReconnect: false
    },
    mutations: {
      // Retry mutations for retryable errors
      retry: (failureCount, error: any) => {
        const apiError = errorHandlingService.handleApiError(error);
        return errorHandlingService.shouldShowRetry(apiError) && failureCount < 2;
      },
      retryDelay: (attemptIndex, error: any) => {
        const apiError = errorHandlingService.handleApiError(error);
        return errorHandlingService.getRetryDelay(apiError, attemptIndex + 1);
      }
    }
  }
});

// Query keys for consistent caching
export const queryKeys = {
  health: ['health'] as const,
  emailAnalysis: (content: string) => ['emailAnalysis', content] as const,
} as const;