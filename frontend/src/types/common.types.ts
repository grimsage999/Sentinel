/**
 * Common types and utilities for Sentinel
 */

// Loading states
export interface LoadingState {
  isLoading: boolean;
  error?: string | null;
}

// Form states
export interface FormState<T> extends LoadingState {
  data: T;
  isDirty: boolean;
  isValid: boolean;
}

// Generic response wrapper
export interface ResponseWrapper<T> {
  data: T;
  meta?: {
    timestamp: string;
    requestId?: string;
  };
}

// Error boundary types
export interface ErrorInfo {
  componentStack: string;
  errorBoundary?: string;
}

// Component props base types
export interface BaseComponentProps {
  className?: string;
  testId?: string;
}

// Event handler types
export type ClickHandler = (event: React.MouseEvent<HTMLElement>) => void;
export type ChangeHandler = (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => void;
export type SubmitHandler = (event: React.FormEvent<HTMLFormElement>) => void;