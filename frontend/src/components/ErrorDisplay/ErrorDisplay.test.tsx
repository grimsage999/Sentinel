import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { vi } from 'vitest';
import { ErrorDisplay } from './ErrorDisplay';
import { ApiError } from '../../types/api.types';

describe('ErrorDisplay', () => {
  const mockError: ApiError = {
    code: 'NETWORK_ERROR',
    message: 'Connection failed',
    details: 'Please check your internet connection',
    retryable: true
  };

  it('renders error message correctly', () => {
    render(<ErrorDisplay error={mockError} />);

    expect(screen.getByText('Connection Problem')).toBeInTheDocument();
    expect(screen.getByText(/Connection failed. Please check your internet connection/)).toBeInTheDocument();
  });

  it('shows retry button for retryable errors', () => {
    const onRetry = vi.fn();
    
    render(<ErrorDisplay error={mockError} onRetry={onRetry} />);

    const retryButton = screen.getByText('Try Again');
    expect(retryButton).toBeInTheDocument();

    fireEvent.click(retryButton);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('hides retry button when showRetry is false', () => {
    render(<ErrorDisplay error={mockError} showRetry={false} />);

    expect(screen.queryByText('Try Again')).not.toBeInTheDocument();
  });

  it('shows dismiss button when showDismiss is true', () => {
    const onDismiss = vi.fn();
    
    render(<ErrorDisplay error={mockError} onDismiss={onDismiss} showDismiss={true} />);

    const dismissButton = screen.getByText('Dismiss');
    expect(dismissButton).toBeInTheDocument();

    fireEvent.click(dismissButton);
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it('renders different error types with appropriate styling', () => {
    const timeoutError: ApiError = {
      code: 'TIMEOUT',
      message: 'Request timed out',
      retryable: true
    };

    render(<ErrorDisplay error={timeoutError} />);

    expect(screen.getByText('Request Timeout')).toBeInTheDocument();
    expect(screen.getByText(/Analysis is taking longer than expected/)).toBeInTheDocument();
  });

  it('renders rate limit error correctly', () => {
    const rateLimitError: ApiError = {
      code: 'RATE_LIMITED',
      message: 'Too many requests',
      retryable: true
    };

    render(<ErrorDisplay error={rateLimitError} />);

    expect(screen.getByText('Too Many Requests')).toBeInTheDocument();
    expect(screen.getByText(/Too many requests. Please wait a moment/)).toBeInTheDocument();
  });

  it('renders validation error correctly', () => {
    const validationError: ApiError = {
      code: 'VALIDATION_ERROR',
      message: 'Invalid input',
      retryable: false
    };

    render(<ErrorDisplay error={validationError} />);

    expect(screen.getByText('Invalid Input')).toBeInTheDocument();
    expect(screen.queryByText('Try Again')).not.toBeInTheDocument(); // Non-retryable
  });

  it('applies custom className', () => {
    const { container } = render(
      <ErrorDisplay error={mockError} className="custom-class" />
    );

    expect(container.firstChild).toHaveClass('custom-class');
  });

  it('shows error details when different from message', () => {
    const errorWithDetails: ApiError = {
      code: 'NETWORK_ERROR',
      message: 'Connection failed',
      details: 'Specific technical details here',
      retryable: true
    };

    render(<ErrorDisplay error={errorWithDetails} />);

    expect(screen.getByText('Connection failed. Please check your internet connection and try again.')).toBeInTheDocument();
    expect(screen.getByText('Specific technical details here')).toBeInTheDocument();
  });

  it('does not show duplicate details when same as user message', () => {
    const userMessage = 'Connection failed. Please check your internet connection and try again.';
    const errorWithSameDetails: ApiError = {
      code: 'NETWORK_ERROR',
      message: 'Connection failed',
      details: userMessage,
      retryable: true
    };

    render(<ErrorDisplay error={errorWithSameDetails} />);

    // Should only appear once
    const messages = screen.getAllByText(userMessage);
    expect(messages).toHaveLength(1);
  });
});