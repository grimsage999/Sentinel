import { FormValidationResult } from '../components/EmailAnalysisForm/EmailAnalysisForm.types';

export const validationUtils = {
  /**
   * Validates email content for analysis
   * @param emailContent - Raw email content to validate
   * @returns Validation result with error message if invalid
   */
  validateEmailContent: (emailContent: string): FormValidationResult => {
    // Check if content is empty
    if (!emailContent || emailContent.trim().length === 0) {
      return {
        isValid: false,
        error: 'Please enter email content to analyze'
      };
    }

    // Check minimum content length (should have some meaningful content)
    if (emailContent.trim().length < 10) {
      return {
        isValid: false,
        error: 'Email content is too short. Please provide more complete email content.'
      };
    }

    // Check maximum content length (1MB limit as per requirements)
    const maxSizeBytes = 1024 * 1024; // 1MB
    const contentSizeBytes = new Blob([emailContent]).size;
    
    if (contentSizeBytes > maxSizeBytes) {
      return {
        isValid: false,
        error: 'Email content is too large. Maximum size is 1MB.'
      };
    }

    // Basic email format validation - should contain some email-like structure
    const hasEmailIndicators = 
      emailContent.includes('@') || 
      emailContent.toLowerCase().includes('from:') ||
      emailContent.toLowerCase().includes('to:') ||
      emailContent.toLowerCase().includes('subject:');

    if (!hasEmailIndicators) {
      return {
        isValid: false,
        error: 'Content does not appear to be email format. Please include email headers or content.'
      };
    }

    return { isValid: true };
  },

  /**
   * Sanitizes email content for safe processing
   * @param emailContent - Raw email content
   * @returns Sanitized email content
   */
  sanitizeEmailContent: (emailContent: string): string => {
    // Remove any potential script tags or dangerous HTML
    return emailContent
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[SCRIPT_REMOVED]')
      .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '[IFRAME_REMOVED]')
      .trim();
  }
};