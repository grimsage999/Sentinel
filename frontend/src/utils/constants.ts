/**
 * Constants and enums for Sentinel
 */

// Intent types
export const INTENT_TYPES = {
  CREDENTIAL_THEFT: 'credential_theft',
  WIRE_TRANSFER: 'wire_transfer', 
  MALWARE_DELIVERY: 'malware_delivery',
  RECONNAISSANCE: 'reconnaissance',
  OTHER: 'other'
} as const;

// Confidence levels
export const CONFIDENCE_LEVELS = {
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low'
} as const;

// Deception indicator types
export const DECEPTION_INDICATOR_TYPES = {
  SPOOFING: 'spoofing',
  URGENCY: 'urgency',
  AUTHORITY: 'authority',
  SUSPICIOUS_LINKS: 'suspicious_links',
  GRAMMAR: 'grammar'
} as const;

// IOC types
export const IOC_TYPES = {
  URL: 'url',
  IP: 'ip',
  DOMAIN: 'domain'
} as const;

// Severity levels
export const SEVERITY_LEVELS = {
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low'
} as const;

// API endpoints
export const API_ENDPOINTS = {
  ANALYZE: '/api/analyze',
  HEALTH: '/api/health'
} as const;

// Error codes
export const ERROR_CODES = {
  ANALYSIS_FAILED: 'ANALYSIS_FAILED',
  INVALID_INPUT: 'INVALID_INPUT',
  NETWORK_ERROR: 'NETWORK_ERROR',
  TIMEOUT: 'TIMEOUT',
  RATE_LIMITED: 'RATE_LIMITED',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE'
} as const;

// Validation constants
export const VALIDATION_LIMITS = {
  MAX_EMAIL_SIZE: 1024 * 1024, // 1MB
  MIN_EMAIL_LENGTH: 10,
  MAX_PROCESSING_TIME: 60000, // 60 seconds
  DEFAULT_CONFIDENCE_THRESHOLD: 0.5
} as const;

// UI constants
export const UI_CONSTANTS = {
  LOADING_TIMEOUT: 30000, // 30 seconds
  DEBOUNCE_DELAY: 300,
  ANIMATION_DURATION: 200
} as const;