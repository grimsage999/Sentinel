"""
Custom exceptions for Sentinel backend
"""

from typing import Any, Dict, Optional
from fastapi import HTTPException, status


class SentinelException(Exception):
    """Base exception for Sentinel"""
    
    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        details: Optional[str] = None,
        retryable: bool = False
    ):
        self.message = message
        self.code = code
        self.details = details
        self.retryable = retryable
        super().__init__(self.message)


class ValidationException(SentinelException):
    """Exception for validation errors"""
    
    def __init__(
        self,
        message: str = "Validation failed",
        field: Optional[str] = None,
        invalid_value: Any = None
    ):
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            details=f"Field: {field}, Value: {invalid_value}" if field else None,
            retryable=False
        )
        self.field = field
        self.invalid_value = invalid_value


class EmailParsingException(SentinelException):
    """Exception for email parsing errors"""
    
    def __init__(self, message: str = "Failed to parse email content", details: Optional[str] = None):
        super().__init__(
            message=message,
            code="PARSING_ERROR",
            details=details,
            retryable=False
        )


class LLMServiceException(SentinelException):
    """Exception for LLM service errors"""
    
    def __init__(
        self,
        message: str = "LLM service error",
        details: Optional[str] = None,
        retryable: bool = True
    ):
        super().__init__(
            message=message,
            code="LLM_ERROR",
            details=details,
            retryable=retryable
        )


# Specific LLM exceptions
class LLMServiceError(LLMServiceException):
    """General LLM service error"""
    pass


class LLMTimeoutError(LLMServiceException):
    """LLM request timeout error"""
    
    def __init__(self, message: str = "LLM request timed out"):
        super().__init__(
            message=message,
            details=None,
            retryable=True
        )
        self.code = "TIMEOUT"


class LLMRateLimitError(LLMServiceException):
    """LLM rate limit error"""
    
    def __init__(self, message: str = "LLM rate limit exceeded"):
        super().__init__(
            message=message,
            details=None,
            retryable=True
        )
        self.code = "RATE_LIMITED"


class LLMParsingError(LLMServiceException):
    """LLM response parsing error"""
    
    def __init__(self, message: str = "Failed to parse LLM response"):
        super().__init__(
            message=message,
            details=None,
            retryable=False
        )
        self.code = "PARSING_ERROR"


class LLMConfigurationError(LLMServiceException):
    """LLM configuration error"""
    
    def __init__(self, message: str = "LLM configuration error"):
        super().__init__(
            message=message,
            details=None,
            retryable=False
        )
        self.code = "CONFIGURATION_ERROR"


class IOCExtractionException(SentinelException):
    """Exception for IOC extraction errors"""
    
    def __init__(self, message: str = "Failed to extract IOCs", details: Optional[str] = None):
        super().__init__(
            message=message,
            code="IOC_EXTRACTION_ERROR",
            details=details,
            retryable=False
        )


class RateLimitException(SentinelException):
    """Exception for rate limiting"""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None
    ):
        super().__init__(
            message=message,
            code="RATE_LIMITED",
            details=f"Retry after {retry_after} seconds" if retry_after else None,
            retryable=True
        )
        self.retry_after = retry_after


class ServiceUnavailableException(SentinelException):
    """Exception for service unavailability"""
    
    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        service_name: Optional[str] = None
    ):
        super().__init__(
            message=message,
            code="SERVICE_UNAVAILABLE",
            details=f"Service: {service_name}" if service_name else None,
            retryable=True
        )
        self.service_name = service_name


class AnalysisTimeoutException(SentinelException):
    """Exception for analysis timeout"""
    
    def __init__(
        self,
        message: str = "Analysis timed out",
        timeout_seconds: Optional[float] = None
    ):
        super().__init__(
            message=message,
            code="TIMEOUT",
            details=f"Timeout after {timeout_seconds} seconds" if timeout_seconds else None,
            retryable=True
        )
        self.timeout_seconds = timeout_seconds


# HTTP Exception mappings
class SentinelHTTPException(HTTPException):
    """HTTP exception wrapper for Sentinel exceptions"""
    
    def __init__(self, exception: SentinelException):
        status_code = self._get_status_code(exception.code)
        super().__init__(
            status_code=status_code,
            detail={
                "code": exception.code,
                "message": exception.message,
                "details": exception.details,
                "retryable": exception.retryable
            }
        )
    
    @staticmethod
    def _get_status_code(error_code: str) -> int:
        """Map error codes to HTTP status codes"""
        mapping = {
            "VALIDATION_ERROR": status.HTTP_400_BAD_REQUEST,
            "PARSING_ERROR": status.HTTP_400_BAD_REQUEST,
            "RATE_LIMITED": status.HTTP_429_TOO_MANY_REQUESTS,
            "SERVICE_UNAVAILABLE": status.HTTP_503_SERVICE_UNAVAILABLE,
            "LLM_ERROR": status.HTTP_502_BAD_GATEWAY,
            "TIMEOUT": status.HTTP_504_GATEWAY_TIMEOUT,
            "IOC_EXTRACTION_ERROR": status.HTTP_422_UNPROCESSABLE_ENTITY,
            "INTERNAL_ERROR": status.HTTP_500_INTERNAL_SERVER_ERROR,
        }
        return mapping.get(error_code, status.HTTP_500_INTERNAL_SERVER_ERROR)