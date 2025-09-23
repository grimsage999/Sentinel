"""
Response models and error handling for Sentinel backend
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Generic, List, Optional, TypeVar, Union
from pydantic import BaseModel, Field
from pydantic import BaseModel

T = TypeVar('T')


class ServiceStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"


class SystemStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ErrorCode(str, Enum):
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    INVALID_INPUT = "INVALID_INPUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    LLM_ERROR = "LLM_ERROR"
    PARSING_ERROR = "PARSING_ERROR"


class ApiError(BaseModel):
    """Standard API error response"""
    code: ErrorCode
    message: str = Field(..., min_length=1, max_length=500)
    details: Optional[str] = Field(default=None, max_length=1000)
    retryable: bool = Field(default=False)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ApiResponse(BaseModel, Generic[T]):
    """Generic API response wrapper"""
    data: Optional[T] = Field(default=None)
    error: Optional[ApiError] = Field(default=None)
    success: bool = Field(...)
    meta: Optional[Dict[str, Any]] = Field(default=None)
    
    @classmethod
    def success_response(cls, data: T, meta: Optional[Dict[str, Any]] = None) -> 'ApiResponse[T]':
        """Create a successful response"""
        return cls(data=data, success=True, meta=meta)
    
    @classmethod
    def error_response(cls, error: ApiError) -> 'ApiResponse[T]':
        """Create an error response"""
        return cls(error=error, success=False)


class HealthCheckResponse(BaseModel):
    """Health check endpoint response"""
    status: SystemStatus
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    services: Dict[str, ServiceStatus] = Field(default_factory=dict)
    version: Optional[str] = Field(default=None)
    uptime: Optional[float] = Field(default=None)  # seconds
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ValidationErrorDetail(BaseModel):
    """Detailed validation error information"""
    field: str
    message: str
    invalid_value: Optional[Any] = Field(default=None)


class ValidationErrorResponse(BaseModel):
    """Response for validation errors"""
    code: ErrorCode = Field(default=ErrorCode.VALIDATION_ERROR)
    message: str = Field(default="Validation failed")
    errors: List[ValidationErrorDetail] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ProcessingMetrics(BaseModel):
    """Metrics for analysis processing"""
    start_time: datetime
    end_time: Optional[datetime] = Field(default=None)
    processing_time: Optional[float] = Field(default=None)  # seconds
    llm_response_time: Optional[float] = Field(default=None)  # seconds
    ioc_extraction_time: Optional[float] = Field(default=None)  # seconds
    email_parsing_time: Optional[float] = Field(default=None)  # seconds
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }