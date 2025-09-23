"""
API dependencies for PhishContext AI backend
"""

import logging
from typing import Dict, Any, Optional
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from ..core.config import settings
from ..services.email_parser import EmailParser
from ..services.ioc_extractor import IOCExtractor
from ..services.llm_analyzer import LLMAnalyzer
from ..core.exceptions import ValidationException, LLMConfigurationError

logger = logging.getLogger(__name__)

# Security scheme for potential future authentication
security = HTTPBearer(auto_error=False)

# Service instances (singleton pattern)
_email_parser: Optional[EmailParser] = None
_ioc_extractor: Optional[IOCExtractor] = None
_llm_analyzer: Optional[LLMAnalyzer] = None


def get_email_parser() -> EmailParser:
    """
    Dependency to provide EmailParser service
    
    Returns:
        EmailParser instance
    """
    global _email_parser
    if _email_parser is None:
        _email_parser = EmailParser()
        logger.info("EmailParser service initialized")
    return _email_parser


def get_ioc_extractor() -> IOCExtractor:
    """
    Dependency to provide IOCExtractor service
    
    Returns:
        IOCExtractor instance
    """
    global _ioc_extractor
    if _ioc_extractor is None:
        _ioc_extractor = IOCExtractor()
        logger.info("IOCExtractor service initialized")
    return _ioc_extractor


def get_llm_analyzer() -> LLMAnalyzer:
    """
    Dependency to provide LLMAnalyzer service
    
    Returns:
        LLMAnalyzer instance
        
    Raises:
        HTTPException: If LLM service cannot be initialized
    """
    global _llm_analyzer
    if _llm_analyzer is None:
        try:
            _llm_analyzer = LLMAnalyzer()
            logger.info("LLMAnalyzer service initialized")
        except LLMConfigurationError as e:
            logger.error(f"Failed to initialize LLM analyzer: {str(e)}")
            raise HTTPException(
                status_code=503,
                detail="AI analysis service is not properly configured"
            )
        except Exception as e:
            logger.error(f"Unexpected error initializing LLM analyzer: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Failed to initialize AI analysis service"
            )
    return _llm_analyzer


def get_analysis_services() -> Dict[str, Any]:
    """
    Dependency to provide all analysis services
    
    Returns:
        Dictionary containing all analysis services
    """
    return {
        "email_parser": get_email_parser(),
        "ioc_extractor": get_ioc_extractor(),
        "llm_analyzer": get_llm_analyzer()
    }


def validate_request_size(request: Request) -> Request:
    """
    Dependency to validate request content size
    
    Args:
        request: FastAPI request object
        
    Returns:
        Request object if valid
        
    Raises:
        HTTPException: If request is too large
    """
    content_length = request.headers.get("content-length")
    
    if content_length:
        content_length = int(content_length)
        max_size = settings.max_email_size_mb * 1024 * 1024
        
        if content_length > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"Request too large. Maximum size: {settings.max_email_size_mb}MB"
            )
    
    return request


def get_client_ip(request: Request) -> str:
    """
    Dependency to extract client IP address for rate limiting
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address
    """
    # Check for forwarded headers (when behind proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to direct client IP
    return request.client.host if request.client else "unknown"


def check_service_health() -> Dict[str, str]:
    """
    Dependency to check basic service health
    
    Returns:
        Dictionary with service status information
        
    Raises:
        HTTPException: If critical services are unavailable
    """
    status = {}
    
    try:
        # Check if at least one LLM provider is configured
        has_openai = bool(settings.openai_api_key)
        has_anthropic = bool(settings.anthropic_api_key)
        has_google = bool(settings.google_api_key)
        
        if not any([has_openai, has_anthropic, has_google]):
            raise HTTPException(
                status_code=503,
                detail="No AI providers configured. Service unavailable."
            )
        
        status["llm_providers"] = "available"
        status["email_parser"] = "available"
        status["ioc_extractor"] = "available"
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail="Service health check failed"
        )


# Optional authentication dependency (for future use)
def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict[str, Any]]:
    """
    Optional authentication dependency
    
    Currently returns None (no authentication required)
    Can be extended in the future to support API keys or JWT tokens
    
    Args:
        credentials: HTTP Bearer token credentials
        
    Returns:
        User information or None
    """
    # For now, no authentication is required
    # This can be extended later to validate API keys or JWT tokens
    return None


def log_request_info(request: Request) -> None:
    """
    Dependency to log request information for monitoring
    
    Args:
        request: FastAPI request object
    """
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "unknown")
    
    logger.info(
        f"API request: {request.method} {request.url.path} "
        f"from {client_ip} - User-Agent: {user_agent}"
    )


# Dependency combinations for common use cases
def get_analysis_dependencies() -> Dict[str, Any]:
    """
    Combined dependency for analysis endpoints
    
    Returns:
        Dictionary with all required services and validation
    """
    return {
        "services": get_analysis_services(),
        "health": check_service_health()
    }