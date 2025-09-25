"""
PhishContext AI - Main FastAPI application
Provides AI-powered phishing email analysis for SOC analysts
"""

import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from .core.config import settings
from .core.exceptions import (
    ValidationException,
    LLMServiceError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMParsingError
)
from .models.response_models import ApiError, ErrorCode
from .api.routes import analysis, health

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import secure logging after basic config
from .utils.logging import get_secure_logger, SensitiveDataFilter

# Add sensitive data filter to root logger
root_logger = logging.getLogger()
if not any(isinstance(f, SensitiveDataFilter) for f in root_logger.filters):
    root_logger.addFilter(SensitiveDataFilter())

logger = get_secure_logger(__name__)

# Custom JSON encoder for datetime objects
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def custom_json_response(content: Any, status_code: int = 200) -> JSONResponse:
    """Create JSONResponse with custom datetime serialization"""
    json_content = json.dumps(content, cls=CustomJSONEncoder)
    return JSONResponse(
        content=json.loads(json_content),
        status_code=status_code
    )

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting PhishContext AI API")
    logger.info(f"Primary LLM Provider: {settings.primary_llm_provider}")
    logger.info(f"Fallback LLM Provider: {settings.fallback_llm_provider}")
    
    # Start performance monitoring
    from .utils.performance import performance_monitor
    await performance_monitor.start_background_monitoring()
    logger.info("Performance monitoring started")
    
    # Start cache background cleanup
    from .services.cache_service import analysis_cache
    await analysis_cache.start_background_cleanup()
    logger.info("Cache background cleanup started")
    
    # Start threat intelligence services
    if settings.threat_intel_enabled:
        from .services.threat_intelligence import ThreatIntelligenceHarvester, ThreatIntelligenceProcessor
        
        # Initialize harvester and processor
        app.state.threat_harvester = ThreatIntelligenceHarvester(
            db_path=settings.threat_intel_db_path,
            sources=None  # Uses default sources from harvester
        )
        app.state.threat_processor = ThreatIntelligenceProcessor(
            db_path=settings.threat_intel_db_path
        )
        
        # Start background threat intelligence harvesting
        async def threat_intel_background_task():
            """Background task for threat intelligence harvesting and processing"""
            import asyncio
            while True:
                try:
                    logger.info("Starting threat intelligence harvest cycle")
                    
                    # Harvest new threat intelligence
                    harvest_results = await app.state.threat_harvester.harvest_all_sources()
                    logger.info(f"Harvest completed: {harvest_results['entries_new']} new entries")
                    
                    # Process unprocessed entries to extract IOCs
                    if harvest_results['entries_new'] > 0:
                        process_results = await app.state.threat_processor.process_all_unprocessed()
                        logger.info(f"IOC processing completed: {process_results['iocs_extracted']} IOCs extracted")
                    
                    # Cleanup old entries
                    await app.state.threat_harvester.cleanup_old_entries(settings.threat_intel_cleanup_days)
                    
                    # Wait for next harvest cycle
                    await asyncio.sleep(settings.threat_intel_harvest_interval_hours * 3600)
                    
                except Exception as e:
                    logger.error(f"Error in threat intelligence background task: {str(e)}")
                    # Wait a bit before retrying on error
                    await asyncio.sleep(300)  # 5 minutes
                    
        # Start the background task
        import asyncio
        app.state.threat_intel_task = asyncio.create_task(threat_intel_background_task())
        logger.info(f"Threat intelligence background task started (harvest interval: {settings.threat_intel_harvest_interval_hours} hours)")
        
    # VirusTotal background submission service (disabled for now)
    # from .services.background_vt_service import background_vt_service
    # await background_vt_service.start()
    # logger.info("VirusTotal background submission service started")
    
    # Log security configuration
    logger.info(
        "Security features enabled",
        content_sanitization=settings.enable_content_sanitization,
        security_headers=settings.enable_security_headers,
        max_concurrent_requests=settings.max_concurrent_requests,
        max_email_size_mb=settings.max_email_size_mb
    )
    
    yield
    
    # Shutdown
    logger.info("Shutting down PhishContext AI API")
    
    # Stop performance monitoring
    await performance_monitor.stop_background_monitoring()
    
    # Stop threat intelligence background task
    if settings.threat_intel_enabled and hasattr(app.state, 'threat_intel_task'):
        app.state.threat_intel_task.cancel()
        try:
            await app.state.threat_intel_task
        except asyncio.CancelledError:
            pass
        
        # Close harvester resources
        if hasattr(app.state, 'threat_harvester'):
            await app.state.threat_harvester.close()
            
        logger.info("Threat intelligence background task stopped")
    
    # Stop VirusTotal background service (disabled for now)
    # await background_vt_service.stop()
    # logger.info("VirusTotal background submission service stopped")
    logger.info("Performance monitoring stopped")
    
    # Stop cache background cleanup
    await analysis_cache.stop_background_cleanup()
    logger.info("Cache background cleanup stopped")
    
    # Final memory cleanup
    from .core.security import clear_sensitive_memory
    clear_sensitive_memory()
    logger.info("Final memory cleanup completed")

# Create FastAPI application
app = FastAPI(
    title="PhishContext AI API",
    description="AI-powered phishing email analysis for SOC analysts",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add security middleware
from .middleware.security import (
    SecurityMiddleware,
    ContentValidationMiddleware,
    SecurityHeadersMiddleware
)

# Add security middleware stack (order matters - first added is outermost)
app.add_middleware(SecurityHeadersMiddleware)
# app.add_middleware(ContentValidationMiddleware)  # Temporarily disabled for testing
# app.add_middleware(SecurityMiddleware, max_request_size=settings.max_email_size_mb * 1024 * 1024)  # Temporarily disabled

# Add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Add trusted host middleware for security
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure based on deployment needs
)

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    return response

# Add request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log request details for monitoring"""
    start_time = time.time()
    
    # Generate request ID for tracking
    request_id = f"req_{int(start_time * 1000000)}"
    request.state.request_id = request_id
    
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Log request start (without sensitive data)
    logger.info(
        "Request started",
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        client_ip=client_ip,
        user_agent=request.headers.get("User-Agent", "unknown")
    )
    
    response = await call_next(request)
    
    # Log request completion
    process_time = time.time() - start_time
    logger.info(
        "Request completed",
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        processing_time_seconds=process_time
    )
    
    return response

# Global exception handlers
@app.exception_handler(ValidationException)
async def validation_exception_handler(request: Request, exc: ValidationException):
    """Handle validation errors"""
    request_id = getattr(request.state, 'request_id', 'unknown')
    client_ip = request.client.host if request.client else "unknown"
    
    logger.log_error_with_context(
        error=exc,
        request_id=request_id,
        operation="input validation",
        client_ip=client_ip
    )
    
    error = ApiError(
        code=ErrorCode.VALIDATION_ERROR,
        message="Input validation failed",
        details=str(exc),
        retryable=False
    )
    
    return custom_json_response(
        content={"error": error.model_dump(), "success": False},
        status_code=400
    )

@app.exception_handler(LLMTimeoutError)
async def llm_timeout_handler(request: Request, exc: LLMTimeoutError):
    """Handle LLM timeout errors"""
    logger.error(f"LLM timeout: {str(exc)}")
    
    error = ApiError(
        code=ErrorCode.TIMEOUT,
        message="Analysis request timed out",
        details="The analysis took too long to complete. Please try again.",
        retryable=True
    )
    
    return custom_json_response(
        content={"error": error.model_dump(), "success": False},
        status_code=504
    )

@app.exception_handler(LLMRateLimitError)
async def llm_rate_limit_handler(request: Request, exc: LLMRateLimitError):
    """Handle LLM rate limit errors"""
    logger.warning(f"LLM rate limit: {str(exc)}")
    
    error = ApiError(
        code=ErrorCode.RATE_LIMITED,
        message="Service temporarily unavailable due to high demand",
        details="Please wait a moment and try again.",
        retryable=True
    )
    
    return custom_json_response(
        content={"error": error.model_dump(), "success": False},
        status_code=429
    )

@app.exception_handler(LLMServiceError)
async def llm_service_error_handler(request: Request, exc: LLMServiceError):
    """Handle LLM service errors"""
    logger.error(f"LLM service error: {str(exc)}")
    
    error = ApiError(
        code=ErrorCode.LLM_ERROR,
        message="AI analysis service temporarily unavailable",
        details="Please try again in a few moments.",
        retryable=True
    )
    
    return custom_json_response(
        content={"error": error.model_dump(), "success": False},
        status_code=503
    )

@app.exception_handler(LLMParsingError)
async def llm_parsing_error_handler(request: Request, exc: LLMParsingError):
    """Handle LLM response parsing errors"""
    logger.error(f"LLM parsing error: {str(exc)}")
    
    error = ApiError(
        code=ErrorCode.PARSING_ERROR,
        message="Failed to process analysis results",
        details="The analysis completed but results could not be processed. Please try again.",
        retryable=True
    )
    
    return custom_json_response(
        content={"error": error.model_dump(), "success": False},
        status_code=500
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    logger.warning(f"HTTP exception: {exc.status_code} - {exc.detail}")
    
    # Map HTTP status codes to error codes
    error_code_map = {
        400: ErrorCode.INVALID_INPUT,
        404: ErrorCode.INVALID_INPUT,
        413: ErrorCode.INVALID_INPUT,
        422: ErrorCode.VALIDATION_ERROR,
        429: ErrorCode.RATE_LIMITED,
        500: ErrorCode.INTERNAL_ERROR,
        503: ErrorCode.SERVICE_UNAVAILABLE
    }
    
    # Handle case where exc.detail might be a dict
    detail_message = exc.detail
    if isinstance(detail_message, dict):
        detail_message = str(detail_message)
    
    error = ApiError(
        code=error_code_map.get(exc.status_code, ErrorCode.INTERNAL_ERROR),
        message=detail_message,
        retryable=exc.status_code in [429, 500, 502, 503, 504]
    )
    
    return custom_json_response(
        content={"error": error.model_dump(), "success": False},
        status_code=exc.status_code
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors"""
    request_id = getattr(request.state, 'request_id', 'unknown')
    client_ip = request.client.host if request.client else "unknown"
    
    logger.log_error_with_context(
        error=exc,
        request_id=request_id,
        operation="request processing",
        client_ip=client_ip
    )
    
    error = ApiError(
        code=ErrorCode.INTERNAL_ERROR,
        message="An unexpected error occurred",
        details="Please try again later.",
        retryable=True
    )
    
    return custom_json_response(
        content={"error": error.model_dump(), "success": False},
        status_code=500
    )

# Include API routes
app.include_router(analysis.router, prefix="/api", tags=["analysis"])
app.include_router(health.router, prefix="/api", tags=["health"])

# Include monitoring routes
from .api.routes import monitoring
app.include_router(monitoring.router, prefix="/api/monitoring", tags=["monitoring"])

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with basic API information"""
    return {
        "name": "PhishContext AI API",
        "version": "1.0.0",
        "description": "AI-powered phishing email analysis for SOC analysts",
        "docs": "/docs",
        "health": "/api/health"
    }