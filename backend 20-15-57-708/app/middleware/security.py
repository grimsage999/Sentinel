"""
Security middleware for PhishContext AI
Handles request validation, size limits, and concurrent request management
"""

import asyncio
import time
from typing import Callable, Dict, Any
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..core.config import settings
from ..core.security import (
    sanitize_email_content,
    validate_content_size,
    detect_malicious_patterns,
    generate_request_id,
    security_metrics,
    clear_sensitive_memory
)
from ..utils.performance import performance_monitor, track_request_performance
from ..utils.logging import get_secure_logger
from ..models.response_models import ApiError, ErrorCode

logger = get_secure_logger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Middleware for security validation and request management"""
    
    def __init__(self, app, max_request_size: int = 1024 * 1024):  # 1MB default
        super().__init__(app)
        self.max_request_size = max_request_size
        self.request_semaphore = asyncio.Semaphore(settings.max_concurrent_requests)
        self.last_cleanup = time.time()
        self.cleanup_interval = settings.memory_cleanup_interval_minutes * 60  # Convert to seconds
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through security middleware"""
        
        # Generate request ID for tracking
        request_id = generate_request_id()
        request.state.request_id = request_id
        
        # Get client IP for logging
        client_ip = self._get_client_ip(request)
        request.state.client_ip = client_ip
        
        try:
            # Check system capacity
            can_process, capacity_message = performance_monitor.check_capacity()
            if not can_process:
                logger.log_security_event(
                    event_type="capacity_limit_reached",
                    client_ip=client_ip,
                    details=capacity_message
                )
                security_metrics.record_blocked_request()
                
                error = ApiError(
                    code=ErrorCode.SERVICE_UNAVAILABLE,
                    message="Service temporarily unavailable",
                    details="System is at capacity. Please try again in a moment.",
                    retryable=True
                )
                
                return JSONResponse(
                    content={"error": error.model_dump(), "success": False},
                    status_code=503
                )
            
            # Acquire semaphore for concurrent request limiting
            async with self.request_semaphore:
                # Validate request size before processing
                if hasattr(request, 'body'):
                    try:
                        body = await request.body()
                        if len(body) > self.max_request_size:
                            logger.log_security_event(
                                event_type="request_size_exceeded",
                                client_ip=client_ip,
                                details=f"Request size {len(body)} exceeds limit {self.max_request_size}",
                                request_size=len(body)
                            )
                            security_metrics.record_blocked_request()
                            
                            error = ApiError(
                                code=ErrorCode.INVALID_INPUT,
                                message="Request too large",
                                details=f"Request size exceeds maximum of {self.max_request_size // (1024*1024)}MB",
                                retryable=False
                            )
                            
                            return JSONResponse(
                                content={"error": error.model_dump(), "success": False},
                                status_code=413
                            )
                    except Exception as e:
                        logger.error("Error reading request body", error=e, request_id=request_id)
                
                # Track request performance
                async with track_request_performance(
                    request_id=request_id,
                    endpoint=request.url.path,
                    method=request.method,
                    email_size=0  # Will be updated later if email content is processed
                ):
                    # Process request
                    response = await call_next(request)
                    
                    # Perform periodic cleanup
                    await self._periodic_cleanup()
                    
                    return response
        
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.error(
                "Unexpected error in security middleware",
                error=e,
                request_id=request_id,
                client_ip=client_ip
            )
            
            error = ApiError(
                code=ErrorCode.INTERNAL_ERROR,
                message="An unexpected error occurred",
                details="Please try again later.",
                retryable=True
            )
            
            return JSONResponse(
                content={"error": error.model_dump(), "success": False},
                status_code=500
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request"""
        # Check for forwarded headers first (for reverse proxy setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fall back to direct client IP
        if request.client:
            return request.client.host
        
        return "unknown"
    
    async def _periodic_cleanup(self):
        """Perform periodic memory cleanup"""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            try:
                clear_sensitive_memory()
                self.last_cleanup = current_time
                logger.debug("Periodic security cleanup completed")
            except Exception as e:
                logger.error("Error during periodic cleanup", error=e)


class ContentValidationMiddleware(BaseHTTPMiddleware):
    """Middleware for validating and sanitizing request content"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Validate and sanitize request content"""
        
        # Only process POST requests that might contain email content
        if request.method == "POST" and request.url.path.endswith("/analyze"):
            try:
                # Get request body
                body = await request.body()
                
                if body:
                    # Parse JSON to check for email content
                    import json
                    try:
                        data = json.loads(body.decode('utf-8'))
                        email_content = data.get('emailContent', data.get('email_content', ''))
                        
                        if email_content:
                            # Validate content size
                            is_valid, error_msg = validate_content_size(
                                email_content, 
                                settings.max_email_size_mb
                            )
                            
                            if not is_valid:
                                logger.log_security_event(
                                    event_type="content_size_validation_failed",
                                    client_ip=getattr(request.state, 'client_ip', 'unknown'),
                                    details=error_msg,
                                    content_size=len(email_content)
                                )
                                
                                error = ApiError(
                                    code=ErrorCode.INVALID_INPUT,
                                    message="Email content validation failed",
                                    details=error_msg,
                                    retryable=False
                                )
                                
                                return JSONResponse(
                                    content={"error": error.model_dump(), "success": False},
                                    status_code=400
                                )
                            
                            # Detect malicious patterns
                            if settings.enable_content_sanitization:
                                threats = detect_malicious_patterns(email_content)
                                
                                if threats:
                                    # Log detected threats
                                    high_severity_threats = [t for t in threats if t['severity'] == 'high']
                                    
                                    if high_severity_threats:
                                        logger.log_security_event(
                                            event_type="high_severity_threats_detected",
                                            client_ip=getattr(request.state, 'client_ip', 'unknown'),
                                            details=f"Detected {len(high_severity_threats)} high-severity threats",
                                            threat_count=len(threats),
                                            high_severity_count=len(high_severity_threats)
                                        )
                                        
                                        # Record security metrics
                                        for threat in threats:
                                            security_metrics.record_threat(threat['type'])
                                    
                                    # Sanitize content
                                    sanitized_content = sanitize_email_content(email_content)
                                    if sanitized_content != email_content:
                                        security_metrics.record_sanitization()
                                        data['email_content'] = sanitized_content
                                        
                                        # Update request body with sanitized content
                                        new_body = json.dumps(data).encode('utf-8')
                                        
                                        # Create a new request with sanitized body
                                        async def receive():
                                            return {"type": "http.request", "body": new_body}
                                        
                                        request._receive = receive
                            
                            # Update performance tracking with email size
                            if hasattr(request.state, 'request_id'):
                                performance_monitor.update_request(
                                    request.state.request_id,
                                    email_size=len(email_content)
                                )
                    
                    except json.JSONDecodeError:
                        # Not JSON content, skip validation
                        pass
                    except Exception as e:
                        logger.error(
                            "Error during content validation",
                            error=e,
                            request_id=getattr(request.state, 'request_id', 'unknown')
                        )
            
            except Exception as e:
                logger.error(
                    "Error in content validation middleware",
                    error=e,
                    request_id=getattr(request.state, 'request_id', 'unknown')
                )
        
        # Continue with request processing
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware for adding security headers to responses"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to response"""
        
        response = await call_next(request)
        
        if settings.enable_security_headers:
            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "connect-src 'self' https:; "
                "font-src 'self'; "
                "object-src 'none'; "
                "media-src 'self'; "
                "frame-src 'none';"
            )
            
            # Add cache control for sensitive endpoints
            if request.url.path.startswith("/api/analyze"):
                response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
        
        return response


def get_security_status() -> Dict[str, Any]:
    """Get current security status and metrics"""
    return {
        "security_features": {
            "content_sanitization": settings.enable_content_sanitization,
            "security_headers": settings.enable_security_headers,
            "security_logging": settings.enable_security_logging,
            "performance_monitoring": settings.enable_performance_monitoring
        },
        "limits": {
            "max_email_size_mb": settings.max_email_size_mb,
            "max_concurrent_requests": settings.max_concurrent_requests,
            "rate_limit_per_minute": settings.rate_limit_requests_per_minute,
            "request_timeout_seconds": settings.request_timeout_seconds
        },
        "metrics": security_metrics.get_metrics(),
        "performance": performance_monitor.get_current_metrics()
    }