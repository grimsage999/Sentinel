"""
Analysis API routes for phishing email analysis
"""

import logging
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...core.config import settings
from ...models.analysis_models import EmailAnalysisRequest, AnalysisResult
from ...models.response_models import ApiResponse, ApiError, ErrorCode
from ...core.exceptions import ValidationException, LLMServiceError
from ...api.dependencies import get_analysis_services
from ...utils.performance import performance_monitor, track_request_performance

logger = logging.getLogger(__name__)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# Services will be initialized via dependencies


@router.post("/analyze", response_model=ApiResponse[AnalysisResult])
@limiter.limit(f"{settings.rate_limit_requests_per_minute}/minute")
async def analyze_email(
    request: Request,
    analysis_request: EmailAnalysisRequest,
    services: Dict[str, Any] = Depends(get_analysis_services)
) -> ApiResponse[AnalysisResult]:
    """
    Analyze phishing email content using AI
    
    This endpoint accepts raw email content and returns comprehensive analysis including:
    - Intent classification (credential theft, wire transfer fraud, etc.)
    - Deception indicators and social engineering tactics
    - Risk score with confidence level
    - Extracted IOCs (URLs, IPs, domains) with VirusTotal links
    
    **Rate Limit:** 60 requests per minute per IP address
    **Timeout:** 30 seconds maximum processing time
    **Max Size:** 1MB email content limit
    """
    start_time = datetime.utcnow()
    request_id = getattr(request.state, 'request_id', f"req_{int(start_time.timestamp() * 1000000)}")
    
    # Check system capacity before processing
    has_capacity, capacity_message = performance_monitor.check_capacity()
    if not has_capacity:
        raise HTTPException(status_code=503, detail=capacity_message)
    
    # Track request performance - temporarily disabled for debugging
    # async with track_request_performance(
    #     request_id=request_id,
    #     endpoint="/api/analyze",
    #     method="POST",
    #     email_size=len(analysis_request.email_content.encode('utf-8'))
    # ) as metrics:
    if True:  # Temporary replacement for the async context manager
        try:
            print(f"DEBUG: Starting analysis for request {request_id}")
            logger.info(f"Starting email analysis for request {request_id}")
            
            # Extract email content
            print(f"DEBUG: Extracting email content...")
            email_content = analysis_request.email_content
            analysis_options = analysis_request.analysis_options
            print(f"DEBUG: Email content length: {len(email_content)}")
            
            # Content size validation is now handled by middleware
            # But we can still log the size for monitoring
            email_size = len(email_content.encode('utf-8'))
            logger.debug(f"Processing email content of size: {email_size} bytes")
            
            # Step 1: Parse email headers and body
            logger.debug("Parsing email content")
            try:
                email_headers, email_body = services["email_parser"].parse_email(email_content)
                
                # Convert headers to dict for LLM analysis
                headers_dict = {
                    "from": email_headers.from_address,
                    "to": email_headers.to_addresses,
                    "subject": email_headers.subject,
                    "date": email_headers.date,
                    "reply_to": email_headers.reply_to,
                    "message_id": email_headers.message_id,
                    "received": email_headers.received_headers[:3],  # Limit for prompt size
                    "x_headers": dict(list(email_headers.x_headers.items())[:5])  # Limit X-headers
                }
                
            except ValidationException as e:
                logger.warning(f"Email parsing validation failed: {str(e)}")
                raise HTTPException(status_code=400, detail=f"Invalid email format: {str(e)}")
            except Exception as e:
                logger.error(f"Email parsing failed: {str(e)}")
                raise HTTPException(status_code=400, detail="Failed to parse email content")
            
            # Step 2: Extract IOCs if requested
            iocs = None
            if not analysis_options or analysis_options.include_iocs:
                logger.debug("Extracting IOCs")
                try:
                    iocs = await services["ioc_extractor"].extract_all_iocs(
                        email_content, 
                        context="phishing_analysis"
                    )
                    logger.info(f"Extracted IOCs: {len(iocs.urls)} URLs, {len(iocs.ips)} IPs, {len(iocs.domains)} domains")
                except Exception as e:
                    logger.warning(f"IOC extraction failed: {str(e)}")
                    # Continue without IOCs rather than failing
                    from ...models.analysis_models import IOCCollection
                    iocs = IOCCollection()
            
            # Step 3: Perform LLM analysis
            logger.debug("Starting LLM analysis")
            llm_start_time = datetime.utcnow()
            try:
                analysis_result = await services["llm_analyzer"].analyze_email(
                    email_content=email_body or email_content,
                    email_headers=headers_dict,
                    iocs=iocs
                )
                
                llm_processing_time = (datetime.utcnow() - llm_start_time).total_seconds()
                
                # Update performance metrics
                performance_monitor.update_request(
                    request_id,
                    llm_provider="cached" if hasattr(analysis_result, '_from_cache') else 'llm',
                    llm_processing_time=llm_processing_time,
                    ioc_count=len(iocs.urls) + len(iocs.ips) + len(iocs.domains) if iocs else 0
                )
                
                logger.info(
                    f"Analysis completed - Intent: {analysis_result.intent.primary}, "
                    f"Risk Score: {analysis_result.risk_score.score}, "
                    f"Processing Time: {analysis_result.processing_time:.2f}s"
                )
                
            except Exception as e:
                logger.error(f"LLM analysis failed: {str(e)}")
                # Re-raise LLM-specific exceptions to be handled by global handlers
                if isinstance(e, (LLMServiceError, ValidationException)):
                    raise e
                else:
                    raise HTTPException(
                        status_code=500, 
                        detail="Analysis service temporarily unavailable"
                    )
            
            # Step 4: Return successful response
            total_processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Clear email content from memory for security
            from ...core.security import clear_sensitive_memory
            try:
                # Clear the email content variables
                email_content = None
                email_body = None
                headers_dict = None
                
                # Force memory cleanup
                clear_sensitive_memory()
            except Exception as e:
                logger.warning("Error during memory cleanup", error=e)
            
            return ApiResponse.success_response(
                data=analysis_result,
                meta={
                    "total_processing_time": total_processing_time,
                    "ioc_count": {
                        "urls": len(iocs.urls) if iocs else 0,
                        "ips": len(iocs.ips) if iocs else 0,
                        "domains": len(iocs.domains) if iocs else 0
                    },
                    "email_size_bytes": email_size,
                    "security_features_applied": {
                        "content_sanitization": settings.enable_content_sanitization,
                        "memory_cleanup": True
                    }
                }
            )
            
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            # Handle any unexpected errors
            logger.error(f"Unexpected error in analysis endpoint: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail="An unexpected error occurred during analysis"
            )


@router.post("/test")
async def test_endpoint(request: Request) -> Dict[str, Any]:
    """Simple test endpoint to check if POST requests work"""
    try:
        body = await request.body()
        return {"status": "success", "body_length": len(body)}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@router.get("/analyze/status")
@limiter.limit("120/minute")
async def get_analysis_status(request: Request) -> Dict[str, Any]:
    """
    Get current status of analysis services
    
    Returns information about:
    - Available LLM providers
    - Service health status
    - Current rate limits
    """
    try:
        # Check LLM analyzer status
        llm_status = {
            "primary_provider": settings.primary_llm_provider,
            "fallback_provider": settings.fallback_llm_provider,
            "openai_available": bool(settings.openai_api_key),
            "anthropic_available": bool(settings.anthropic_api_key),
        }
        
        # Check service configuration
        config_status = {
            "max_email_size_mb": settings.max_email_size_mb,
            "request_timeout_seconds": settings.request_timeout_seconds,
            "rate_limit_per_minute": settings.rate_limit_requests_per_minute,
        }
        
        return {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "llm_providers": llm_status,
            "configuration": config_status
        }
        
    except Exception as e:
        logger.error(f"Failed to get analysis status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve service status"
        )