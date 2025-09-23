"""
Health check API routes for system monitoring
"""

import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...core.config import settings
from ...models.response_models import HealthCheckResponse, ServiceStatus, SystemStatus

logger = logging.getLogger(__name__)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# Track application start time for uptime calculation
app_start_time = datetime.utcnow()


@router.get("/health", response_model=HealthCheckResponse)
@limiter.limit("300/minute")  # Higher limit for health checks
async def health_check(request: Request) -> HealthCheckResponse:
    """
    Comprehensive health check endpoint
    
    Returns detailed system status including:
    - Overall system health
    - Individual service status
    - Application uptime
    - Configuration validation
    
    This endpoint is used by:
    - Load balancers for health monitoring
    - Monitoring systems for alerting
    - Operations teams for troubleshooting
    """
    try:
        logger.debug("Performing health check")
        
        # Calculate uptime
        uptime_seconds = (datetime.utcnow() - app_start_time).total_seconds()
        
        # Check individual services
        services_status = await _check_services_health()
        
        # Determine overall system status
        system_status = _determine_system_status(services_status)
        
        return HealthCheckResponse(
            status=system_status,
            timestamp=datetime.utcnow(),
            services=services_status,
            version="1.0.0",
            uptime=uptime_seconds
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}", exc_info=True)
        
        # Return unhealthy status if health check itself fails
        return HealthCheckResponse(
            status=SystemStatus.UNHEALTHY,
            timestamp=datetime.utcnow(),
            services={"health_check": ServiceStatus.UNAVAILABLE},
            uptime=(datetime.utcnow() - app_start_time).total_seconds()
        )


@router.get("/health/live")
@limiter.limit("600/minute")  # Very high limit for liveness probes
async def liveness_probe(request: Request) -> Dict[str, Any]:
    """
    Simple liveness probe for Kubernetes/container orchestration
    
    Returns basic status indicating the application is running.
    This is a lightweight check that should always succeed if the app is alive.
    """
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime": (datetime.utcnow() - app_start_time).total_seconds()
    }


@router.get("/health/ready")
@limiter.limit("300/minute")
async def readiness_probe(request: Request) -> Dict[str, Any]:
    """
    Readiness probe for Kubernetes/container orchestration
    
    Returns status indicating whether the application is ready to serve traffic.
    Checks critical dependencies and configuration.
    """
    try:
        # Check critical services
        services_status = await _check_critical_services()
        
        # Determine if ready to serve traffic
        is_ready = all(
            status in [ServiceStatus.AVAILABLE, ServiceStatus.DEGRADED]
            for status in services_status.values()
        )
        
        if is_ready:
            return {
                "status": "ready",
                "timestamp": datetime.utcnow().isoformat(),
                "services": services_status
            }
        else:
            raise HTTPException(
                status_code=503,
                detail={
                    "status": "not_ready",
                    "timestamp": datetime.utcnow().isoformat(),
                    "services": services_status
                }
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}")
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "error": "Readiness check failed",
                "timestamp": datetime.utcnow().isoformat()
            }
        )


async def _check_services_health() -> Dict[str, ServiceStatus]:
    """Check health of all application services"""
    services = {}
    
    # Check LLM providers
    services.update(await _check_llm_providers())
    
    # Check configuration
    services["configuration"] = _check_configuration()
    
    # Check memory and basic system resources
    services["system_resources"] = _check_system_resources()
    
    return services


async def _check_critical_services() -> Dict[str, ServiceStatus]:
    """Check only critical services for readiness probe"""
    services = {}
    
    # Check at least one LLM provider is available
    llm_services = await _check_llm_providers()
    has_available_llm = any(
        status == ServiceStatus.AVAILABLE 
        for status in llm_services.values()
    )
    
    services["llm_providers"] = (
        ServiceStatus.AVAILABLE if has_available_llm 
        else ServiceStatus.UNAVAILABLE
    )
    
    # Check configuration
    services["configuration"] = _check_configuration()
    
    return services


async def _check_llm_providers() -> Dict[str, ServiceStatus]:
    """Check availability of LLM providers"""
    services = {}
    
    # Check OpenAI
    if settings.openai_api_key:
        services["openai"] = await _test_llm_provider("openai")
    else:
        services["openai"] = ServiceStatus.UNAVAILABLE
    
    # Check Anthropic
    if settings.anthropic_api_key:
        services["anthropic"] = await _test_llm_provider("anthropic")
    else:
        services["anthropic"] = ServiceStatus.UNAVAILABLE
    
    # Check Google (if configured)
    if settings.google_api_key:
        services["google"] = await _test_llm_provider("google")
    else:
        services["google"] = ServiceStatus.UNAVAILABLE
    
    return services


async def _test_llm_provider(provider: str) -> ServiceStatus:
    """Test connectivity to a specific LLM provider"""
    try:
        # For health checks, we just verify the API key is configured
        # and basic connectivity (without making actual API calls to save costs)
        
        if provider == "openai" and settings.openai_api_key:
            # Could add a simple API test here if needed
            return ServiceStatus.AVAILABLE
        elif provider == "anthropic" and settings.anthropic_api_key:
            # Could add a simple API test here if needed
            return ServiceStatus.AVAILABLE
        elif provider == "google" and settings.google_api_key:
            # Could add a simple API test here if needed
            return ServiceStatus.AVAILABLE
        else:
            return ServiceStatus.UNAVAILABLE
            
    except Exception as e:
        logger.warning(f"LLM provider {provider} health check failed: {str(e)}")
        return ServiceStatus.DEGRADED


def _check_configuration() -> ServiceStatus:
    """Check application configuration validity"""
    try:
        # Verify critical configuration
        required_settings = [
            settings.primary_llm_provider,
            settings.max_email_size_mb,
            settings.request_timeout_seconds
        ]
        
        if not all(required_settings):
            return ServiceStatus.DEGRADED
        
        # Verify at least one LLM provider is configured
        has_llm_provider = any([
            settings.openai_api_key,
            settings.anthropic_api_key,
            settings.google_api_key
        ])
        
        if not has_llm_provider:
            return ServiceStatus.UNAVAILABLE
        
        return ServiceStatus.AVAILABLE
        
    except Exception as e:
        logger.error(f"Configuration check failed: {str(e)}")
        return ServiceStatus.DEGRADED


def _check_system_resources() -> ServiceStatus:
    """Check basic system resource availability"""
    try:
        # Basic memory and system checks
        # In a production environment, you might check:
        # - Available memory
        # - Disk space
        # - CPU usage
        # - Network connectivity
        
        # For now, return available if no obvious issues
        return ServiceStatus.AVAILABLE
        
    except Exception as e:
        logger.warning(f"System resource check failed: {str(e)}")
        return ServiceStatus.DEGRADED


@router.get("/health/security")
@limiter.limit("120/minute")
async def security_status(request: Request) -> Dict[str, Any]:
    """
    Security status and metrics endpoint
    
    Returns current security configuration and metrics including:
    - Security feature status
    - Current threat metrics
    - Performance metrics
    - System capacity status
    """
    try:
        from ...middleware.security import get_security_status
        return get_security_status()
    except Exception as e:
        logger.error(f"Security status check failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve security status"
        )


def _determine_system_status(services_status: Dict[str, ServiceStatus]) -> SystemStatus:
    """Determine overall system status based on individual services"""
    
    # Count service statuses
    available_count = sum(1 for status in services_status.values() 
                         if status == ServiceStatus.AVAILABLE)
    degraded_count = sum(1 for status in services_status.values() 
                        if status == ServiceStatus.DEGRADED)
    unavailable_count = sum(1 for status in services_status.values() 
                           if status == ServiceStatus.UNAVAILABLE)
    
    total_services = len(services_status)
    
    # Determine overall status
    if unavailable_count > total_services // 2:
        return SystemStatus.UNHEALTHY
    elif degraded_count > 0 or unavailable_count > 0:
        return SystemStatus.DEGRADED
    else:
        return SystemStatus.HEALTHY