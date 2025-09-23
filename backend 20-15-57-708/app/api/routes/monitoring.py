"""
Monitoring API endpoints for performance metrics and system health
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from ...utils.performance import performance_monitor, get_performance_summary
from ...services.cache_service import analysis_cache
from ...utils.logging import get_secure_logger
from ...core.config import settings

logger = get_secure_logger(__name__)

router = APIRouter()


@router.get("/metrics")
async def get_performance_metrics():
    """
    Get current performance metrics including request stats, system metrics, and cache stats
    """
    try:
        # Get performance metrics
        perf_metrics = get_performance_summary()
        
        # Get cache statistics
        cache_stats = analysis_cache.get_stats()
        
        # Combine all metrics
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "performance": perf_metrics,
            "cache": cache_stats,
            "configuration": {
                "max_concurrent_requests": settings.max_concurrent_requests,
                "max_email_size_mb": settings.max_email_size_mb,
                "llm_timeout_seconds": settings.llm_timeout_seconds,
                "rate_limit_requests_per_minute": settings.rate_limit_requests_per_minute
            }
        }
        
        return JSONResponse(content=metrics)
        
    except Exception as e:
        logger.error("Failed to get performance metrics", error=e)
        raise HTTPException(status_code=500, detail="Failed to retrieve metrics")


@router.get("/metrics/requests")
async def get_request_metrics(
    limit: int = Query(default=100, ge=1, le=1000, description="Number of recent requests to return")
):
    """
    Get detailed metrics for recent requests
    """
    try:
        request_history = performance_monitor.get_request_history(limit=limit)
        
        return JSONResponse(content={
            "timestamp": datetime.utcnow().isoformat(),
            "request_count": len(request_history),
            "requests": request_history
        })
        
    except Exception as e:
        logger.error("Failed to get request metrics", error=e)
        raise HTTPException(status_code=500, detail="Failed to retrieve request metrics")


@router.get("/metrics/dashboard")
async def get_dashboard_data():
    """
    Get comprehensive dashboard data for monitoring UI
    """
    try:
        # Get current metrics
        current_metrics = get_performance_summary()
        cache_stats = analysis_cache.get_stats()
        
        # Get recent request history for charts
        recent_requests = performance_monitor.get_request_history(limit=50)
        
        # Calculate additional dashboard metrics
        now = datetime.utcnow()
        
        # Response time trend (last 50 requests)
        response_times = []
        error_counts = []
        throughput_data = []
        
        if recent_requests:
            # Group by 5-minute intervals for trend data
            interval_data = {}
            for req in recent_requests:
                if req['end_time']:
                    end_time = datetime.fromisoformat(req['end_time'].replace('Z', '+00:00'))
                    interval_key = end_time.replace(minute=(end_time.minute // 5) * 5, second=0, microsecond=0)
                    
                    if interval_key not in interval_data:
                        interval_data[interval_key] = {
                            'response_times': [],
                            'error_count': 0,
                            'total_count': 0
                        }
                    
                    interval_data[interval_key]['total_count'] += 1
                    if req['processing_time']:
                        interval_data[interval_key]['response_times'].append(req['processing_time'])
                    if req['status_code'] and req['status_code'] >= 400:
                        interval_data[interval_key]['error_count'] += 1
            
            # Convert to chart data
            for interval_time, data in sorted(interval_data.items()):
                avg_response_time = (
                    sum(data['response_times']) / len(data['response_times'])
                    if data['response_times'] else 0
                )
                
                response_times.append({
                    'timestamp': interval_time.isoformat(),
                    'avg_response_time': avg_response_time
                })
                
                error_counts.append({
                    'timestamp': interval_time.isoformat(),
                    'error_count': data['error_count'],
                    'total_count': data['total_count'],
                    'error_rate': data['error_count'] / data['total_count'] if data['total_count'] > 0 else 0
                })
                
                throughput_data.append({
                    'timestamp': interval_time.isoformat(),
                    'requests_per_interval': data['total_count']
                })
        
        # System health indicators
        health_indicators = {
            'status': 'healthy',
            'issues': []
        }
        
        # Check for potential issues
        if current_metrics.get('active_requests', 0) > settings.max_concurrent_requests * 0.8:
            health_indicators['issues'].append({
                'type': 'high_load',
                'message': 'High number of active requests',
                'severity': 'warning'
            })
        
        if current_metrics.get('error_rate', 0) > 0.1:  # More than 10% error rate
            health_indicators['issues'].append({
                'type': 'high_error_rate',
                'message': f"Error rate is {current_metrics['error_rate']:.1%}",
                'severity': 'error'
            })
            health_indicators['status'] = 'degraded'
        
        system_metrics = current_metrics.get('system_metrics', {})
        if system_metrics.get('memory_percent', 0) > 85:
            health_indicators['issues'].append({
                'type': 'high_memory',
                'message': f"Memory usage is {system_metrics['memory_percent']:.1f}%",
                'severity': 'warning'
            })
        
        if system_metrics.get('cpu_percent', 0) > 80:
            health_indicators['issues'].append({
                'type': 'high_cpu',
                'message': f"CPU usage is {system_metrics['cpu_percent']:.1f}%",
                'severity': 'warning'
            })
        
        if health_indicators['issues']:
            health_indicators['status'] = 'degraded' if health_indicators['status'] == 'healthy' else health_indicators['status']
        
        # LLM provider status
        llm_status = {
            'primary_provider': settings.primary_llm_provider,
            'fallback_provider': settings.fallback_llm_provider,
            'providers_available': []
        }
        
        if settings.openai_api_key:
            llm_status['providers_available'].append('openai')
        if settings.anthropic_api_key:
            llm_status['providers_available'].append('anthropic')
        
        dashboard_data = {
            'timestamp': now.isoformat(),
            'health': health_indicators,
            'current_metrics': current_metrics,
            'cache_stats': cache_stats,
            'llm_status': llm_status,
            'charts': {
                'response_times': response_times[-20:],  # Last 20 intervals
                'error_rates': error_counts[-20:],
                'throughput': throughput_data[-20:]
            },
            'recent_requests': recent_requests[:10]  # Last 10 requests for details
        }
        
        return JSONResponse(content=dashboard_data)
        
    except Exception as e:
        logger.error("Failed to get dashboard data", error=e)
        raise HTTPException(status_code=500, detail="Failed to retrieve dashboard data")


@router.post("/cache/clear")
async def clear_cache():
    """
    Clear the analysis cache
    """
    try:
        await analysis_cache.clear()
        
        logger.info("Cache cleared via API request")
        
        return JSONResponse(content={
            "message": "Cache cleared successfully",
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error("Failed to clear cache", error=e)
        raise HTTPException(status_code=500, detail="Failed to clear cache")


@router.post("/cache/cleanup")
async def cleanup_cache():
    """
    Manually trigger cache cleanup (remove expired entries)
    """
    try:
        await analysis_cache.remove_expired()
        
        cache_stats = analysis_cache.get_stats()
        
        return JSONResponse(content={
            "message": "Cache cleanup completed",
            "cache_stats": cache_stats,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error("Failed to cleanup cache", error=e)
        raise HTTPException(status_code=500, detail="Failed to cleanup cache")


@router.get("/health/detailed")
async def get_detailed_health():
    """
    Get detailed health check including all system components
    """
    try:
        current_metrics = get_performance_summary()
        cache_stats = analysis_cache.get_stats()
        
        # Check system capacity
        has_capacity, capacity_message = performance_monitor.check_capacity()
        
        # Check LLM provider availability
        llm_providers = {
            'openai': bool(settings.openai_api_key),
            'anthropic': bool(settings.anthropic_api_key),
            'google': bool(settings.google_api_key)
        }
        
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'components': {
                'api': {
                    'status': 'healthy',
                    'active_requests': current_metrics.get('active_requests', 0),
                    'max_concurrent': settings.max_concurrent_requests,
                    'has_capacity': has_capacity,
                    'capacity_message': capacity_message
                },
                'cache': {
                    'status': 'healthy',
                    'size': cache_stats['cache_size'],
                    'hit_rate': cache_stats['hit_rate'],
                    'memory_usage_mb': cache_stats['estimated_memory_mb']
                },
                'llm_providers': {
                    'status': 'healthy' if any(llm_providers.values()) else 'error',
                    'available_providers': [k for k, v in llm_providers.items() if v],
                    'primary': settings.primary_llm_provider,
                    'fallback': settings.fallback_llm_provider
                },
                'system': {
                    'status': 'healthy',
                    'cpu_percent': current_metrics.get('system_metrics', {}).get('cpu_percent', 0),
                    'memory_percent': current_metrics.get('system_metrics', {}).get('memory_percent', 0),
                    'memory_used_mb': current_metrics.get('system_metrics', {}).get('memory_used_mb', 0)
                }
            },
            'metrics': current_metrics
        }
        
        # Determine overall status
        component_statuses = [comp['status'] for comp in health_status['components'].values()]
        if 'error' in component_statuses:
            health_status['status'] = 'error'
        elif 'degraded' in component_statuses:
            health_status['status'] = 'degraded'
        
        return JSONResponse(content=health_status)
        
    except Exception as e:
        logger.error("Failed to get detailed health status", error=e)
        return JSONResponse(
            status_code=500,
            content={
                'status': 'error',
                'timestamp': datetime.utcnow().isoformat(),
                'error': 'Failed to retrieve health status'
            }
        )