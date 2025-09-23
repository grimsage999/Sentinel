"""
Performance monitoring utilities for PhishContext AI
Tracks request metrics, concurrent usage, and system performance
"""

import time
import asyncio
import psutil
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import deque
import threading
from contextlib import asynccontextmanager

from ..utils.logging import get_secure_logger
from ..core.config import settings

logger = get_secure_logger(__name__)


@dataclass
class RequestMetrics:
    """Metrics for a single request"""
    request_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    processing_time: Optional[float] = None
    endpoint: str = ""
    method: str = ""
    status_code: Optional[int] = None
    email_size: int = 0
    llm_provider: str = ""
    llm_processing_time: Optional[float] = None
    ioc_count: int = 0
    error: Optional[str] = None


@dataclass
class SystemMetrics:
    """System-level performance metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    active_requests: int
    total_requests: int
    avg_response_time: float
    error_rate: float


class PerformanceMonitor:
    """Monitor and track application performance metrics"""
    
    def __init__(self):
        self.active_requests: Dict[str, RequestMetrics] = {}
        self.completed_requests: deque = deque(maxlen=1000)  # Keep last 1000 requests
        self.system_metrics: deque = deque(maxlen=288)  # Keep 24 hours of 5-minute intervals
        self.request_queue_size = 0
        self.max_concurrent_requests = 0
        self.lock = threading.RLock()
        
        # Start background monitoring
        self._monitoring_task = None
        self._start_monitoring()
    
    def _start_monitoring(self):
        """Start background system monitoring"""
        if settings.enable_performance_monitoring:
            # This would typically be started in the application lifespan
            logger.info("Performance monitoring enabled")
    
    async def start_background_monitoring(self):
        """Start the background monitoring task"""
        if self._monitoring_task is None:
            self._monitoring_task = asyncio.create_task(self._monitor_system_metrics())
            logger.info("Background performance monitoring started")
    
    async def stop_background_monitoring(self):
        """Stop the background monitoring task"""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            self._monitoring_task = None
            logger.info("Background performance monitoring stopped")
    
    async def _monitor_system_metrics(self):
        """Background task to collect system metrics"""
        while True:
            try:
                await asyncio.sleep(300)  # Collect metrics every 5 minutes
                await self._collect_system_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error collecting system metrics", error=e)
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    async def _collect_system_metrics(self):
        """Collect current system metrics"""
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            # Calculate request metrics
            with self.lock:
                active_count = len(self.active_requests)
                total_count = len(self.completed_requests)
                
                # Calculate average response time from recent requests
                recent_requests = list(self.completed_requests)[-100:]  # Last 100 requests
                if recent_requests:
                    avg_response_time = sum(
                        req.processing_time for req in recent_requests 
                        if req.processing_time is not None
                    ) / len(recent_requests)
                    
                    # Calculate error rate
                    error_count = sum(
                        1 for req in recent_requests 
                        if req.status_code and req.status_code >= 400
                    )
                    error_rate = error_count / len(recent_requests) if recent_requests else 0.0
                else:
                    avg_response_time = 0.0
                    error_rate = 0.0
            
            # Create system metrics record
            metrics = SystemMetrics(
                timestamp=datetime.utcnow(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_mb=memory.used / (1024 * 1024),
                active_requests=active_count,
                total_requests=total_count,
                avg_response_time=avg_response_time,
                error_rate=error_rate
            )
            
            with self.lock:
                self.system_metrics.append(metrics)
            
            # Log metrics if they indicate potential issues
            if cpu_percent > 80 or memory.percent > 85 or active_count > settings.max_concurrent_requests * 0.8:
                logger.warning(
                    "High system resource usage detected",
                    cpu_percent=cpu_percent,
                    memory_percent=memory.percent,
                    active_requests=active_count,
                    max_concurrent=settings.max_concurrent_requests
                )
        
        except Exception as e:
            logger.error("Failed to collect system metrics", error=e)
    
    def start_request(self, request_id: str, endpoint: str, method: str, email_size: int = 0) -> RequestMetrics:
        """Start tracking a new request"""
        metrics = RequestMetrics(
            request_id=request_id,
            start_time=datetime.utcnow(),
            endpoint=endpoint,
            method=method,
            email_size=email_size
        )
        
        with self.lock:
            self.active_requests[request_id] = metrics
            current_active = len(self.active_requests)
            self.max_concurrent_requests = max(self.max_concurrent_requests, current_active)
        
        logger.debug(
            "Request tracking started",
            request_id=request_id,
            endpoint=endpoint,
            active_requests=current_active
        )
        
        return metrics
    
    def update_request(
        self,
        request_id: str,
        llm_provider: Optional[str] = None,
        llm_processing_time: Optional[float] = None,
        ioc_count: Optional[int] = None
    ):
        """Update request metrics during processing"""
        with self.lock:
            if request_id in self.active_requests:
                metrics = self.active_requests[request_id]
                if llm_provider:
                    metrics.llm_provider = llm_provider
                if llm_processing_time is not None:
                    metrics.llm_processing_time = llm_processing_time
                if ioc_count is not None:
                    metrics.ioc_count = ioc_count
    
    def complete_request(
        self,
        request_id: str,
        status_code: int,
        error: Optional[str] = None
    ) -> Optional[RequestMetrics]:
        """Complete request tracking and move to completed requests"""
        with self.lock:
            if request_id not in self.active_requests:
                return None
            
            metrics = self.active_requests.pop(request_id)
            metrics.end_time = datetime.utcnow()
            metrics.processing_time = (metrics.end_time - metrics.start_time).total_seconds()
            metrics.status_code = status_code
            metrics.error = error
            
            self.completed_requests.append(metrics)
        
        logger.debug(
            "Request tracking completed",
            request_id=request_id,
            processing_time=metrics.processing_time,
            status_code=status_code,
            active_requests=len(self.active_requests)
        )
        
        return metrics
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        with self.lock:
            active_count = len(self.active_requests)
            completed_count = len(self.completed_requests)
            
            # Calculate metrics from recent requests
            recent_requests = list(self.completed_requests)[-100:]
            if recent_requests:
                avg_response_time = sum(
                    req.processing_time for req in recent_requests 
                    if req.processing_time is not None
                ) / len(recent_requests)
                
                error_count = sum(
                    1 for req in recent_requests 
                    if req.status_code and req.status_code >= 400
                )
                error_rate = error_count / len(recent_requests)
                
                # Calculate throughput (requests per minute)
                now = datetime.utcnow()
                recent_minute = [
                    req for req in recent_requests 
                    if req.end_time and (now - req.end_time).total_seconds() <= 60
                ]
                throughput = len(recent_minute)
            else:
                avg_response_time = 0.0
                error_rate = 0.0
                throughput = 0
            
            # Get latest system metrics
            latest_system = self.system_metrics[-1] if self.system_metrics else None
        
        return {
            'active_requests': active_count,
            'completed_requests': completed_count,
            'max_concurrent_requests': self.max_concurrent_requests,
            'avg_response_time_seconds': avg_response_time,
            'error_rate': error_rate,
            'throughput_per_minute': throughput,
            'request_queue_size': self.request_queue_size,
            'system_metrics': {
                'cpu_percent': latest_system.cpu_percent if latest_system else 0,
                'memory_percent': latest_system.memory_percent if latest_system else 0,
                'memory_used_mb': latest_system.memory_used_mb if latest_system else 0,
                'timestamp': latest_system.timestamp.isoformat() if latest_system else None
            } if latest_system else None
        }
    
    def get_request_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent request history"""
        with self.lock:
            recent_requests = list(self.completed_requests)[-limit:]
        
        return [
            {
                'request_id': req.request_id,
                'start_time': req.start_time.isoformat(),
                'end_time': req.end_time.isoformat() if req.end_time else None,
                'processing_time': req.processing_time,
                'endpoint': req.endpoint,
                'method': req.method,
                'status_code': req.status_code,
                'email_size': req.email_size,
                'llm_provider': req.llm_provider,
                'llm_processing_time': req.llm_processing_time,
                'ioc_count': req.ioc_count,
                'error': req.error
            }
            for req in recent_requests
        ]
    
    def check_capacity(self) -> Tuple[bool, str]:
        """Check if system has capacity for new requests"""
        with self.lock:
            active_count = len(self.active_requests)
        
        if active_count >= settings.max_concurrent_requests:
            return False, f"Maximum concurrent requests ({settings.max_concurrent_requests}) reached"
        
        if self.request_queue_size >= settings.max_request_queue_size:
            return False, f"Request queue full ({settings.max_request_queue_size})"
        
        # Check system resources if available
        try:
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                return False, "System memory usage too high (>90%)"
            
            cpu_percent = psutil.cpu_percent(interval=0.1)
            if cpu_percent > 95:
                return False, "System CPU usage too high (>95%)"
        except Exception:
            # If we can't check system resources, allow the request
            pass
        
        return True, "Capacity available"
    
    def increment_queue_size(self):
        """Increment request queue size"""
        self.request_queue_size += 1
    
    def decrement_queue_size(self):
        """Decrement request queue size"""
        self.request_queue_size = max(0, self.request_queue_size - 1)


# Global performance monitor instance
performance_monitor = PerformanceMonitor()


@asynccontextmanager
async def track_request_performance(
    request_id: str,
    endpoint: str,
    method: str,
    email_size: int = 0
):
    """Context manager for tracking request performance"""
    metrics = performance_monitor.start_request(request_id, endpoint, method, email_size)
    
    try:
        yield metrics
        performance_monitor.complete_request(request_id, 200)
    except Exception as e:
        error_msg = str(e)
        status_code = getattr(e, 'status_code', 500)
        performance_monitor.complete_request(request_id, status_code, error_msg)
        raise


def get_performance_summary() -> Dict[str, Any]:
    """Get a summary of current performance metrics"""
    return performance_monitor.get_current_metrics()


async def cleanup_performance_data():
    """Clean up old performance data to prevent memory leaks"""
    try:
        # This is handled automatically by the deque maxlen, but we can log it
        current_metrics = performance_monitor.get_current_metrics()
        logger.debug(
            "Performance data cleanup completed",
            active_requests=current_metrics['active_requests'],
            completed_requests=current_metrics['completed_requests']
        )
    except Exception as e:
        logger.error("Error during performance data cleanup", error=e)