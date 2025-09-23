# Security and Performance Features

This document describes the security and performance features implemented in PhishContext AI.

## Security Features

### 1. Input Sanitization and XSS Prevention

**Implementation**: `app/core/security.py`

- **Content Sanitization**: Removes malicious script tags, JavaScript URLs, and other potentially dangerous content
- **XSS Prevention**: Neutralizes JavaScript execution attempts and dangerous HTML elements
- **Pattern Detection**: Identifies and logs various threat types including:
  - Script injection attempts
  - Dangerous file attachments (.exe, .scr, .bat, etc.)
  - IP-based URLs (potential C&C servers)
  - URL shorteners (common in phishing)
  - Base64 encoded content (potential malware)

**Key Functions**:

```python
sanitize_email_content(content: str) -> str
detect_malicious_patterns(content: str) -> List[Dict[str, Any]]
validate_url_safety(url: str) -> Dict[str, Any]
```

### 2. Request Size Validation

**Implementation**: `app/middleware/security.py`

- **Size Limits**: Configurable maximum email content size (default: 1MB)
- **Early Validation**: Requests are validated before processing to prevent resource exhaustion
- **Graceful Rejection**: Oversized requests receive clear error messages

**Configuration**:

```python
MAX_EMAIL_SIZE_MB = 1  # Configurable via environment variable
```

### 3. Memory Management

**Implementation**: `app/core/security.py` - `EmailContentManager`

- **Automatic Cleanup**: Email content is automatically cleared from memory after processing
- **Retention Limits**: Content is retained for maximum 5 minutes before forced cleanup
- **Explicit Clearing**: Content can be explicitly cleared after analysis completion
- **Garbage Collection**: Forces garbage collection to ensure memory is freed

**Key Features**:

```python
email_content_manager.store_content(content_id, content)
email_content_manager.clear_content(content_id)
email_content_manager.cleanup_expired()
```

### 4. Security Headers

**Implementation**: `app/middleware/security.py` - `SecurityHeadersMiddleware`

Applied security headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'; ...`
- `Cache-Control: no-store, no-cache` (for sensitive endpoints)

### 5. Security Logging

**Implementation**: `app/utils/logging.py` - `SecureLogger`

- **Sensitive Data Filtering**: Automatically removes email addresses and sensitive content from logs
- **Structured Logging**: JSON-formatted logs with security event tracking
- **Threat Metrics**: Tracks and logs security events for monitoring

**Security Events Logged**:

- Content sanitization events
- Malicious pattern detection
- Size limit violations
- Capacity limit reached
- High-severity threats

## Performance Features

### 1. Concurrent Request Handling

**Implementation**: `app/middleware/security.py` - `SecurityMiddleware`

- **Semaphore-based Limiting**: Controls maximum concurrent requests (default: 50)
- **Queue Management**: Manages request queue with configurable size limits
- **Capacity Checking**: Validates system capacity before processing requests
- **Graceful Degradation**: Returns appropriate error messages when at capacity

**Configuration**:

```python
MAX_CONCURRENT_REQUESTS = 50
MAX_REQUEST_QUEUE_SIZE = 100
```

### 2. Performance Monitoring

**Implementation**: `app/utils/performance.py` - `PerformanceMonitor`

**Request-Level Metrics**:

- Processing time tracking
- LLM provider performance
- Email content size
- IOC extraction counts
- Error rates and status codes

**System-Level Metrics**:

- CPU usage monitoring
- Memory usage tracking
- Active request counts
- Throughput measurements (requests per minute)

**Background Monitoring**:

- Automatic system metrics collection every 5 minutes
- Resource usage alerts when thresholds exceeded
- Historical data retention for analysis

### 3. Rate Limiting

**Implementation**: FastAPI SlowAPI integration

- **Per-IP Rate Limiting**: 60 requests per minute per IP address (configurable)
- **Burst Protection**: Additional burst size limiting
- **Endpoint-Specific Limits**: Different limits for different endpoints
  - Analysis: 60/minute
  - Health checks: 300/minute
  - Security status: 120/minute

### 4. Memory Optimization

**Features**:

- **Periodic Cleanup**: Automatic cleanup every 5 minutes
- **Content Lifecycle Management**: Tracks and manages email content lifecycle
- **Garbage Collection**: Forced garbage collection after sensitive operations
- **Memory Usage Monitoring**: Tracks memory usage and alerts on high usage

## Configuration

### Environment Variables

```bash
# Security Configuration
ENABLE_CONTENT_SANITIZATION=true
ENABLE_SECURITY_HEADERS=true
ENABLE_SECURITY_LOGGING=true
MAX_EMAIL_SIZE_MB=1
MAX_CONCURRENT_REQUESTS=50

# Performance Configuration
ENABLE_PERFORMANCE_MONITORING=true
MEMORY_CLEANUP_INTERVAL_MINUTES=5
MAX_REQUEST_QUEUE_SIZE=100
RATE_LIMIT_REQUESTS_PER_MINUTE=60
RATE_LIMIT_BURST_SIZE=10

# Timeouts
REQUEST_TIMEOUT_SECONDS=30
LLM_TIMEOUT_SECONDS=25
```

### Security Levels

The system supports different security levels through configuration:

**High Security** (Production):

```python
ENABLE_CONTENT_SANITIZATION=true
ENABLE_SECURITY_HEADERS=true
MAX_EMAIL_SIZE_MB=1
MAX_CONCURRENT_REQUESTS=25
```

**Balanced** (Default):

```python
ENABLE_CONTENT_SANITIZATION=true
ENABLE_SECURITY_HEADERS=true
MAX_EMAIL_SIZE_MB=1
MAX_CONCURRENT_REQUESTS=50
```

**Development**:

```python
ENABLE_CONTENT_SANITIZATION=false
ENABLE_SECURITY_HEADERS=false
MAX_EMAIL_SIZE_MB=2
MAX_CONCURRENT_REQUESTS=100
```

## Monitoring and Alerting

### Health Endpoints

- **`/api/health`**: Comprehensive system health check
- **`/api/health/security`**: Security status and metrics
- **`/api/health/live`**: Simple liveness probe
- **`/api/health/ready`**: Readiness probe with dependency checks

### Metrics Available

**Security Metrics**:

```json
{
  "threat_counts": {
    "script_injection": 5,
    "dangerous_attachment": 2,
    "ip_based_urls": 3
  },
  "sanitization_counts": 12,
  "blocked_requests": 1
}
```

**Performance Metrics**:

```json
{
  "active_requests": 3,
  "completed_requests": 1247,
  "avg_response_time_seconds": 2.3,
  "error_rate": 0.02,
  "throughput_per_minute": 45,
  "system_metrics": {
    "cpu_percent": 25.4,
    "memory_percent": 67.2,
    "memory_used_mb": 512.3
  }
}
```

## Testing

### Validation Script

Run the validation script to test all security and performance features:

```bash
cd backend
python3 validate_security.py
```

### Unit Tests

Comprehensive test suite available in `tests/test_security_features.py`:

```bash
python3 -m pytest tests/test_security_features.py -v
```

### Test Coverage

The test suite covers:

- Content sanitization and XSS prevention
- Size validation and limits
- Malicious pattern detection
- Memory management lifecycle
- Performance monitoring
- Request tracking
- Security metrics
- Configuration validation

## Security Best Practices

### Content Handling

1. **Never log email content**: All logging filters out sensitive email content
2. **Sanitize before processing**: Content is sanitized before LLM analysis
3. **Clear after use**: Email content is explicitly cleared from memory
4. **Validate size limits**: Prevent resource exhaustion attacks

### Request Processing

1. **Rate limiting**: Prevent abuse and DoS attacks
2. **Concurrent limits**: Protect system resources
3. **Input validation**: Validate all inputs before processing
4. **Error handling**: Provide secure error messages without information leakage

### Monitoring

1. **Security events**: Log all security-relevant events
2. **Performance tracking**: Monitor system performance continuously
3. **Alerting**: Set up alerts for security and performance thresholds
4. **Regular cleanup**: Automatic cleanup of sensitive data

## Performance Optimization

### Request Processing

1. **Async processing**: All I/O operations are asynchronous
2. **Connection pooling**: Efficient HTTP client connections
3. **Memory management**: Proactive memory cleanup
4. **Resource monitoring**: Continuous resource usage tracking

### System Resources

1. **CPU monitoring**: Track CPU usage and alert on high usage
2. **Memory tracking**: Monitor memory usage and cleanup
3. **Concurrent limits**: Prevent resource exhaustion
4. **Queue management**: Efficient request queuing

## Troubleshooting

### Common Issues

**High Memory Usage**:

- Check memory cleanup interval
- Verify email content is being cleared
- Monitor for memory leaks in logs

**Performance Degradation**:

- Check concurrent request limits
- Monitor system resource usage
- Review error rates and timeouts

**Security Alerts**:

- Review security event logs
- Check threat detection patterns
- Verify sanitization is working

### Debug Commands

```bash
# Check security status
curl http://localhost:8000/api/health/security

# Monitor performance
curl http://localhost:8000/api/health

# Validate security features
python3 validate_security.py
```

## Dependencies

Required packages for security and performance features:

```
psutil==5.9.6          # System resource monitoring
slowapi==0.1.9         # Rate limiting
fastapi==0.104.1       # Web framework with security features
```

## Future Enhancements

Planned improvements:

1. **Advanced Threat Detection**: Machine learning-based threat detection
2. **Distributed Rate Limiting**: Redis-based rate limiting for multiple instances
3. **Enhanced Monitoring**: Integration with monitoring systems (Prometheus, Grafana)
4. **Security Scanning**: Integration with external security scanning services
5. **Performance Analytics**: Advanced performance analytics and optimization recommendations
