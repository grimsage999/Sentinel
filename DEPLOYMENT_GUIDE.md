# PhishContext AI - Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying PhishContext AI in production environments, including configuration, security considerations, monitoring, and maintenance procedures.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Web Server    │    │   API Server    │
│   (nginx/ALB)   │────│   (Frontend)    │────│   (Backend)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                       ┌─────────────────┐             │
                       │   Monitoring    │             │
                       │   (Logs/Metrics)│─────────────┘
                       └─────────────────┘             │
                                                        │
                       ┌─────────────────┐             │
                       │  External APIs  │─────────────┘
                       │ (OpenAI/VT/etc) │
                       └─────────────────┘
```

## Prerequisites

### System Requirements

**Minimum Requirements**:
- CPU: 2 cores
- RAM: 4GB
- Storage: 20GB
- Network: 100Mbps

**Recommended Requirements**:
- CPU: 4+ cores
- RAM: 8GB+
- Storage: 50GB+ SSD
- Network: 1Gbps

### Software Dependencies

**Backend**:
- Python 3.9+
- pip (Python package manager)
- Virtual environment support

**Frontend**:
- Node.js 18+
- npm 8+

**System**:
- Linux (Ubuntu 20.04+ recommended) or macOS
- nginx (for reverse proxy)
- SSL certificates
- Firewall configuration

### External Services

**Required**:
- OpenAI API key (GPT-4 access)
- OR Anthropic API key (Claude access)
- OR Google Cloud API key (Gemini access)

**Optional**:
- VirusTotal API key (for IOC enrichment)
- Monitoring service (DataDog, New Relic, etc.)
- Log aggregation service (ELK stack, Splunk, etc.)

## Deployment Options

### Option 1: Traditional Server Deployment

#### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip python3-venv nodejs npm nginx certbot python3-certbot-nginx

# Create application user
sudo useradd -m -s /bin/bash phishcontext
sudo usermod -aG sudo phishcontext

# Create application directories
sudo mkdir -p /opt/phishcontext/{backend,frontend}
sudo chown -R phishcontext:phishcontext /opt/phishcontext
```

#### 2. Backend Deployment

```bash
# Switch to application user
sudo su - phishcontext

# Navigate to backend directory
cd /opt/phishcontext/backend

# Copy application files
# (Upload your backend code to this directory)

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create production configuration
cp .env.example .env
# Edit .env with production values (see Configuration section)

# Test the application
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

#### 3. Frontend Deployment

```bash
# Navigate to frontend directory
cd /opt/phishcontext/frontend

# Copy application files
# (Upload your frontend code to this directory)

# Install dependencies
npm ci --production

# Create production configuration
cp .env.example .env.production
# Edit .env.production with production values

# Build for production
npm run build

# The built files will be in the 'dist' directory
```

#### 4. Process Management with systemd

**Backend Service** (`/etc/systemd/system/phishcontext-backend.service`):
```ini
[Unit]
Description=PhishContext AI Backend
After=network.target

[Service]
Type=exec
User=phishcontext
Group=phishcontext
WorkingDirectory=/opt/phishcontext/backend
Environment=PATH=/opt/phishcontext/backend/venv/bin
ExecStart=/opt/phishcontext/backend/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

**Enable and start the service**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable phishcontext-backend
sudo systemctl start phishcontext-backend
sudo systemctl status phishcontext-backend
```

#### 5. Nginx Configuration

**Main configuration** (`/etc/nginx/sites-available/phishcontext`):
```nginx
# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;
limit_req_zone $binary_remote_addr zone=analyze:10m rate=10r/m;

server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self';" always;
    
    # Frontend (Static Files)
    location / {
        root /opt/phishcontext/frontend/dist;
        try_files $uri $uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
    
    # API Backend
    location /api/ {
        # Rate limiting
        limit_req zone=api burst=20 nodelay;
        
        # Special rate limiting for analyze endpoint
        location /api/analyze {
            limit_req zone=analyze burst=5 nodelay;
            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 120s;
            proxy_connect_timeout 10s;
            proxy_send_timeout 10s;
            client_max_body_size 2M;
        }
        
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
        proxy_connect_timeout 10s;
        proxy_send_timeout 10s;
        client_max_body_size 2M;
    }
    
    # Health check endpoint (no rate limiting)
    location /api/health {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        access_log off;
    }
}
```

**Enable the site**:
```bash
sudo ln -s /etc/nginx/sites-available/phishcontext /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### 6. SSL Certificate Setup

```bash
# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com

# Set up automatic renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Option 2: Docker Deployment

#### 1. Backend Dockerfile

**`backend/Dockerfile`**:
```dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Start application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

#### 2. Frontend Dockerfile

**`frontend/Dockerfile`**:
```dockerfile
# Build stage
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built files
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/api/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
```

#### 3. Docker Compose

**`docker-compose.yml`**:
```yaml
version: '3.8'

services:
  backend:
    build: ./backend
    container_name: phishcontext-backend
    restart: unless-stopped
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - PRIMARY_LLM_PROVIDER=${PRIMARY_LLM_PROVIDER:-openai}
      - FALLBACK_LLM_PROVIDER=${FALLBACK_LLM_PROVIDER:-anthropic}
      - CORS_ORIGINS=["https://your-domain.com"]
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
    ports:
      - "8000:8000"
    volumes:
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  frontend:
    build: ./frontend
    container_name: phishcontext-frontend
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Optional: Monitoring
  prometheus:
    image: prom/prometheus:latest
    container_name: phishcontext-prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

volumes:
  prometheus_data:
```

**Deploy with Docker Compose**:
```bash
# Create environment file
cp .env.example .env
# Edit .env with production values

# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

## Configuration

### Backend Configuration (`.env`)

```bash
# LLM Provider Configuration
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
GOOGLE_API_KEY=your_google_api_key_here
PRIMARY_LLM_PROVIDER=openai
FALLBACK_LLM_PROVIDER=anthropic

# VirusTotal Configuration
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
CORS_ORIGINS=["https://your-domain.com"]

# Security Configuration
SECRET_KEY=your_secret_key_here_minimum_32_characters
ALLOWED_HOSTS=["your-domain.com", "www.your-domain.com"]

# Performance Configuration
MAX_EMAIL_SIZE_MB=1
REQUEST_TIMEOUT_SECONDS=30
RATE_LIMIT_REQUESTS_PER_MINUTE=60
MAX_CONCURRENT_REQUESTS=50

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE_PATH=/var/log/phishcontext/app.log
LOG_RETENTION_DAYS=30

# Monitoring Configuration
ENABLE_METRICS=true
METRICS_PORT=9000
HEALTH_CHECK_INTERVAL=30
```

### Frontend Configuration (`.env.production`)

```bash
# API Configuration
VITE_API_BASE_URL=https://your-domain.com

# Feature Flags
VITE_ENABLE_ANALYTICS=true
VITE_ENABLE_ERROR_REPORTING=true

# Monitoring
VITE_SENTRY_DSN=your_sentry_dsn_here
```

## Security Considerations

### 1. Network Security

```bash
# Firewall configuration (UFW example)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Fail2ban for SSH protection
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 2. Application Security

**API Key Management**:
- Store API keys in environment variables, never in code
- Use different keys for development and production
- Rotate keys regularly (quarterly recommended)
- Monitor API key usage and set up alerts

**Input Validation**:
- Email content size limits (1MB default)
- Content sanitization for XSS prevention
- Rate limiting to prevent abuse
- Request timeout limits

**Data Protection**:
- No persistent storage of email content
- Memory cleanup after processing
- Secure logging (no sensitive data in logs)
- HTTPS enforcement

### 3. Infrastructure Security

**Server Hardening**:
```bash
# Disable root login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Change default SSH port
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart ssh

# Install security updates automatically
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

## Monitoring and Logging

### 1. Application Monitoring

**Health Checks**:
- `/api/health` - Basic health check
- `/api/health/ready` - Readiness probe
- `/api/health/live` - Liveness probe

**Metrics Collection**:
```python
# Example Prometheus metrics
from prometheus_client import Counter, Histogram, Gauge

# Request metrics
REQUEST_COUNT = Counter('phishcontext_requests_total', 'Total requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('phishcontext_request_duration_seconds', 'Request duration')
ACTIVE_REQUESTS = Gauge('phishcontext_active_requests', 'Active requests')

# Analysis metrics
ANALYSIS_COUNT = Counter('phishcontext_analyses_total', 'Total analyses', ['intent', 'risk_level'])
ANALYSIS_DURATION = Histogram('phishcontext_analysis_duration_seconds', 'Analysis duration')
LLM_API_CALLS = Counter('phishcontext_llm_calls_total', 'LLM API calls', ['provider', 'status'])
```

### 2. Log Management

**Log Configuration** (`logging.conf`):
```ini
[loggers]
keys=root,phishcontext

[handlers]
keys=consoleHandler,fileHandler,rotatingFileHandler

[formatters]
keys=simpleFormatter,detailedFormatter

[logger_root]
level=INFO
handlers=consoleHandler

[logger_phishcontext]
level=INFO
handlers=fileHandler,rotatingFileHandler
qualname=phishcontext
propagate=0

[handler_consoleHandler]
class=StreamHandler
level=INFO
formatter=simpleFormatter
args=(sys.stdout,)

[handler_fileHandler]
class=FileHandler
level=INFO
formatter=detailedFormatter
args=('/var/log/phishcontext/app.log',)

[handler_rotatingFileHandler]
class=handlers.RotatingFileHandler
level=INFO
formatter=detailedFormatter
args=('/var/log/phishcontext/app.log', 'a', 10485760, 5)

[formatter_simpleFormatter]
format=%(asctime)s - %(name)s - %(levelname)s - %(message)s

[formatter_detailedFormatter]
format=%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s
```

### 3. Alerting

**Example alert rules** (Prometheus/Alertmanager):
```yaml
groups:
- name: phishcontext
  rules:
  - alert: HighErrorRate
    expr: rate(phishcontext_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"

  - alert: HighResponseTime
    expr: histogram_quantile(0.95, rate(phishcontext_request_duration_seconds_bucket[5m])) > 30
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High response time detected"
      description: "95th percentile response time is {{ $value }} seconds"

  - alert: ServiceDown
    expr: up{job="phishcontext"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "PhishContext AI service is down"
      description: "Service has been down for more than 1 minute"
```

## Backup and Recovery

### 1. Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/opt/backups/phishcontext"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configuration files
tar -czf $BACKUP_DIR/config_$DATE.tar.gz \
    /opt/phishcontext/backend/.env \
    /opt/phishcontext/frontend/.env.production \
    /etc/nginx/sites-available/phishcontext \
    /etc/systemd/system/phishcontext-backend.service

# Backup logs (last 7 days)
find /var/log/phishcontext -name "*.log" -mtime -7 -exec cp {} $BACKUP_DIR/ \;

# Clean old backups (keep 30 days)
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/config_$DATE.tar.gz"
```

### 2. Disaster Recovery Plan

**Recovery Steps**:
1. Provision new server with same specifications
2. Install required software dependencies
3. Restore configuration files from backup
4. Deploy application code
5. Start services and verify functionality
6. Update DNS records if necessary

**Recovery Time Objective (RTO)**: 2 hours
**Recovery Point Objective (RPO)**: 24 hours

## Maintenance Procedures

### 1. Regular Maintenance Tasks

**Daily**:
- Monitor system health and performance metrics
- Check error logs for issues
- Verify API key usage and limits

**Weekly**:
- Review security logs
- Update system packages
- Backup configuration files
- Test disaster recovery procedures

**Monthly**:
- Rotate API keys
- Review and update security configurations
- Performance optimization review
- Capacity planning assessment

### 2. Update Procedures

**Application Updates**:
```bash
#!/bin/bash
# update-application.sh

# Stop services
sudo systemctl stop phishcontext-backend
sudo systemctl stop nginx

# Backup current version
cp -r /opt/phishcontext /opt/phishcontext.backup.$(date +%Y%m%d)

# Deploy new version
# (Copy new code to /opt/phishcontext)

# Update dependencies
cd /opt/phishcontext/backend
source venv/bin/activate
pip install -r requirements.txt

cd /opt/phishcontext/frontend
npm ci --production
npm run build

# Start services
sudo systemctl start phishcontext-backend
sudo systemctl start nginx

# Verify deployment
curl -f http://localhost:8000/api/health
curl -f http://localhost/api/health

echo "Update completed successfully"
```

**System Updates**:
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Restart services if required
sudo systemctl restart phishcontext-backend
sudo systemctl restart nginx

# Verify services are running
sudo systemctl status phishcontext-backend
sudo systemctl status nginx
```

## Troubleshooting

### Common Issues

**1. Backend Service Won't Start**
```bash
# Check service status
sudo systemctl status phishcontext-backend

# Check logs
sudo journalctl -u phishcontext-backend -f

# Common fixes:
# - Verify API keys in .env file
# - Check Python virtual environment
# - Verify port 8000 is not in use
```

**2. High Response Times**
```bash
# Check system resources
htop
df -h

# Check API provider status
curl -I https://api.openai.com/v1/models

# Scale up workers if needed
# Edit /etc/systemd/system/phishcontext-backend.service
# Change --workers parameter
```

**3. SSL Certificate Issues**
```bash
# Check certificate status
sudo certbot certificates

# Renew certificate
sudo certbot renew

# Test nginx configuration
sudo nginx -t
```

### Performance Tuning

**Backend Optimization**:
```python
# Increase worker processes
uvicorn app.main:app --workers 8 --worker-class uvicorn.workers.UvicornWorker

# Tune memory settings
export PYTHONMALLOC=malloc
export MALLOC_ARENA_MAX=2
```

**Nginx Optimization**:
```nginx
# Increase worker connections
worker_processes auto;
worker_connections 2048;

# Enable gzip compression
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml;

# Optimize buffer sizes
client_body_buffer_size 128k;
client_max_body_size 2m;
client_header_buffer_size 1k;
large_client_header_buffers 4 4k;
```

## Support and Maintenance Contacts

**Technical Support**:
- Primary: [Your technical team contact]
- Secondary: [Backup contact]
- Emergency: [24/7 support contact]

**Vendor Contacts**:
- OpenAI Support: https://help.openai.com/
- Anthropic Support: https://support.anthropic.com/
- VirusTotal Support: https://support.virustotal.com/

**Documentation**:
- Application Documentation: [Link to docs]
- API Documentation: https://your-domain.com/docs
- Monitoring Dashboard: [Link to monitoring]

---

This deployment guide provides comprehensive instructions for production deployment of PhishContext AI. Follow the security best practices and monitoring recommendations to ensure a stable and secure deployment.