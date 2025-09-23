"""
Configuration settings for PhishContext AI backend
"""
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_reload: bool = Field(default=True, env="API_RELOAD")
    
    # LLM Provider Configuration
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, env="ANTHROPIC_API_KEY")
    google_api_key: Optional[str] = Field(default=None, env="GOOGLE_API_KEY")
    
    # LLM Provider Selection
    primary_llm_provider: str = Field(default="openai", env="PRIMARY_LLM_PROVIDER")
    fallback_llm_provider: str = Field(default="anthropic", env="FALLBACK_LLM_PROVIDER")
    
    # VirusTotal Configuration
    virustotal_api_key: Optional[str] = Field(default=None, env="VIRUSTOTAL_API_KEY")
    
    # Security Configuration
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        env="CORS_ORIGINS"
    )
    rate_limit_requests_per_minute: int = Field(default=60, env="RATE_LIMIT_REQUESTS_PER_MINUTE")
    rate_limit_burst_size: int = Field(default=10, env="RATE_LIMIT_BURST_SIZE")
    enable_security_headers: bool = Field(default=True, env="ENABLE_SECURITY_HEADERS")
    enable_content_sanitization: bool = Field(default=True, env="ENABLE_CONTENT_SANITIZATION")
    max_concurrent_requests: int = Field(default=50, env="MAX_CONCURRENT_REQUESTS")
    
    # Logging Configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    enable_security_logging: bool = Field(default=True, env="ENABLE_SECURITY_LOGGING")
    
    # Performance Configuration
    max_email_size_mb: int = Field(default=1, env="MAX_EMAIL_SIZE_MB")
    request_timeout_seconds: int = Field(default=30, env="REQUEST_TIMEOUT_SECONDS")
    llm_timeout_seconds: int = Field(default=25, env="LLM_TIMEOUT_SECONDS")
    memory_cleanup_interval_minutes: int = Field(default=5, env="MEMORY_CLEANUP_INTERVAL_MINUTES")
    enable_performance_monitoring: bool = Field(default=True, env="ENABLE_PERFORMANCE_MONITORING")
    max_request_queue_size: int = Field(default=100, env="MAX_REQUEST_QUEUE_SIZE")
    
    # LLM Model Configuration
    openai_model: str = Field(default="gpt-4", env="OPENAI_MODEL")
    anthropic_model: str = Field(default="claude-3-sonnet-20240229", env="ANTHROPIC_MODEL")
    
    # Retry Configuration
    max_retries: int = Field(default=3, env="MAX_RETRIES")
    retry_delay_seconds: float = Field(default=1.0, env="RETRY_DELAY_SECONDS")
    
    # Cache Configuration
    cache_max_size: int = Field(default=1000, env="CACHE_MAX_SIZE")
    cache_ttl_hours: int = Field(default=24, env="CACHE_TTL_HOURS")
    enable_response_caching: bool = Field(default=True, env="ENABLE_RESPONSE_CACHING")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()