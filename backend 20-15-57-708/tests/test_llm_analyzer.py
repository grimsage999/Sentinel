"""
Tests for LLM analyzer service
"""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from app.services.llm_analyzer import LLMAnalyzer, LLMProvider
from app.services.prompt_builder import PromptBuilder
from app.models.analysis_models import (
    IOCCollection, 
    IntentType, 
    ConfidenceLevel,
    DeceptionIndicatorType,
    SeverityLevel
)
from app.core.exceptions import (
    LLMServiceError,
    LLMTimeoutError,
    LLMParsingError,
    LLMConfigurationError
)


class TestLLMAnalyzer:
    """Test cases for LLMAnalyzer class"""
    
    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing"""
        with patch('app.services.llm_analyzer.settings') as mock_settings:
            mock_settings.openai_api_key = "test-openai-key"
            mock_settings.anthropic_api_key = "test-anthropic-key"
            mock_settings.primary_llm_provider = "openai"
            mock_settings.fallback_llm_provider = "anthropic"
            mock_settings.llm_timeout_seconds = 25
            mock_settings.openai_model = "gpt-4"
            mock_settings.anthropic_model = "claude-3-sonnet-20240229"
            mock_settings.max_retries = 3
            mock_settings.retry_delay_seconds = 1.0
            yield mock_settings
    
    @pytest.fixture
    def sample_llm_response(self):
        """Sample valid LLM response"""
        return json.dumps({
            "intent": {
                "primary": "credential_theft",
                "confidence": "High",
                "alternatives": ["reconnaissance"]
            },
            "deception_indicators": [
                {
                    "type": "spoofing",
                    "description": "Sender impersonation detected",
                    "evidence": "From field shows 'Microsoft Security' but domain is suspicious",
                    "severity": "High"
                },
                {
                    "type": "urgency",
                    "description": "Urgent action required language",
                    "evidence": "Account will be suspended in 24 hours",
                    "severity": "Medium"
                }
            ],
            "risk_score": {
                "score": 8,
                "confidence": "High",
                "reasoning": "High confidence phishing attempt with multiple deception indicators"
            }
        })
    
    @pytest.fixture
    def sample_email_content(self):
        """Sample email content for testing"""
        return """
        From: Microsoft Security <security@microsoft-security.com>
        To: user@company.com
        Subject: Urgent: Account Security Alert
        
        Your Microsoft account has been compromised. Click here to secure your account:
        https://microsoft-security-alert.com/secure-account
        
        You have 24 hours to respond or your account will be suspended.
        """
    
    def test_initialization_with_valid_config(self, mock_settings):
        """Test LLMAnalyzer initialization with valid configuration"""
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai, \
             patch('app.services.llm_analyzer.AsyncAnthropic') as mock_anthropic:
            
            analyzer = LLMAnalyzer()
            
            assert analyzer.openai_client is not None
            assert analyzer.anthropic_client is not None
            assert isinstance(analyzer.prompt_builder, PromptBuilder)
            mock_openai.assert_called_once()
            mock_anthropic.assert_called_once()
    
    def test_initialization_without_api_keys(self):
        """Test LLMAnalyzer initialization without API keys raises error"""
        with patch('app.services.llm_analyzer.settings') as mock_settings:
            mock_settings.openai_api_key = None
            mock_settings.anthropic_api_key = None
            
            with pytest.raises(LLMConfigurationError):
                LLMAnalyzer()
    
    def test_provider_order_primary_first(self, mock_settings):
        """Test that primary provider is tried first"""
        with patch('app.services.llm_analyzer.AsyncOpenAI'), \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            analyzer = LLMAnalyzer()
            providers = analyzer._get_provider_order()
            
            assert providers[0] == LLMProvider.OPENAI
            assert providers[1] == LLMProvider.ANTHROPIC
    
    @pytest.mark.asyncio
    async def test_successful_analysis_openai(self, mock_settings, sample_email_content, sample_llm_response):
        """Test successful email analysis using OpenAI"""
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai_class, \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            # Mock OpenAI client and response
            mock_openai_client = AsyncMock()
            mock_openai_class.return_value = mock_openai_client
            
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = sample_llm_response
            mock_openai_client.chat.completions.create.return_value = mock_response
            
            analyzer = LLMAnalyzer()
            result = await analyzer.analyze_email(sample_email_content)
            
            # Verify result structure
            assert result.intent.primary == IntentType.CREDENTIAL_THEFT
            assert result.intent.confidence == ConfidenceLevel.HIGH
            assert len(result.deception_indicators) == 2
            assert result.risk_score.score == 8
            assert result.processing_time > 0
            
            # Verify OpenAI was called
            mock_openai_client.chat.completions.create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_fallback_to_anthropic(self, mock_settings, sample_email_content, sample_llm_response):
        """Test fallback to Anthropic when OpenAI fails"""
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai_class, \
             patch('app.services.llm_analyzer.AsyncAnthropic') as mock_anthropic_class:
            
            # Mock OpenAI client to fail
            mock_openai_client = AsyncMock()
            mock_openai_class.return_value = mock_openai_client
            mock_openai_client.chat.completions.create.side_effect = Exception("OpenAI failed")
            
            # Mock Anthropic client to succeed
            mock_anthropic_client = AsyncMock()
            mock_anthropic_class.return_value = mock_anthropic_client
            
            mock_response = MagicMock()
            mock_response.content = [MagicMock()]
            mock_response.content[0].text = sample_llm_response
            mock_anthropic_client.messages.create.return_value = mock_response
            
            analyzer = LLMAnalyzer()
            result = await analyzer.analyze_email(sample_email_content)
            
            # Verify result was obtained from Anthropic
            assert result.intent.primary == IntentType.CREDENTIAL_THEFT
            mock_anthropic_client.messages.create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_all_providers_fail(self, mock_settings, sample_email_content):
        """Test behavior when all providers fail"""
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai_class, \
             patch('app.services.llm_analyzer.AsyncAnthropic') as mock_anthropic_class:
            
            # Mock both clients to fail
            mock_openai_client = AsyncMock()
            mock_openai_class.return_value = mock_openai_client
            mock_openai_client.chat.completions.create.side_effect = Exception("OpenAI failed")
            
            mock_anthropic_client = AsyncMock()
            mock_anthropic_class.return_value = mock_anthropic_client
            mock_anthropic_client.messages.create.side_effect = Exception("Anthropic failed")
            
            analyzer = LLMAnalyzer()
            
            with pytest.raises(LLMServiceError):
                await analyzer.analyze_email(sample_email_content)
    
    @pytest.mark.asyncio
    async def test_invalid_json_response(self, mock_settings, sample_email_content):
        """Test handling of invalid JSON response"""
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai_class, \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            mock_openai_client = AsyncMock()
            mock_openai_class.return_value = mock_openai_client
            
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = "Invalid JSON response"
            mock_openai_client.chat.completions.create.return_value = mock_response
            
            analyzer = LLMAnalyzer()
            
            with pytest.raises(LLMParsingError):
                await analyzer.analyze_email(sample_email_content)
    
    def test_clean_response_text_with_markdown(self, mock_settings):
        """Test cleaning response text with markdown formatting"""
        with patch('app.services.llm_analyzer.AsyncOpenAI'), \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            analyzer = LLMAnalyzer()
            
            # Test with markdown code blocks
            markdown_response = '```json\n{"test": "value"}\n```'
            cleaned = analyzer._clean_response_text(markdown_response)
            assert cleaned == '{"test": "value"}'
            
            # Test with regular JSON
            json_response = '{"test": "value"}'
            cleaned = analyzer._clean_response_text(json_response)
            assert cleaned == '{"test": "value"}'
    
    def test_parse_intent(self, mock_settings):
        """Test parsing intent from LLM response"""
        with patch('app.services.llm_analyzer.AsyncOpenAI'), \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            analyzer = LLMAnalyzer()
            
            intent_data = {
                "primary": "credential_theft",
                "confidence": "High",
                "alternatives": ["reconnaissance"]
            }
            
            intent = analyzer._parse_intent(intent_data)
            
            assert intent.primary == IntentType.CREDENTIAL_THEFT
            assert intent.confidence == ConfidenceLevel.HIGH
            assert intent.alternatives == [IntentType.RECONNAISSANCE]
    
    def test_parse_deception_indicators(self, mock_settings):
        """Test parsing deception indicators from LLM response"""
        with patch('app.services.llm_analyzer.AsyncOpenAI'), \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            analyzer = LLMAnalyzer()
            
            indicators_data = [
                {
                    "type": "spoofing",
                    "description": "Sender impersonation",
                    "evidence": "Suspicious domain",
                    "severity": "High"
                }
            ]
            
            indicators = analyzer._parse_deception_indicators(indicators_data)
            
            assert len(indicators) == 1
            assert indicators[0].type == DeceptionIndicatorType.SPOOFING
            assert indicators[0].severity == SeverityLevel.HIGH
    
    def test_parse_risk_score(self, mock_settings):
        """Test parsing risk score from LLM response"""
        with patch('app.services.llm_analyzer.AsyncOpenAI'), \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            analyzer = LLMAnalyzer()
            
            risk_data = {
                "score": 8,
                "confidence": "High",
                "reasoning": "Multiple indicators present"
            }
            
            risk_score = analyzer._parse_risk_score(risk_data)
            
            assert risk_score.score == 8
            assert risk_score.confidence == ConfidenceLevel.HIGH
            assert risk_score.reasoning == "Multiple indicators present"


class TestPromptBuilder:
    """Test cases for PromptBuilder class"""
    
    def test_initialization(self):
        """Test PromptBuilder initialization"""
        builder = PromptBuilder()
        
        assert builder.system_prompt is not None
        assert builder.json_schema is not None
        assert len(builder.system_prompt) > 0
    
    def test_build_analysis_prompt(self):
        """Test building analysis prompt"""
        builder = PromptBuilder()
        
        email_content = "Test email content"
        email_headers = {"From": "test@example.com", "Subject": "Test"}
        
        prompt = builder.build_analysis_prompt(email_content, email_headers)
        
        assert "Test email content" in prompt
        assert "From: test@example.com" in prompt
        assert "Subject: Test" in prompt
        assert "JSON Response:" in prompt
    
    def test_validate_response_format_valid(self):
        """Test validation of valid response format"""
        builder = PromptBuilder()
        
        valid_response = json.dumps({
            "intent": {
                "primary": "credential_theft",
                "confidence": "High"
            },
            "deception_indicators": [],
            "risk_score": {
                "score": 5,
                "confidence": "Medium",
                "reasoning": "Test reasoning"
            }
        })
        
        assert builder.validate_response_format(valid_response) is True
    
    def test_validate_response_format_invalid(self):
        """Test validation of invalid response format"""
        builder = PromptBuilder()
        
        # Missing required fields
        invalid_response = json.dumps({
            "intent": {
                "primary": "credential_theft"
            }
        })
        
        assert builder.validate_response_format(invalid_response) is False
        
        # Invalid JSON
        assert builder.validate_response_format("not json") is False
    
    def test_format_headers(self):
        """Test formatting email headers"""
        builder = PromptBuilder()
        
        headers = {
            "From": "test@example.com",
            "Subject": "Test Subject",
            "Custom-Header": "Custom Value"
        }
        
        formatted = builder._format_headers(headers)
        
        assert "From: test@example.com" in formatted
        assert "Subject: Test Subject" in formatted
        assert "Custom-Header: Custom Value" in formatted


class TestLLMAnalyzerAdvanced:
    """Advanced test cases for LLMAnalyzer class"""
    
    @pytest.fixture
    def mock_settings_advanced(self):
        """Advanced mock settings for testing"""
        with patch('app.services.llm_analyzer.settings') as mock_settings:
            mock_settings.openai_api_key = "test-openai-key"
            mock_settings.anthropic_api_key = "test-anthropic-key"
            mock_settings.primary_llm_provider = "openai"
            mock_settings.fallback_llm_provider = "anthropic"
            mock_settings.llm_timeout_seconds = 25
            mock_settings.openai_model = "gpt-4"
            mock_settings.anthropic_model = "claude-3-sonnet-20240229"
            mock_settings.max_retries = 3
            mock_settings.retry_delay_seconds = 1.0
            yield mock_settings

    @pytest.mark.asyncio
    async def test_analyze_email_with_caching(self, mock_settings_advanced, sample_email_content, sample_llm_response):
        """Test email analysis with caching functionality"""
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai_class, \
             patch('app.services.llm_analyzer.AsyncAnthropic'), \
             patch('app.services.llm_analyzer.analysis_cache') as mock_cache:
            
            # Mock cache miss first, then hit
            mock_cache.get.side_effect = [None, MagicMock()]  # First call miss, second hit
            mock_cache.set.return_value = None
            
            # Mock OpenAI client
            mock_openai_client = AsyncMock()
            mock_openai_class.return_value = mock_openai_client
            
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = sample_llm_response
            mock_openai_client.chat.completions.create.return_value = mock_response
            
            analyzer = LLMAnalyzer()
            
            # First call should hit LLM
            result1 = await analyzer.analyze_email(sample_email_content)
            assert result1.intent.primary == IntentType.CREDENTIAL_THEFT
            
            # Verify cache was called
            mock_cache.get.assert_called()
            mock_cache.set.assert_called()

    @pytest.mark.asyncio
    async def test_analyze_email_with_retry_logic(self, mock_settings_advanced, sample_email_content, sample_llm_response):
        """Test retry logic when LLM calls fail temporarily"""
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai_class, \
             patch('app.services.llm_analyzer.AsyncAnthropic'), \
             patch('app.services.llm_analyzer.asyncio.sleep', new_callable=AsyncMock):
            
            mock_openai_client = AsyncMock()
            mock_openai_class.return_value = mock_openai_client
            
            # First call fails, second succeeds
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = sample_llm_response
            
            mock_openai_client.chat.completions.create.side_effect = [
                Exception("Temporary failure"),
                mock_response
            ]
            
            analyzer = LLMAnalyzer()
            result = await analyzer.analyze_email(sample_email_content)
            
            # Should succeed after retry
            assert result.intent.primary == IntentType.CREDENTIAL_THEFT
            assert mock_openai_client.chat.completions.create.call_count == 2

    @pytest.mark.asyncio
    async def test_analyze_email_timeout_handling(self, mock_settings_advanced, sample_email_content):
        """Test timeout handling in LLM analysis"""
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai_class, \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            mock_openai_client = AsyncMock()
            mock_openai_class.return_value = mock_openai_client
            mock_openai_client.chat.completions.create.side_effect = asyncio.TimeoutError()
            
            analyzer = LLMAnalyzer()
            
            with pytest.raises(LLMTimeoutError):
                await analyzer.analyze_email(sample_email_content)

    @pytest.mark.asyncio
    async def test_analyze_email_rate_limit_handling(self, mock_settings_advanced, sample_email_content):
        """Test rate limit handling in LLM analysis"""
        import httpx
        
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai_class, \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            mock_openai_client = AsyncMock()
            mock_openai_class.return_value = mock_openai_client
            
            # Mock rate limit response
            mock_response = MagicMock()
            mock_response.status_code = 429
            rate_limit_error = httpx.HTTPStatusError("Rate limited", request=MagicMock(), response=mock_response)
            mock_openai_client.chat.completions.create.side_effect = rate_limit_error
            
            analyzer = LLMAnalyzer()
            
            with pytest.raises(LLMRateLimitError):
                await analyzer.analyze_email(sample_email_content)

    def test_parse_intent_with_invalid_values(self, mock_settings_advanced):
        """Test intent parsing with invalid enum values"""
        with patch('app.services.llm_analyzer.AsyncOpenAI'), \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            analyzer = LLMAnalyzer()
            
            # Test with invalid intent type
            intent_data = {
                "primary": "invalid_intent_type",
                "confidence": "High",
                "alternatives": ["also_invalid"]
            }
            
            intent = analyzer._parse_intent_fast(intent_data)
            
            # Should fallback to default values
            assert intent.primary == IntentType.OTHER
            assert intent.confidence == ConfidenceLevel.HIGH
            assert intent.alternatives == []  # Invalid alternatives filtered out

    def test_parse_deception_indicators_with_invalid_data(self, mock_settings_advanced):
        """Test deception indicator parsing with invalid data"""
        with patch('app.services.llm_analyzer.AsyncOpenAI'), \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            analyzer = LLMAnalyzer()
            
            indicators_data = [
                {
                    "type": "invalid_type",
                    "description": "Test description",
                    "evidence": "Test evidence",
                    "severity": "High"
                },
                {
                    "type": "spoofing",
                    "description": "Valid indicator",
                    "evidence": "Valid evidence",
                    "severity": "invalid_severity"
                }
            ]
            
            indicators = analyzer._parse_deception_indicators_fast(indicators_data)
            
            # Should filter out invalid indicators and use defaults for invalid fields
            assert len(indicators) == 1  # Only valid indicator
            assert indicators[0].type == DeceptionIndicatorType.SPOOFING
            assert indicators[0].severity == SeverityLevel.MEDIUM  # Default fallback

    def test_clean_response_text_various_formats(self, mock_settings_advanced):
        """Test response text cleaning with various formats"""
        with patch('app.services.llm_analyzer.AsyncOpenAI'), \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            analyzer = LLMAnalyzer()
            
            # Test with markdown code blocks
            markdown_response = '```json\n{"test": "value"}\n```'
            cleaned = analyzer._clean_response_text(markdown_response)
            assert cleaned == '{"test": "value"}'
            
            # Test with plain code blocks
            plain_response = '```\n{"test": "value"}\n```'
            cleaned = analyzer._clean_response_text(plain_response)
            assert cleaned == '{"test": "value"}'
            
            # Test with extra text around JSON
            messy_response = 'Here is the analysis:\n{"test": "value"}\nEnd of analysis.'
            cleaned = analyzer._clean_response_text(messy_response)
            assert cleaned == '{"test": "value"}'
            
            # Test with no JSON brackets
            no_json_response = 'This is not JSON'
            cleaned = analyzer._clean_response_text(no_json_response)
            assert cleaned == 'This is not JSON'

    @pytest.mark.asyncio
    async def test_analyze_email_with_iocs(self, mock_settings_advanced, sample_email_content, sample_llm_response):
        """Test email analysis with pre-extracted IOCs"""
        from app.models.analysis_models import IOCItem, IOCCollection, IOCType
        
        with patch('app.services.llm_analyzer.AsyncOpenAI') as mock_openai_class, \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            mock_openai_client = AsyncMock()
            mock_openai_class.return_value = mock_openai_client
            
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = sample_llm_response
            mock_openai_client.chat.completions.create.return_value = mock_response
            
            # Create test IOCs
            test_iocs = IOCCollection(
                urls=[IOCItem(value="https://malicious.com", type=IOCType.URL, vtLink="https://vt.com/test")],
                ips=[IOCItem(value="203.0.113.45", type=IOCType.IP, vtLink="https://vt.com/ip")],
                domains=[IOCItem(value="evil.org", type=IOCType.DOMAIN, vtLink="https://vt.com/domain")]
            )
            
            analyzer = LLMAnalyzer()
            result = await analyzer.analyze_email(sample_email_content, iocs=test_iocs)
            
            # Should include the provided IOCs
            assert result.iocs == test_iocs
            assert len(result.iocs.urls) == 1
            assert len(result.iocs.ips) == 1
            assert len(result.iocs.domains) == 1

    def test_provider_availability_check(self, mock_settings_advanced):
        """Test provider availability checking"""
        with patch('app.services.llm_analyzer.AsyncOpenAI'), \
             patch('app.services.llm_analyzer.AsyncAnthropic'):
            
            analyzer = LLMAnalyzer()
            
            # Test with configured providers
            assert analyzer._is_provider_available(LLMProvider.OPENAI) == True
            assert analyzer._is_provider_available(LLMProvider.ANTHROPIC) == True
            
            # Test provider order
            providers = analyzer._get_provider_order()
            assert LLMProvider.OPENAI in providers
            assert LLMProvider.ANTHROPIC in providers


class TestPromptBuilderAdvanced:
    """Advanced test cases for PromptBuilder class"""
    
    def test_build_analysis_prompt_with_complex_headers(self):
        """Test building analysis prompt with complex email headers"""
        builder = PromptBuilder()
        
        email_content = "Suspicious email content"
        complex_headers = {
            "From": "attacker@evil.com",
            "To": ["victim1@company.com", "victim2@company.com"],
            "Subject": "Urgent: Account Verification Required",
            "Date": "Mon, 1 Jan 2024 12:00:00 +0000",
            "Reply-To": "noreply@phishing.com",
            "X-Spam-Score": "8.5",
            "Received": [
                "from evil.com by mail.company.com",
                "from [203.0.113.45] by evil.com"
            ]
        }
        
        prompt = builder.build_analysis_prompt(email_content, complex_headers)
        
        assert "Suspicious email content" in prompt
        assert "attacker@evil.com" in prompt
        assert "victim1@company.com" in prompt
        assert "X-Spam-Score: 8.5" in prompt
        assert "JSON Response:" in prompt

    def test_validate_response_format_edge_cases(self):
        """Test response format validation with edge cases"""
        builder = PromptBuilder()
        
        # Test with minimal valid response
        minimal_response = json.dumps({
            "intent": {"primary": "other", "confidence": "Low"},
            "deception_indicators": [],
            "risk_score": {"score": 1, "confidence": "Low", "reasoning": "No clear threats"}
        })
        assert builder.validate_response_format(minimal_response) == True
        
        # Test with extra fields (should still be valid)
        extra_fields_response = json.dumps({
            "intent": {"primary": "credential_theft", "confidence": "High"},
            "deception_indicators": [],
            "risk_score": {"score": 8, "confidence": "High", "reasoning": "Clear phishing"},
            "extra_field": "should be ignored"
        })
        assert builder.validate_response_format(extra_fields_response) == True
        
        # Test with missing required nested fields
        missing_nested_response = json.dumps({
            "intent": {"primary": "credential_theft"},  # Missing confidence
            "deception_indicators": [],
            "risk_score": {"score": 8, "confidence": "High", "reasoning": "Clear phishing"}
        })
        assert builder.validate_response_format(missing_nested_response) == False

    def test_format_headers_with_none_values(self):
        """Test header formatting with None values"""
        builder = PromptBuilder()
        
        headers_with_none = {
            "From": "sender@example.com",
            "To": None,
            "Subject": "Test Subject",
            "Date": None,
            "Reply-To": ""
        }
        
        formatted = builder._format_headers(headers_with_none)
        
        assert "From: sender@example.com" in formatted
        assert "Subject: Test Subject" in formatted
        # None and empty values should be handled gracefully
        assert "To: None" not in formatted
        assert "Date: None" not in formatted