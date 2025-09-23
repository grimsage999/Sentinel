"""
LLM analysis service for phishing email analysis
"""
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
from enum import Enum

import httpx
from openai import AsyncOpenAI
from anthropic import AsyncAnthropic
import google.generativeai as genai

from ..core.config import settings
from ..core.exceptions import (
    LLMServiceError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMParsingError,
    LLMConfigurationError
)
from ..models.analysis_models import (
    AnalysisResult,
    IntentAnalysis,
    DeceptionIndicator,
    RiskScore,
    IOCCollection,
    MitreAttackAnalysis,
    IntentType,
    ConfidenceLevel,
    DeceptionIndicatorType,
    SeverityLevel
)
from .prompt_builder import PromptBuilder
from .cache_service import analysis_cache
from ..utils.logging import get_secure_logger, extract_safe_email_metadata


logger = get_secure_logger(__name__)


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"


class LLMAnalyzer:
    """
    Comprehensive LLM integration service for phishing email analysis
    Supports multiple providers with fallback and retry logic
    """
    
    def __init__(self):
        self.prompt_builder = PromptBuilder()
        self.openai_client = None
        self.anthropic_client = None
        self.google_client = None
        
        # Initialize clients based on available API keys
        self._initialize_clients()
        
        # Validate configuration
        self._validate_configuration()
    
    def _initialize_clients(self):
        """Initialize LLM provider clients based on available API keys"""
        if settings.openai_api_key:
            self.openai_client = AsyncOpenAI(
                api_key=settings.openai_api_key,
                timeout=settings.llm_timeout_seconds
            )
            logger.info("OpenAI client initialized")
        
        if settings.anthropic_api_key:
            self.anthropic_client = AsyncAnthropic(
                api_key=settings.anthropic_api_key,
                timeout=settings.llm_timeout_seconds
            )
            logger.info("Anthropic client initialized")
        
        if settings.google_api_key:
            genai.configure(api_key=settings.google_api_key)
            self.google_client = genai.GenerativeModel('gemini-1.5-flash')
            logger.info("Google Gemini client initialized")
    
    def _validate_configuration(self):
        """Validate that at least one LLM provider is configured"""
        if not any([self.openai_client, self.anthropic_client, self.google_client]):
            raise LLMConfigurationError(
                "No LLM providers configured. Please set at least one API key."
            )
        
        # Validate primary provider is available
        primary_provider = LLMProvider(settings.primary_llm_provider)
        if primary_provider == LLMProvider.OPENAI and not self.openai_client:
            logger.warning("Primary provider OpenAI not configured, will use fallback")
        elif primary_provider == LLMProvider.ANTHROPIC and not self.anthropic_client:
            logger.warning("Primary provider Anthropic not configured, will use fallback")
        elif primary_provider == LLMProvider.GOOGLE and not self.google_client:
            logger.warning("Primary provider Google not configured, will use fallback")
    
    async def analyze_email(
        self, 
        email_content: str, 
        email_headers: Optional[Dict[str, Any]] = None,
        iocs: Optional[IOCCollection] = None,
        request_id: Optional[str] = None
    ) -> AnalysisResult:
        """
        Analyze email content using LLM with caching, fallback and retry logic
        
        Args:
            email_content: Raw email content to analyze
            email_headers: Parsed email headers (optional)
            iocs: Pre-extracted IOCs (optional)
            request_id: Unique request identifier for tracking
            
        Returns:
            Structured analysis result
            
        Raises:
            LLMServiceError: When all providers fail
            LLMTimeoutError: When analysis times out
            LLMParsingError: When response cannot be parsed
        """
        start_time = datetime.now(timezone.utc)
        
        if not request_id:
            request_id = f"analysis_{start_time.strftime('%Y%m%d_%H%M%S_%f')}"
        
        # Check cache first for performance optimization
        cached_result = await analysis_cache.get(email_content, email_headers)
        if cached_result:
            logger.debug(
                "Cache hit - returning cached analysis result",
                request_id=request_id,
                cache_age_seconds=(datetime.now(timezone.utc) - cached_result.timestamp).total_seconds()
            )
            
            # Update IOCs if provided (cache doesn't store IOCs)
            if iocs:
                cached_result.iocs = iocs
            
            return cached_result
        
        # Log analysis start with safe metadata
        email_metadata = extract_safe_email_metadata(email_content)
        logger.log_analysis_start(
            request_id=request_id,
            email_length=len(email_content),
            client_ip="internal"  # This will be updated by the API layer
        )
        
        # Build optimized analysis prompt
        prompt = self.prompt_builder.build_analysis_prompt(email_content, email_headers)
        
        # Try primary provider first, then fallback
        providers_to_try = self._get_provider_order()
        
        last_error = None
        for provider in providers_to_try:
            try:
                logger.log_llm_request(
                    request_id=request_id,
                    provider=provider,
                    prompt_length=len(prompt)
                )
                
                # Perform analysis with retry logic
                llm_response = await self._analyze_with_retry(provider, prompt)
                
                logger.log_llm_response(
                    request_id=request_id,
                    provider=provider,
                    response_length=len(llm_response),
                    processing_time=(datetime.now(timezone.utc) - start_time).total_seconds(),
                    success=True
                )
                
                # Parse and validate response with optimized parsing
                analysis_result = self._parse_llm_response_optimized(
                    llm_response, 
                    start_time, 
                    iocs or IOCCollection()
                )
                
                # Enhance with MITRE ATT&CK context
                analysis_result = self.prompt_builder.enhance_analysis_with_mitre(analysis_result)
                
                # Cache the result for future requests
                await analysis_cache.set(email_content, analysis_result, email_headers)
                
                # Log successful completion
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                ioc_count = (len(analysis_result.iocs.urls) + len(analysis_result.iocs.ips) + 
                           len(analysis_result.iocs.domains)) if analysis_result.iocs else 0
                
                logger.log_analysis_complete(
                    request_id=request_id,
                    processing_time=processing_time,
                    llm_provider=provider,
                    success=True,
                    ioc_count=ioc_count
                )
                
                return analysis_result
                
            except Exception as e:
                logger.log_error_with_context(
                    error=e,
                    request_id=request_id,
                    operation=f"LLM analysis with {provider}",
                    provider=provider
                )
                last_error = e
                continue
        
        # All providers failed - try demo mode
        logger.warning("All LLM providers failed, falling back to demo mode")
        return self._create_demo_analysis_result(email_content, email_headers, iocs, start_time)
    
    def _get_provider_order(self) -> list[LLMProvider]:
        """Get ordered list of providers to try (primary first, then fallback)"""
        providers = []
        
        # Add primary provider if available
        try:
            primary = LLMProvider(settings.primary_llm_provider)
            if self._is_provider_available(primary):
                providers.append(primary)
        except ValueError:
            logger.warning(f"Invalid primary provider: {settings.primary_llm_provider}")
        
        # Add fallback provider if available and different from primary
        try:
            fallback = LLMProvider(settings.fallback_llm_provider)
            if (self._is_provider_available(fallback) and 
                fallback not in providers):
                providers.append(fallback)
        except ValueError:
            logger.warning(f"Invalid fallback provider: {settings.fallback_llm_provider}")
        
        # Add any remaining available providers
        for provider in LLMProvider:
            if (self._is_provider_available(provider) and 
                provider not in providers):
                providers.append(provider)
        
        return providers
    
    def _is_provider_available(self, provider: LLMProvider) -> bool:
        """Check if a provider is available (has client initialized)"""
        if provider == LLMProvider.OPENAI:
            return self.openai_client is not None
        elif provider == LLMProvider.ANTHROPIC:
            return self.anthropic_client is not None
        elif provider == LLMProvider.GOOGLE:
            return self.google_client is not None
        return False
    
    async def _analyze_with_retry(self, provider: LLMProvider, prompt: str) -> str:
        """
        Perform analysis with exponential backoff retry logic
        
        Args:
            provider: LLM provider to use
            prompt: Analysis prompt
            
        Returns:
            Raw LLM response text
            
        Raises:
            LLMTimeoutError: When analysis times out
            LLMRateLimitError: When rate limited
            LLMServiceError: When service fails
        """
        for attempt in range(settings.max_retries):
            try:
                if provider == LLMProvider.OPENAI:
                    return await self._call_openai(prompt)
                elif provider == LLMProvider.ANTHROPIC:
                    return await self._call_anthropic(prompt)
                elif provider == LLMProvider.GOOGLE:
                    return await self._call_google(prompt)
                else:
                    raise LLMServiceError(f"Unsupported provider: {provider}")
                    
            except asyncio.TimeoutError:
                if attempt == settings.max_retries - 1:
                    raise LLMTimeoutError(f"Analysis timed out after {settings.max_retries} attempts")
                
                # Exponential backoff
                delay = settings.retry_delay_seconds * (2 ** attempt)
                logger.warning(f"Timeout on attempt {attempt + 1}, retrying in {delay}s")
                await asyncio.sleep(delay)
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Rate limited
                    if attempt == settings.max_retries - 1:
                        raise LLMRateLimitError("Rate limit exceeded")
                    
                    # Wait longer for rate limits
                    delay = settings.retry_delay_seconds * (3 ** attempt)
                    logger.warning(f"Rate limited on attempt {attempt + 1}, retrying in {delay}s")
                    await asyncio.sleep(delay)
                else:
                    raise LLMServiceError(f"HTTP error: {e.response.status_code}")
                    
            except Exception as e:
                if attempt == settings.max_retries - 1:
                    raise LLMServiceError(f"Provider {provider} failed: {str(e)}")
                
                delay = settings.retry_delay_seconds * (2 ** attempt)
                logger.warning(f"Error on attempt {attempt + 1}: {str(e)}, retrying in {delay}s")
                await asyncio.sleep(delay)
    
    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API for analysis"""
        if not self.openai_client:
            raise LLMServiceError("OpenAI client not initialized")
        
        try:
            response = await self.openai_client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Low temperature for consistent analysis
                max_tokens=2000,
                timeout=settings.llm_timeout_seconds
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}")
            raise
    
    async def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic API for analysis"""
        if not self.anthropic_client:
            raise LLMServiceError("Anthropic client not initialized")
        
        try:
            response = await self.anthropic_client.messages.create(
                model=settings.anthropic_model,
                max_tokens=2000,
                temperature=0.1,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            return response.content[0].text.strip()
            
        except Exception as e:
            logger.error(f"Anthropic API error: {str(e)}")
            raise
    
    async def _call_google(self, prompt: str) -> str:
        """Call Google Gemini API for analysis"""
        if not self.google_client:
            raise LLMServiceError("Google client not initialized")
        
        try:
            # Google Gemini doesn't have async support yet, so we'll run it in a thread
            import asyncio
            import concurrent.futures
            
            def _sync_generate():
                try:
                    response = self.google_client.generate_content(
                        prompt,
                        generation_config=genai.types.GenerationConfig(
                            temperature=0.1,
                            max_output_tokens=2000,
                        )
                    )
                    if response and response.text:
                        return response.text.strip()
                    else:
                        raise Exception("Empty response from Google Gemini")
                except Exception as e:
                    logger.error(f"Google Gemini sync error: {str(e)}")
                    raise
            
            # Run the synchronous call in a thread pool with timeout
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = loop.run_in_executor(executor, _sync_generate)
                response_text = await asyncio.wait_for(future, timeout=20.0)
            
            return response_text
            
        except asyncio.TimeoutError:
            logger.error("Google Gemini API timeout")
            raise LLMServiceError("Google Gemini API timeout")
        except Exception as e:
            logger.error(f"Google Gemini API error: {str(e)}")
            raise
    
    def _parse_llm_response_optimized(
        self, 
        response_text: str, 
        start_time: datetime,
        iocs: IOCCollection
    ) -> AnalysisResult:
        """
        Optimized parsing of LLM response into structured AnalysisResult
        
        Args:
            response_text: Raw LLM response
            start_time: Analysis start time
            iocs: Extracted IOCs
            
        Returns:
            Structured analysis result
            
        Raises:
            LLMParsingError: When response cannot be parsed
        """
        try:
            # Fast JSON extraction
            json_text = self.prompt_builder.extract_json_from_response(response_text)
            
            # Quick validation
            if not self.prompt_builder.validate_response_format(json_text):
                raise LLMParsingError("Response does not match expected JSON format")
            
            # Parse JSON
            data = json.loads(json_text)
            
            # Build structured result with optimized parsing
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            # Parse MITRE ATT&CK data if present
            mitre_attack = None
            if 'mitre_attack' in data:
                mitre_attack = self._parse_mitre_attack_fast(data['mitre_attack'])
            
            return AnalysisResult(
                intent=self._parse_intent_fast(data['intent']),
                deception_indicators=self._parse_deception_indicators_fast(data['deception_indicators']),
                risk_score=self._parse_risk_score_fast(data['risk_score']),
                iocs=iocs,
                mitre_attack=mitre_attack,
                processing_time=processing_time,
                timestamp=datetime.now(timezone.utc)
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {str(e)}")
            raise LLMParsingError(f"Invalid JSON response: {str(e)}")
        
        except KeyError as e:
            logger.error(f"Missing required field in response: {str(e)}")
            raise LLMParsingError(f"Missing required field: {str(e)}")
        
        except Exception as e:
            logger.error(f"Unexpected parsing error: {str(e)}")
            raise LLMParsingError(f"Failed to parse response: {str(e)}")
    
    def _parse_llm_response(
        self, 
        response_text: str, 
        start_time: datetime,
        iocs: IOCCollection
    ) -> AnalysisResult:
        """
        Legacy parsing method - kept for compatibility
        """
        return self._parse_llm_response_optimized(response_text, start_time, iocs)
    
    def _clean_response_text(self, response_text: str) -> str:
        """Clean response text to extract JSON"""
        # Remove markdown code blocks if present
        if "```json" in response_text:
            start = response_text.find("```json") + 7
            end = response_text.find("```", start)
            if end != -1:
                response_text = response_text[start:end]
        elif "```" in response_text:
            start = response_text.find("```") + 3
            end = response_text.find("```", start)
            if end != -1:
                response_text = response_text[start:end]
        
        # Find JSON object boundaries
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        
        if start != -1 and end > start:
            return response_text[start:end].strip()
        
        return response_text.strip()
    
    def _parse_intent(self, intent_data: Dict[str, Any]) -> IntentAnalysis:
        """Parse intent data from LLM response"""
        primary = IntentType(intent_data['primary'])
        confidence = ConfidenceLevel(intent_data['confidence'])
        
        alternatives = None
        if 'alternatives' in intent_data and intent_data['alternatives']:
            alternatives = [IntentType(alt) for alt in intent_data['alternatives']]
        
        return IntentAnalysis(
            primary=primary,
            confidence=confidence,
            alternatives=alternatives
        )
    
    def _parse_deception_indicators(self, indicators_data: list) -> list[DeceptionIndicator]:
        """Parse deception indicators from LLM response"""
        indicators = []
        
        for indicator_data in indicators_data:
            indicator = DeceptionIndicator(
                type=DeceptionIndicatorType(indicator_data['type']),
                description=indicator_data['description'],
                evidence=indicator_data['evidence'],
                severity=SeverityLevel(indicator_data['severity'])
            )
            indicators.append(indicator)
        
        return indicators
    
    def _parse_intent_fast(self, intent_data: Dict[str, Any]) -> IntentAnalysis:
        """Fast parsing of intent data from LLM response"""
        try:
            primary = IntentType(intent_data['primary'])
        except ValueError:
            primary = IntentType.OTHER  # Default fallback
        
        try:
            confidence = ConfidenceLevel(intent_data['confidence'])
        except ValueError:
            confidence = ConfidenceLevel.MEDIUM  # Default fallback
        
        alternatives = None
        if 'alternatives' in intent_data and intent_data['alternatives']:
            alternatives = []
            for alt in intent_data['alternatives']:
                try:
                    alternatives.append(IntentType(alt))
                except ValueError:
                    continue  # Skip invalid alternatives
        
        return IntentAnalysis(
            primary=primary,
            confidence=confidence,
            alternatives=alternatives
        )
    
    def _parse_deception_indicators_fast(self, indicators_data: list) -> list[DeceptionIndicator]:
        """Fast parsing of deception indicators from LLM response"""
        indicators = []
        
        for indicator_data in indicators_data:
            try:
                indicator_type = DeceptionIndicatorType(indicator_data['type'])
            except (ValueError, KeyError):
                continue  # Skip invalid indicators
            
            try:
                severity = SeverityLevel(indicator_data['severity'])
            except (ValueError, KeyError):
                severity = SeverityLevel.MEDIUM  # Default fallback
            
            indicator = DeceptionIndicator(
                type=indicator_type,
                description=indicator_data.get('description', ''),
                evidence=indicator_data.get('evidence', ''),
                severity=severity
            )
            indicators.append(indicator)
        
        return indicators
    
    def _parse_risk_score_fast(self, risk_data: Dict[str, Any]) -> RiskScore:
        """Fast parsing of risk score data from LLM response"""
        try:
            score = int(risk_data['score'])
            if not 1 <= score <= 10:
                score = 5  # Default fallback
        except (ValueError, KeyError):
            score = 5  # Default fallback
        
        try:
            confidence = ConfidenceLevel(risk_data['confidence'])
        except (ValueError, KeyError):
            confidence = ConfidenceLevel.MEDIUM  # Default fallback
        
        reasoning = risk_data.get('reasoning', 'Analysis completed')
        
        return RiskScore(
            score=score,
            confidence=confidence,
            reasoning=reasoning
        )
    
    def _parse_risk_score(self, risk_data: Dict[str, Any]) -> RiskScore:
        """Parse risk score data from LLM response"""
        return RiskScore(
            score=int(risk_data['score']),
            confidence=ConfidenceLevel(risk_data['confidence']),
            reasoning=risk_data['reasoning']
        )
    
    def _parse_mitre_attack_fast(self, mitre_data: Dict[str, Any]) -> MitreAttackAnalysis:
        """Fast parsing of MITRE ATT&CK data from LLM response"""
        techniques = mitre_data.get('techniques', [])
        tactics = mitre_data.get('tactics', [])
        attack_narrative = mitre_data.get('attack_narrative', '')
        
        # Validate technique IDs format
        valid_techniques = []
        for technique in techniques:
            if isinstance(technique, str) and technique.startswith('T'):
                valid_techniques.append(technique)
        
        return MitreAttackAnalysis(
            techniques=valid_techniques,
            tactics=tactics,
            attack_narrative=attack_narrative
        )
    
    def _create_demo_analysis_result(
        self, 
        email_content: str, 
        email_headers: Dict[str, Any], 
        iocs: Optional[IOCCollection],
        start_time: datetime
    ) -> AnalysisResult:
        """
        Create a demo analysis result when no LLM providers are available.
        This allows the system to work in offline/demo mode.
        """
        logger.info("Creating demo analysis result - no API keys configured")
        
        # Analyze email content for basic patterns
        content_lower = email_content.lower()
        
        # Determine intent based on keywords
        intent_type = IntentType.OTHER
        confidence = ConfidenceLevel.LOW
        
        # Check for legitimate email indicators first
        legitimate_keywords = ['meeting', 'schedule', 'conference', 'agenda', 'project', 'report', 'update', 'thank you', 'thanks', 'congratulations']
        malicious_keywords = ['urgent', 'immediate', 'suspended', 'verify', 'click here', 'act now', 'limited time']
        
        if (any(word in content_lower for word in legitimate_keywords) and 
            not any(word in content_lower for word in malicious_keywords) and
            len([word for word in ['password', 'login', 'credentials', 'account', 'verify', 'click', 'download'] if word in content_lower]) == 0):
            intent_type = IntentType.LEGITIMATE
            confidence = ConfidenceLevel.HIGH
        elif any(word in content_lower for word in ['password', 'login', 'credentials', 'account', 'verify']):
            intent_type = IntentType.CREDENTIAL_THEFT
            confidence = ConfidenceLevel.MEDIUM
        elif any(word in content_lower for word in ['wire', 'transfer', 'payment', 'invoice']):
            intent_type = IntentType.WIRE_TRANSFER
            confidence = ConfidenceLevel.MEDIUM
        elif any(word in content_lower for word in ['download', 'attachment', '.exe', '.zip', '.pdf']) and any(word in content_lower for word in ['click', 'download']):
            intent_type = IntentType.MALWARE_DELIVERY
            confidence = ConfidenceLevel.MEDIUM
        elif any(word in content_lower for word in ['urgent', 'immediate', 'suspended', 'verify']):
            intent_type = IntentType.OTHER  # Generic social engineering
            confidence = ConfidenceLevel.MEDIUM
        
        # Create intent analysis
        intent_analysis = IntentAnalysis(
            primary=intent_type,
            confidence=confidence,
            explanation=f"Demo mode: Detected potential {intent_type.value} based on keyword analysis"
        )
        
        # Create basic deception indicators
        deception_indicators = []
        
        if email_headers.get('from') and '@' in str(email_headers['from']):
            from_domain = str(email_headers['from']).split('@')[-1].lower()
            if any(suspicious in from_domain for suspicious in ['gmail', 'yahoo', 'hotmail', 'outlook']):
                deception_indicators.append(DeceptionIndicator(
                    type=DeceptionIndicatorType.SPOOFING,
                    description=f"Email from free email provider: {from_domain}",
                    evidence=f"From header contains domain: {from_domain}",
                    severity=SeverityLevel.LOW
                ))
        
        if any(word in content_lower for word in ['urgent', 'immediate', 'act now', 'limited time']):
            urgency_words = [word for word in ['urgent', 'immediate', 'act now', 'limited time'] if word in content_lower]
            deception_indicators.append(DeceptionIndicator(
                type=DeceptionIndicatorType.URGENCY,
                description="Email contains urgency language to pressure recipient",
                evidence=f"Found urgency keywords: {', '.join(urgency_words)}",
                severity=SeverityLevel.MEDIUM
            ))
        
        # Calculate risk score (1-10 scale)
        risk_score_value = 3  # Base score
        if intent_type in [IntentType.CREDENTIAL_THEFT, IntentType.WIRE_TRANSFER]:
            risk_score_value += 4
        elif intent_type == IntentType.MALWARE_DELIVERY:
            risk_score_value += 3
        elif intent_type == IntentType.OTHER:
            risk_score_value += 2
        
        risk_score_value += len(deception_indicators)
        risk_score_value = min(risk_score_value, 10)
        
        risk_factors = [f"Intent: {intent_type.value}"]
        if deception_indicators:
            risk_factors.append(f"{len(deception_indicators)} deception indicators found")
        
        risk_score = RiskScore(
            score=risk_score_value,
            confidence=confidence,
            reasoning=f"Demo analysis: {', '.join(risk_factors)}"
        )
        
        # Create basic MITRE analysis based on intent
        techniques = []
        tactics = []
        attack_narrative = "No attack is present. The email is benign."
        
        if intent_type == IntentType.CREDENTIAL_THEFT:
            techniques = ["T1566.002"]  # Spearphishing Link
            tactics = ["initial-access"]
            attack_narrative = "Demo mode: Credential theft attack using spearphishing link detected"
        elif intent_type == IntentType.MALWARE_DELIVERY:
            techniques = ["T1566.001", "T1204.001"]  # Spearphishing Attachment, User Execution
            tactics = ["initial-access", "execution"]
            attack_narrative = "Demo mode: Malware delivery via spearphishing attachment detected"
        elif intent_type == IntentType.WIRE_TRANSFER:
            techniques = ["T1566.003", "T1534", "T1565.001"]  # Spearphishing via Service, Internal Spearphishing, Data Manipulation
            tactics = ["initial-access", "lateral-movement", "impact"]
            attack_narrative = "Demo mode: Business Email Compromise (BEC) - CEO impersonation requesting fraudulent wire transfer detected"
        elif intent_type == IntentType.RECONNAISSANCE:
            techniques = ["T1598.003"]  # Spearphishing for Information
            tactics = ["reconnaissance"]
            attack_narrative = "Demo mode: Information gathering attempt detected"
        elif intent_type == IntentType.LEGITIMATE:
            techniques = []
            tactics = []
            attack_narrative = "No attack is present. The email is benign."
        elif intent_type == IntentType.OTHER:
            # Only assign techniques if there are deception indicators
            if deception_indicators:
                techniques = ["T1566.002"]  # Generic phishing
                tactics = ["initial-access"]
                attack_narrative = "Demo mode: Generic phishing attempt with deception indicators detected"
            else:
                techniques = []
                tactics = []
                attack_narrative = "No specific attack techniques identified. Email appears benign."
        
        mitre_analysis = MitreAttackAnalysis(
            techniques=techniques,
            tactics=tactics,
            attack_narrative=attack_narrative
        )
        
        # Calculate processing time
        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        return AnalysisResult(
            intent=intent_analysis,
            deception_indicators=deception_indicators,
            risk_score=risk_score,
            mitre_attack=mitre_analysis,
            iocs=iocs or IOCCollection(),
            processing_time=processing_time,
            timestamp=datetime.now(timezone.utc)
        )