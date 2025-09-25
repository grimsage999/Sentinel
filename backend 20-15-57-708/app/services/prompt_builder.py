"""
Prompt building service for LLM analysis with MITRE ATT&CK integration
"""
import json
from typing import Dict, Any
from ..models.analysis_models import (
    IntentType, 
    DeceptionIndicatorType, 
    ConfidenceLevel, 
    SeverityLevel,
    IOCType
)
from .mitre_attack_service import MitreAttackService


class PromptBuilder:
    """Builds comprehensive prompts for phishing email analysis with MITRE ATT&CK context"""
    
    def __init__(self):
        self.system_prompt = self._build_system_prompt()
        self.json_schema = self._build_json_schema()
        self.mitre_service = MitreAttackService()
    
    def build_analysis_prompt(self, email_content: str, email_headers: Dict[str, Any] = None, threat_intelligence_context: str = "") -> str:
        """
        Build optimized analysis prompt for faster processing with threat intelligence context
        
        Args:
            email_content: Raw email content to analyze
            email_headers: Parsed email headers (optional)
            threat_intelligence_context: Additional threat intelligence context (optional)
            
        Returns:
            Optimized prompt string for LLM analysis
        """
        # Optimize email content for speed
        optimized_content = self._optimize_email_content(email_content)
        
        # Build minimal header context
        header_context = ""
        if email_headers:
            header_context = self._build_minimal_header_context(email_headers)
        
        # Build streamlined prompt for faster processing with threat intelligence if available
        threat_intel_section = ""
        if threat_intelligence_context:
            threat_intel_section = f"""

{threat_intelligence_context}
Consider this threat intelligence when analyzing the email. If any IOCs match known threats, increase risk assessment accordingly."""

        prompt = f"""Analyze this email for phishing. Respond with JSON only:

{optimized_content}{header_context}{threat_intel_section}

Required JSON format:
{self._get_compact_schema()}"""
        
        return prompt
    
    def _build_system_prompt(self) -> str:
        """Build optimized system prompt with MITRE ATT&CK context"""
        return """Analyze email for phishing using MITRE ATT&CK framework context. Be accurate with legitimate vs malicious classification.

LEGITIMATE (Risk 1-3, Intent: legitimate):
- Official domains: microsoft.com, chase.com, apple.com, google.com, amazon.com, paypal.com
- Business communications: statements, updates, notifications
- Links match sender domain
- No credential requests or threats
- MITRE Context: No attack techniques present

SUSPICIOUS (Risk 4-6):
- Generic senders or vague requests
- Slightly suspicious but unclear intent
- Minor inconsistencies
- MITRE Context: Possible reconnaissance (T1598) or initial access attempts

PHISHING (Risk 7-10):
- Domain spoofing or wrong domains (T1036.005 - Masquerading)
- Credential theft attempts (T1566.002 - Spearphishing Link, T1598.003 - Phishing for Information)
- Urgent threats or account suspension (T1566 - Phishing)
- Wire transfer requests (T1566 - Business Email Compromise)
- Malware delivery attempts (T1566.001 - Spearphishing Attachment, T1204 - User Execution)

Include MITRE ATT&CK technique IDs in your reasoning when applicable. Analyze carefully and classify correctly. Respond JSON only."""

    def _build_json_schema(self) -> str:
        """Build the JSON schema template for LLM responses"""
        schema = {
            "intent": {
                "primary": f"One of: {', '.join([intent.value for intent in IntentType])}",
                "confidence": f"One of: {', '.join([conf.value for conf in ConfidenceLevel])}",
                "alternatives": ["Optional array of alternative intent types"]
            },
            "deception_indicators": [
                {
                    "type": f"One of: {', '.join([dec.value for dec in DeceptionIndicatorType])}",
                    "description": "Brief description of the deception technique",
                    "evidence": "Specific text or element from the email that demonstrates this indicator",
                    "severity": f"One of: {', '.join([sev.value for sev in SeverityLevel])}"
                }
            ],
            "risk_score": {
                "score": "Integer from 1-10",
                "confidence": f"One of: {', '.join([conf.value for conf in ConfidenceLevel])}",
                "reasoning": "Detailed explanation of the risk score assessment with MITRE ATT&CK context"
            },
            "mitre_attack": {
                "techniques": ["Array of applicable MITRE ATT&CK technique IDs (e.g., T1566.002)"],
                "tactics": ["Array of MITRE ATT&CK tactics (e.g., initial-access, credential-access)"],
                "attack_narrative": "Brief explanation of the attack chain using MITRE ATT&CK framework"
            }
        }
        
        return json.dumps(schema, indent=2)
    
    def _format_headers(self, headers: Dict[str, Any]) -> str:
        """Format email headers for inclusion in prompt"""
        if not headers:
            return "No headers available"
        
        # Focus on security-relevant headers
        important_headers = [
            'From', 'To', 'Subject', 'Date', 'Reply-To', 'Return-Path',
            'Received', 'Message-ID', 'X-Originating-IP', 'Authentication-Results',
            'DKIM-Signature', 'SPF', 'DMARC'
        ]
        
        formatted_headers = []
        for header in important_headers:
            if header in headers:
                value = headers[header]
                if isinstance(value, list):
                    value = '; '.join(str(v) for v in value)
                formatted_headers.append(f"{header}: {value}")
        
        # Add any other headers not in the important list
        for header, value in headers.items():
            if header not in important_headers:
                if isinstance(value, list):
                    value = '; '.join(str(v) for v in value)
                formatted_headers.append(f"{header}: {value}")
        
        return '\n'.join(formatted_headers)
    
    def _optimize_email_content(self, email_content: str) -> str:
        """
        Optimize email content for faster LLM processing
        Removes redundant information while preserving analysis-critical elements
        """
        import re
        
        # Aggressive truncation for speed (6000 chars max)
        max_length = 6000
        if len(email_content) > max_length:
            # Prioritize important content
            lines = email_content.split('\n')
            important_lines = []
            current_length = 0
            
            for line in lines:
                line_lower = line.lower()
                # Keep headers, URLs, and body content
                if (any(h in line_lower for h in ['from:', 'to:', 'subject:', 'reply-to:']) or
                    'http' in line_lower or 'www.' in line_lower or
                    (len(line.strip()) > 0 and current_length < max_length * 0.8)):
                    
                    important_lines.append(line)
                    current_length += len(line)
                    
                    if current_length > max_length:
                        break
            
            email_content = '\n'.join(important_lines)[:max_length] + "\n[Truncated]"
        
        # Clean up excessive whitespace
        email_content = re.sub(r'\n\s*\n\s*\n', '\n\n', email_content)
        email_content = re.sub(r'[ \t]+', ' ', email_content)
        
        return email_content.strip()
    
    def _build_minimal_header_context(self, headers: Dict[str, Any]) -> str:
        """Build minimal header context for faster processing"""
        critical_headers = ['From', 'Subject', 'Reply-To']
        header_parts = []
        
        for header in critical_headers:
            if header in headers and headers[header]:
                value = str(headers[header])[:100]  # Truncate long values
                header_parts.append(f"{header}: {value}")
        
        return f"\nHeaders: {'; '.join(header_parts)}" if header_parts else ""
    
    def _get_compact_schema(self) -> str:
        """Get compact JSON schema for faster processing with MITRE ATT&CK"""
        return """{
  "intent": {"primary": "credential_theft|wire_transfer|malware_delivery|reconnaissance|legitimate|other", "confidence": "high|medium|low"},
  "deception_indicators": [{"type": "spoofing|urgency|authority|suspicious_links|grammar", "description": "brief", "evidence": "specific text", "severity": "high|medium|low"}],
  "risk_score": {"score": 1-10, "confidence": "high|medium|low", "reasoning": "brief with MITRE context"},
  "mitre_attack": {"techniques": ["T1566.002"], "tactics": ["initial-access"], "attack_narrative": "brief attack explanation"}
}"""
    
    def validate_response_format(self, response_text: str) -> bool:
        """
        Fast validation of LLM response format
        Optimized for speed with minimal checks
        
        Args:
            response_text: Raw response from LLM
            
        Returns:
            True if response is valid JSON with required fields
        """
        try:
            data = json.loads(response_text)
            
            # Quick structural validation
            return (
                isinstance(data, dict) and
                'intent' in data and 'deception_indicators' in data and 'risk_score' in data and
                isinstance(data['intent'], dict) and 'primary' in data['intent'] and
                isinstance(data['risk_score'], dict) and 'score' in data['risk_score'] and
                isinstance(data['risk_score']['score'], int) and
                1 <= data['risk_score']['score'] <= 10
            )
            
        except (json.JSONDecodeError, KeyError, TypeError):
            return False
    
    def extract_json_from_response(self, response: str) -> str:
        """
        Fast JSON extraction from LLM response
        
        Args:
            response: Raw LLM response
            
        Returns:
            Extracted JSON string
        """
        # Quick JSON boundary detection
        start = response.find('{')
        if start == -1:
            return response.strip()
        
        # Find matching closing brace
        brace_count = 0
        end = start
        
        for i, char in enumerate(response[start:], start):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break
        
        return response[start:end] if end > start else response.strip()
    
    def enhance_analysis_with_mitre(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance analysis result with detailed MITRE ATT&CK context
        
        Args:
            analysis_result: Raw analysis result from LLM
            
        Returns:
            Enhanced analysis with MITRE ATT&CK details
        """
        try:
            # Get MITRE techniques from the analysis (access Pydantic model attribute)
            mitre_data = getattr(analysis_result, 'mitre_attack', None)
            
            if mitre_data and hasattr(mitre_data, 'techniques') and mitre_data.techniques:
                # Analyze and enhance with detailed MITRE context
                detailed_techniques = self.mitre_service.analyze_email_techniques(analysis_result)
                
                # Get defensive recommendations
                recommendations = self.mitre_service.get_technique_recommendations(detailed_techniques)
                
                # Build enhanced attack narrative
                enhanced_narrative = self.mitre_service.build_attack_narrative(detailed_techniques)
                
                # Create enhanced MITRE data and update the analysis result
                from ..models.analysis_models import MitreAttackAnalysis
                enhanced_mitre = MitreAttackAnalysis(
                    techniques=mitre_data.techniques,
                    tactics=mitre_data.tactics,
                    attack_narrative=enhanced_narrative,
                    confidence_score=mitre_data.confidence_score
                )
                
                # Update the analysis result with enhanced MITRE data
                analysis_result.mitre_attack = enhanced_mitre
            
            return analysis_result
            
        except Exception as e:
            # If MITRE enhancement fails, return original analysis without modification
            from ..utils.logging import get_secure_logger
            logger = get_secure_logger(__name__)
            logger.warning(f"MITRE enhancement failed: {str(e)}")
            return analysis_result
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for analysis"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'