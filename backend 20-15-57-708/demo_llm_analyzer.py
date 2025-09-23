#!/usr/bin/env python3
"""
Demo script for LLM Analyzer functionality
This script demonstrates the LLM analyzer without requiring actual API keys
"""
import asyncio
import json
from datetime import datetime
from app.services.llm_analyzer import LLMAnalyzer
from app.services.prompt_builder import PromptBuilder
from app.models.analysis_models import IOCCollection


async def demo_prompt_builder():
    """Demonstrate the prompt builder functionality"""
    print("=== Prompt Builder Demo ===")
    
    builder = PromptBuilder()
    
    sample_email = """
From: security@microsoft-alerts.com
To: user@company.com
Subject: URGENT: Account Security Alert - Action Required

Dear Valued Customer,

Your Microsoft account has been flagged for suspicious activity. 
We have detected unauthorized access attempts from the following IP: 192.168.1.100

To secure your account immediately, please click the link below:
https://microsoft-security-center.net/verify-account?token=abc123

You have 24 hours to respond or your account will be permanently suspended.

Best regards,
Microsoft Security Team
    """
    
    sample_headers = {
        "From": "security@microsoft-alerts.com",
        "To": "user@company.com",
        "Subject": "URGENT: Account Security Alert - Action Required",
        "Date": "Mon, 15 Jan 2024 10:30:00 +0000",
        "Reply-To": "noreply@suspicious-domain.com"
    }
    
    prompt = builder.build_analysis_prompt(sample_email, sample_headers)
    
    print("Generated Prompt (first 500 chars):")
    print(prompt[:500] + "...")
    print()
    
    # Test response validation
    valid_response = {
        "intent": {
            "primary": "credential_theft",
            "confidence": "High"
        },
        "deception_indicators": [
            {
                "type": "spoofing",
                "description": "Domain impersonation",
                "evidence": "microsoft-alerts.com vs legitimate microsoft.com",
                "severity": "High"
            }
        ],
        "risk_score": {
            "score": 9,
            "confidence": "High",
            "reasoning": "Clear phishing attempt with domain spoofing"
        }
    }
    
    is_valid = builder.validate_response_format(json.dumps(valid_response))
    print(f"Response validation test: {'PASSED' if is_valid else 'FAILED'}")
    print()


def demo_response_parsing():
    """Demonstrate response parsing without actual LLM calls"""
    print("=== Response Parsing Demo ===")
    
    # Mock LLM response
    mock_response = json.dumps({
        "intent": {
            "primary": "credential_theft",
            "confidence": "High",
            "alternatives": ["reconnaissance"]
        },
        "deception_indicators": [
            {
                "type": "spoofing",
                "description": "Sender domain impersonation detected",
                "evidence": "microsoft-alerts.com mimics legitimate microsoft.com",
                "severity": "High"
            },
            {
                "type": "urgency",
                "description": "Time pressure tactics employed",
                "evidence": "24 hours to respond or account suspension",
                "severity": "Medium"
            },
            {
                "type": "suspicious_links",
                "description": "Suspicious redirect domain",
                "evidence": "microsoft-security-center.net is not legitimate Microsoft domain",
                "severity": "High"
            }
        ],
        "risk_score": {
            "score": 9,
            "confidence": "High",
            "reasoning": "Multiple high-severity deception indicators including domain spoofing, urgency tactics, and suspicious links. Clear credential theft attempt."
        }
    })
    
    # Simulate parsing (without actual LLM analyzer initialization)
    try:
        data = json.loads(mock_response)
        print("Successfully parsed mock LLM response:")
        print(f"Intent: {data['intent']['primary']} (Confidence: {data['intent']['confidence']})")
        print(f"Risk Score: {data['risk_score']['score']}/10")
        print(f"Deception Indicators: {len(data['deception_indicators'])}")
        
        for i, indicator in enumerate(data['deception_indicators'], 1):
            print(f"  {i}. {indicator['type'].title()}: {indicator['description']}")
        
        print()
        
    except Exception as e:
        print(f"Parsing failed: {e}")


def demo_configuration():
    """Demonstrate configuration validation"""
    print("=== Configuration Demo ===")
    
    from app.core.config import settings
    
    print("Current configuration:")
    print(f"Primary LLM Provider: {settings.primary_llm_provider}")
    print(f"Fallback LLM Provider: {settings.fallback_llm_provider}")
    print(f"LLM Timeout: {settings.llm_timeout_seconds}s")
    print(f"Max Retries: {settings.max_retries}")
    print(f"OpenAI Model: {settings.openai_model}")
    print(f"Anthropic Model: {settings.anthropic_model}")
    
    # Check API key configuration (without exposing keys)
    openai_configured = bool(settings.openai_api_key)
    anthropic_configured = bool(settings.anthropic_api_key)
    
    print(f"OpenAI API Key Configured: {openai_configured}")
    print(f"Anthropic API Key Configured: {anthropic_configured}")
    print()


async def main():
    """Run all demos"""
    print("PhishContext AI - LLM Analyzer Demo")
    print("=" * 50)
    print()
    
    demo_configuration()
    await demo_prompt_builder()
    demo_response_parsing()
    
    print("Demo completed successfully!")
    print()
    print("To use the LLM analyzer with real API calls:")
    print("1. Set your API keys in the .env file")
    print("2. Use the LLMAnalyzer.analyze_email() method")
    print("3. The analyzer will handle provider fallback and retry logic automatically")


if __name__ == "__main__":
    asyncio.run(main())