#!/usr/bin/env python3
"""
Minimal Analysis Test
Tests the analysis pipeline step by step to isolate issues
"""

import asyncio
import sys
import os
sys.path.append('/Users/kelvin/Desktop/kelveloper/IBM_FISHING/backend')

from dotenv import load_dotenv
load_dotenv()

from app.services.llm_analyzer import LLMAnalyzer
from app.services.email_parser import EmailParser
from app.services.ioc_extractor import IOCExtractor

async def test_services_individually():
    """Test each service individually"""
    print("🧪 Testing Services Individually")
    print("=" * 50)
    
    # Test 1: Email Parser
    print("1. Testing Email Parser...")
    try:
        parser = EmailParser()
        sample_email = """From: test@example.com
To: victim@company.com
Subject: Test Email

This is a test email."""
        
        headers, body = parser.parse_email(sample_email)
        print(f"✅ Email Parser: Headers parsed, Subject: {headers.subject}")
    except Exception as e:
        print(f"❌ Email Parser Error: {str(e)}")
        return False
    
    # Test 2: IOC Extractor
    print("\n2. Testing IOC Extractor...")
    try:
        extractor = IOCExtractor()
        iocs = extractor.extract_all_iocs(sample_email)
        print(f"✅ IOC Extractor: Found {len(iocs.urls)} URLs, {len(iocs.ips)} IPs")
    except Exception as e:
        print(f"❌ IOC Extractor Error: {str(e)}")
        return False
    
    # Test 3: LLM Analyzer Initialization
    print("\n3. Testing LLM Analyzer Initialization...")
    try:
        analyzer = LLMAnalyzer()
        print(f"✅ LLM Analyzer: Initialized successfully")
        print(f"   Google client: {'✅' if analyzer.google_client else '❌'}")
        print(f"   OpenAI client: {'✅' if analyzer.openai_client else '❌'}")
        print(f"   Anthropic client: {'✅' if analyzer.anthropic_client else '❌'}")
    except Exception as e:
        print(f"❌ LLM Analyzer Error: {str(e)}")
        return False
    
    # Test 4: LLM Analysis
    print("\n4. Testing LLM Analysis...")
    try:
        result = await analyzer.analyze_email(
            email_content=sample_email,
            email_headers={"from": "test@example.com", "subject": "Test Email"},
            iocs=iocs
        )
        print(f"✅ LLM Analysis: Completed successfully")
        print(f"   Intent: {result.intent.primary}")
        print(f"   Risk Score: {result.risk_score.score}")
        print(f"   Processing Time: {result.processing_time:.2f}s")
    except Exception as e:
        print(f"❌ LLM Analysis Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

async def main():
    print("🔧 Minimal Analysis Pipeline Test")
    print("=" * 50)
    
    success = await test_services_individually()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All services working correctly!")
        print("The issue might be in the FastAPI integration or middleware.")
    else:
        print("❌ Found issues in the service pipeline.")

if __name__ == "__main__":
    asyncio.run(main())