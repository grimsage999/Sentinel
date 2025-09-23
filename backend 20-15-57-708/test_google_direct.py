#!/usr/bin/env python3
"""
Direct Google Gemini Test
Tests Google Gemini API directly to isolate any issues
"""

import os
import asyncio
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

async def test_google_direct():
    """Test Google Gemini directly"""
    api_key = os.getenv('GOOGLE_API_KEY')
    
    if not api_key:
        print("❌ No Google API key found")
        return False
    
    try:
        print("🔧 Configuring Google Gemini...")
        genai.configure(api_key=api_key)
        
        print("🤖 Creating model...")
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        print("📝 Testing simple prompt...")
        response = model.generate_content("Hello, respond with 'Working!'")
        
        print(f"✅ Response: {response.text}")
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

async def test_email_analysis_prompt():
    """Test with an email analysis prompt"""
    api_key = os.getenv('GOOGLE_API_KEY')
    
    if not api_key:
        print("❌ No Google API key found")
        return False
    
    try:
        print("\n🔧 Testing email analysis prompt...")
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = """
        Analyze this email for phishing indicators and respond with JSON:
        
        Email:
        From: test@example.com
        Subject: Test Email
        
        This is a test email.
        
        Respond with JSON format:
        {
          "intent": {"primary": "legitimate", "confidence": "high"},
          "risk_score": {"score": 1, "confidence": "high", "reasoning": "Test email"},
          "deception_indicators": []
        }
        """
        
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                max_output_tokens=1000,
            )
        )
        
        print(f"✅ Analysis Response: {response.text[:200]}...")
        return True
        
    except Exception as e:
        print(f"❌ Analysis Error: {str(e)}")
        return False

async def main():
    print("🧪 Direct Google Gemini Integration Test")
    print("=" * 50)
    
    # Test basic functionality
    basic_ok = await test_google_direct()
    
    # Test email analysis
    analysis_ok = await test_email_analysis_prompt()
    
    print("\n" + "=" * 50)
    print("📋 Test Results:")
    print(f"   Basic Gemini: {'✅ Working' if basic_ok else '❌ Failed'}")
    print(f"   Email Analysis: {'✅ Working' if analysis_ok else '❌ Failed'}")
    
    if basic_ok and analysis_ok:
        print("\n🎉 Google Gemini integration is working!")
    else:
        print("\n❌ Google Gemini integration has issues")

if __name__ == "__main__":
    asyncio.run(main())