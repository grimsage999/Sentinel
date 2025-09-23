#!/usr/bin/env python3
"""
API Key Testing Script for PhishContext AI
Tests all configured API keys to ensure they're working properly.
"""

import os
import asyncio
import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def test_openai_key():
    """Test OpenAI API key"""
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key or api_key == 'your_openai_api_key_here':
        return False, "No OpenAI API key configured"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=10.0
            )
            if response.status_code == 200:
                return True, "OpenAI API key is valid"
            else:
                return False, f"OpenAI API error: {response.status_code}"
    except Exception as e:
        return False, f"OpenAI API connection error: {str(e)}"

async def test_anthropic_key():
    """Test Anthropic API key"""
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key or api_key == 'your_anthropic_api_key_here':
        return False, "No Anthropic API key configured"
    
    try:
        async with httpx.AsyncClient() as client:
            # Test with a simple message
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Hello"}]
                },
                timeout=10.0
            )
            if response.status_code == 200:
                return True, "Anthropic API key is valid"
            else:
                return False, f"Anthropic API error: {response.status_code}"
    except Exception as e:
        return False, f"Anthropic API connection error: {str(e)}"

async def test_google_key():
    """Test Google Gemini API key"""
    api_key = os.getenv('GOOGLE_API_KEY')
    if not api_key or api_key == 'your_google_api_key_here' or api_key == 'your_actual_google_api_key_here':
        return False, "No Google API key configured"
    
    try:
        import google.generativeai as genai
        
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Test with a simple prompt
        response = model.generate_content("Hello")
        
        if response and response.text:
            return True, "Google Gemini API key is valid"
        else:
            return False, "Google Gemini API returned empty response"
            
    except Exception as e:
        return False, f"Google Gemini API error: {str(e)}"

async def test_virustotal_key():
    """Test VirusTotal API key"""
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key or api_key == 'your_virustotal_api_key_here':
        return False, "No VirusTotal API key configured"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.virustotal.com/api/v3/users/current",
                headers={"x-apikey": api_key},
                timeout=10.0
            )
            if response.status_code == 200:
                return True, "VirusTotal API key is valid"
            else:
                return False, f"VirusTotal API error: {response.status_code}"
    except Exception as e:
        return False, f"VirusTotal API connection error: {str(e)}"

async def main():
    """Run all API key tests"""
    print("🔑 Testing API Keys for PhishContext AI")
    print("=" * 50)
    
    # Test OpenAI
    print("Testing OpenAI API key...")
    openai_valid, openai_msg = await test_openai_key()
    print(f"✅ {openai_msg}" if openai_valid else f"❌ {openai_msg}")
    
    # Test Anthropic
    print("\nTesting Anthropic API key...")
    anthropic_valid, anthropic_msg = await test_anthropic_key()
    print(f"✅ {anthropic_msg}" if anthropic_valid else f"❌ {anthropic_msg}")
    
    # Test Google Gemini
    print("\nTesting Google Gemini API key...")
    google_valid, google_msg = await test_google_key()
    print(f"✅ {google_msg}" if google_valid else f"❌ {google_msg}")
    
    # Test VirusTotal
    print("\nTesting VirusTotal API key...")
    vt_valid, vt_msg = await test_virustotal_key()
    print(f"✅ {vt_msg}" if vt_valid else f"❌ {vt_msg}")
    
    print("\n" + "=" * 50)
    
    # Summary
    total_configured = sum([openai_valid, anthropic_valid, google_valid, vt_valid])
    llm_providers = sum([openai_valid, anthropic_valid, google_valid])
    
    if total_configured >= 1:
        print(f"🎉 {total_configured}/4 API keys are working!")
        if llm_providers > 0:
            print(f"✅ You have {llm_providers} LLM provider(s) configured - the system should work!")
        if not vt_valid:
            print("⚠️  VirusTotal is optional but recommended for IOC analysis")
    else:
        print("❌ No working API keys found. Please configure at least one LLM provider.")
        print("\nTo add API keys:")
        print("1. Edit backend/.env file")
        print("2. Replace placeholder values with your actual API keys")
        print("3. Restart the backend server")

if __name__ == "__main__":
    asyncio.run(main())