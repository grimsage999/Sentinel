#!/usr/bin/env python3
"""
Simple API Test
Tests the API endpoint with minimal complexity
"""

import asyncio
import httpx
import json

async def test_simple_analysis():
    """Test with the simplest possible email"""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            payload = {
                "emailContent": "From: test@example.com\nSubject: Hello\n\nHello world",
                "analysisOptions": {
                    "includeIOCs": False,
                    "confidenceThreshold": 0.5
                }
            }
            
            print("🔍 Testing simple email analysis...")
            print("📧 Email: Hello world message")
            
            response = await client.post(
                "http://localhost:8000/api/analyze",
                json=payload
            )
            
            print(f"📊 Response Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Analysis completed!")
                
                if data.get('success'):
                    result = data.get('data', {})
                    print(f"   Risk Score: {result.get('risk_score', {}).get('score', 'N/A')}")
                    print(f"   Intent: {result.get('intent', {}).get('primary', 'N/A')}")
                else:
                    print(f"   Error: {data.get('error', {}).get('message', 'Unknown')}")
                
                return True
            else:
                try:
                    error_data = response.json()
                    print(f"❌ Error: {error_data}")
                except:
                    print(f"❌ HTTP Error: {response.status_code}")
                    print(f"   Response: {response.text}")
                return False
                
    except Exception as e:
        print(f"❌ Request error: {str(e)}")
        return False

async def main():
    print("🧪 Simple API Test")
    print("=" * 30)
    
    success = await test_simple_analysis()
    
    print("\n" + "=" * 30)
    if success:
        print("🎉 API is working!")
    else:
        print("❌ API has issues")

if __name__ == "__main__":
    asyncio.run(main())