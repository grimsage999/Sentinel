#!/usr/bin/env python3
"""
Email Analysis Test Script
Tests the email analysis endpoint with sample data
"""

import asyncio
import httpx
import json

# Sample phishing email for testing
SAMPLE_PHISHING_EMAIL = """From: security@amazon-security.com
To: victim@company.com
Subject: Urgent: Your Amazon Account Has Been Compromised
Date: Mon, 1 Jan 2024 12:00:00 +0000

Dear Customer,

We have detected suspicious activity on your Amazon account. Your account has been temporarily suspended for your protection.

To restore access to your account, please verify your identity immediately by clicking the link below:

https://amazon-security-verification.com/verify-account

You have 24 hours to complete this verification, or your account will be permanently closed.

Thank you,
Amazon Security Team"""

async def test_health_endpoint():
    """Test the health endpoint"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:8000/api/health", timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                print("✅ Health check passed")
                print(f"   Status: {data.get('status')}")
                print(f"   Services: {data.get('services', {})}")
                return True
            else:
                print(f"❌ Health check failed: {response.status_code}")
                return False
    except Exception as e:
        print(f"❌ Health check error: {str(e)}")
        return False

async def test_analysis_endpoint():
    """Test the analysis endpoint"""
    try:
        async with httpx.AsyncClient() as client:
            payload = {
                "emailContent": SAMPLE_PHISHING_EMAIL,
                "analysisOptions": {
                    "includeIOCs": True,
                    "confidenceThreshold": 0.5
                }
            }
            
            print("🔍 Testing email analysis endpoint...")
            print("📧 Sample email content:")
            print("   Subject: Urgent: Your Amazon Account Has Been Compromised")
            print("   From: security@amazon-security.com")
            print("   Contains suspicious URL: amazon-security-verification.com")
            
            response = await client.post(
                "http://localhost:8000/api/analyze",
                json=payload,
                timeout=30.0
            )
            
            print(f"\n📊 Response Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Analysis completed successfully!")
                
                if data.get('success'):
                    result = data.get('data', {})
                    print(f"   Risk Score: {result.get('risk_score', {}).get('score', 'N/A')}")
                    print(f"   Intent: {result.get('intent', {}).get('primary', 'N/A')}")
                    print(f"   Processing Time: {result.get('processing_time', 'N/A')}ms")
                else:
                    print(f"   Analysis failed: {data.get('error', {}).get('message', 'Unknown error')}")
                
                return True
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', {}).get('message', 'Unknown error')
                    print(f"❌ Analysis failed: {error_msg}")
                except:
                    print(f"❌ Analysis failed: HTTP {response.status_code}")
                return False
                
    except Exception as e:
        print(f"❌ Analysis test error: {str(e)}")
        return False

async def test_frontend_connection():
    """Test if frontend is accessible"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:3000", timeout=5.0)
            if response.status_code == 200:
                print("✅ Frontend is accessible at http://localhost:3000")
                return True
            else:
                print(f"❌ Frontend returned status: {response.status_code}")
                return False
    except Exception as e:
        print(f"❌ Frontend connection error: {str(e)}")
        return False

async def main():
    """Run all tests"""
    print("🧪 PhishContext AI System Test")
    print("=" * 50)
    
    # Test frontend
    print("1. Testing Frontend Connection...")
    frontend_ok = await test_frontend_connection()
    
    print("\n2. Testing Backend Health...")
    health_ok = await test_health_endpoint()
    
    print("\n3. Testing Email Analysis...")
    analysis_ok = await test_analysis_endpoint()
    
    print("\n" + "=" * 50)
    print("📋 Test Summary:")
    print(f"   Frontend: {'✅ Working' if frontend_ok else '❌ Failed'}")
    print(f"   Backend Health: {'✅ Working' if health_ok else '❌ Failed'}")
    print(f"   Email Analysis: {'✅ Working' if analysis_ok else '❌ Failed'}")
    
    if frontend_ok and health_ok:
        print("\n🎉 System is ready for testing!")
        print("   → Open http://localhost:3000 in your browser")
        print("   → Paste the sample email and click 'Analyze Email'")
        
        if not analysis_ok:
            print("\n⚠️  Analysis failed - likely due to missing API keys")
            print("   → Follow API_SETUP_GUIDE.md to configure API keys")
            print("   → Or test the UI without real analysis")
    else:
        print("\n❌ System setup issues detected")
        if not frontend_ok:
            print("   → Start frontend: cd frontend && npm run dev")
        if not health_ok:
            print("   → Start backend: cd backend && source venv/bin/activate && uvicorn app.main:app --reload")

if __name__ == "__main__":
    asyncio.run(main())