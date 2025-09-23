#!/usr/bin/env python3
"""
Debug Analysis Route
Tests the analysis route step by step to find where it hangs
"""

import asyncio
import sys
import os
sys.path.append('/Users/kelvin/Desktop/kelveloper/IBM_FISHING/backend')

from dotenv import load_dotenv
load_dotenv()

from app.models.analysis_models import EmailAnalysisRequest, AnalysisOptions
from app.api.dependencies import get_analysis_services

async def debug_analysis_route():
    """Debug the analysis route step by step"""
    print("🔧 Debug Analysis Route")
    print("=" * 40)
    
    # Step 1: Create request
    print("1. Creating analysis request...")
    try:
        request_data = {
            "emailContent": "From: test@example.com\nSubject: Hello\n\nHello world",
            "analysisOptions": {
                "includeIOCs": False,
                "confidenceThreshold": 0.5
            }
        }
        
        analysis_request = EmailAnalysisRequest(**request_data)
        print(f"✅ Request created: {len(analysis_request.email_content)} chars")
    except Exception as e:
        print(f"❌ Request creation failed: {str(e)}")
        return False
    
    # Step 2: Get services
    print("\n2. Getting analysis services...")
    try:
        services = get_analysis_services()
        print(f"✅ Services loaded: {list(services.keys())}")
    except Exception as e:
        print(f"❌ Services failed: {str(e)}")
        return False
    
    # Step 3: Test email parsing
    print("\n3. Testing email parsing...")
    try:
        email_headers, email_body = services["email_parser"].parse_email(analysis_request.email_content)
        print(f"✅ Email parsed: Subject='{email_headers.subject}'")
    except Exception as e:
        print(f"❌ Email parsing failed: {str(e)}")
        return False
    
    # Step 4: Test IOC extraction (if enabled)
    print("\n4. Testing IOC extraction...")
    try:
        if analysis_request.analysis_options and analysis_request.analysis_options.include_iocs:
            iocs = services["ioc_extractor"].extract_all_iocs(analysis_request.email_content)
            print(f"✅ IOCs extracted: {len(iocs.urls)} URLs")
        else:
            print("✅ IOC extraction skipped (disabled)")
            from app.models.analysis_models import IOCCollection
            iocs = IOCCollection()
    except Exception as e:
        print(f"❌ IOC extraction failed: {str(e)}")
        return False
    
    # Step 5: Test LLM analysis (this is likely where it hangs)
    print("\n5. Testing LLM analysis...")
    try:
        headers_dict = {
            "from": email_headers.from_address,
            "to": email_headers.to_addresses,
            "subject": email_headers.subject,
        }
        
        print("   Starting LLM analysis...")
        result = await services["llm_analyzer"].analyze_email(
            email_content=email_body or analysis_request.email_content,
            email_headers=headers_dict,
            iocs=iocs
        )
        print(f"✅ LLM analysis completed: Intent={result.intent.primary}, Score={result.risk_score.score}")
    except Exception as e:
        print(f"❌ LLM analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n🎉 All steps completed successfully!")
    return True

async def main():
    success = await debug_analysis_route()
    
    print("\n" + "=" * 40)
    if success:
        print("✅ Analysis route is working!")
    else:
        print("❌ Found issue in analysis route")

if __name__ == "__main__":
    asyncio.run(main())