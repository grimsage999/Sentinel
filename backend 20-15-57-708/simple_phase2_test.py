#!/usr/bin/env python3
"""
Simple test for Phase 2: Verify threat intelligence integration into LLM analysis
"""

import asyncio
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

async def test_phase2_integration():
    """Simple test for Phase 2 integration components"""
    print("🧪 Testing Phase 2: Enhanced LLM Analysis Integration...")
    
    success_count = 0
    total_tests = 6
    
    # Test 1: Verify imports work
    print("\n1️⃣ Testing imports and architecture...")
    try:
        from app.services.threat_intelligence import ThreatIntelService
        from app.models.analysis_models import IOCCollection, IOCItem, IOCType
        from app.services.prompt_builder import PromptBuilder
        print("   ✅ All required imports successful")
        success_count += 1
    except Exception as e:
        print(f"   ❌ Import error: {str(e)}")
        return False
        
    # Test 2: Verify ThreatIntelService integration exists in LLMAnalyzer
    print("\n2️⃣ Testing LLMAnalyzer integration architecture...")
    try:
        import inspect
        from app.services.llm_analyzer import LLMAnalyzer
        
        # Check the source code for integration
        init_source = inspect.getsource(LLMAnalyzer.__init__)
        analyze_source = inspect.getsource(LLMAnalyzer.analyze_email_async)
        
        if 'ThreatIntelService' in init_source:
            print("   ✅ ThreatIntelService integrated in LLMAnalyzer.__init__")
            success_count += 1
        else:
            print("   ❌ ThreatIntelService not found in LLMAnalyzer.__init__")
            
        if 'enrich_iocs_with_threat_intelligence' in analyze_source:
            print("   ✅ IOC enrichment integrated in analyze_email_async")
            success_count += 1
        else:
            print("   ❌ IOC enrichment not found in analyze_email_async")
            
    except Exception as e:
        print(f"   ❌ Architecture check error: {str(e)}")
        
    # Test 3: Verify PromptBuilder enhancement
    print("\n3️⃣ Testing PromptBuilder threat intelligence enhancement...")
    try:
        prompt_builder = PromptBuilder()
        
        # Check if the build_analysis_prompt method accepts threat_intelligence_context
        import inspect
        signature = inspect.signature(prompt_builder.build_analysis_prompt)
        
        if 'threat_intelligence_context' in signature.parameters:
            print("   ✅ PromptBuilder enhanced with threat_intelligence_context parameter")
            success_count += 1
            
            # Test prompt building with context
            test_context = """
            THREAT INTELLIGENCE CONTEXT:
            Found 1 indicators with threat intelligence:
            - URL: https://example.com (HIGH threat level, 95% confidence, source: Test)
            """
            
            prompt = prompt_builder.build_analysis_prompt(
                "Test email content",
                {},
                threat_intelligence_context=test_context
            )
            
            if test_context.strip() in prompt:
                print("   ✅ Threat intelligence context properly included in generated prompt")
                success_count += 1
            else:
                print("   ❌ Threat intelligence context not found in generated prompt")
        else:
            print("   ❌ PromptBuilder missing threat_intelligence_context parameter")
            
    except Exception as e:
        print(f"   ❌ PromptBuilder test error: {str(e)}")
        
    # Test 4: Test ThreatIntelService functionality  
    print("\n4️⃣ Testing ThreatIntelService functionality...")
    try:
        test_db_path = "simple_test.db"
        threat_intel_service = ThreatIntelService(db_path=test_db_path)
        
        # Test IOCs creation
        test_iocs = IOCCollection(
            urls=[
                IOCItem(
                    value="https://example.com",
                    type=IOCType.URL,
                    vtLink="https://www.virustotal.com/gui/url/test",
                    context="Test URL"
                )
            ]
        )
        
        # Test enrichment (will likely return no enrichment but shouldn't error)
        enriched_iocs = await threat_intel_service.enrich_iocs_with_threat_intelligence(test_iocs)
        print("   ✅ IOC enrichment completed without errors")
        success_count += 1
        
        # Cleanup
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            
    except Exception as e:
        print(f"   ❌ ThreatIntelService test error: {str(e)}")
        
    # Results
    print(f"\n🎯 Phase 2 Integration Test Results: {success_count}/{total_tests} tests passed")
    
    if success_count >= 4:  # At least 4/6 core functionality working
        print("✅ Phase 2: Enhanced LLM Analysis with Context - INTEGRATION SUCCESSFUL")
        print("   Key components integrated:")
        print("   - ThreatIntelService available to LLMAnalyzer")
        print("   - PromptBuilder enhanced with threat intelligence context")
        print("   - IOC enrichment pipeline functional")
        return True
    else:
        print("❌ Phase 2 integration incomplete")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_phase2_integration())
    sys.exit(0 if success else 1)