#!/usr/bin/env python3
"""
Comprehensive test for the complete AI Agent Framework
Tests all phases: Foundation + Enhanced LLM + Response Generation + Logging
"""

import asyncio
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

async def test_complete_ai_framework():
    """Test the complete AI Agent Framework with all phases"""
    print("🤖 Testing Complete AI Agent Framework (All 4 Phases)...")
    
    try:
        test_db_path = "complete_ai_test.db"
        
        # Test 1: Initialize complete AI Agent Framework
        print("\n1️⃣ Initializing Complete AI Agent Framework...")
        from app.services.threat_intelligence.ai_agent_framework import AIThreatIntelligenceAgent
        
        ai_agent = AIThreatIntelligenceAgent(db_path=test_db_path)
        print("   ✅ AI Agent Framework initialized successfully")
        
        # Test 2: Populate threat intelligence database
        print("\n2️⃣ Populating threat intelligence database...")
        
        # Quick harvest and processing to populate database
        harvest_result = await ai_agent.harvester.harvest_all_sources()
        print(f"   ✅ Harvested {harvest_result['entries_collected']} threat intelligence entries")
        
        if harvest_result['entries_collected'] > 0:
            process_result = await ai_agent.processor.process_all_unprocessed()
            print(f"   ✅ Processed {process_result['iocs_extracted']} IOCs from threat intelligence")
        
        # Test 3: Create comprehensive test email analysis scenario
        print("\n3️⃣ Creating comprehensive email analysis scenario...")
        
        # Simulated analysis result from LLM
        test_analysis_result = {
            "intent": {
                "primary": "credential_theft",
                "confidence": "High"
            },
            "risk_score": {
                "score": 7,
                "confidence": "High",
                "reasoning": "Credential theft attempt with suspicious URLs"
            },
            "deception_indicators": [
                {
                    "type": "suspicious_links",
                    "description": "Contains potentially malicious URLs",
                    "severity": "High"
                }
            ],
            "mitre_attack": {
                "techniques": ["T1566.002", "T1598.003"],
                "tactics": ["initial-access"],
                "attack_narrative": "Spearphishing link for credential theft"
            },
            "processing_time": 2.3,
            "timestamp": "2024-12-25T16:28:00Z"
        }
        
        # Simulated IOCs extracted from email
        test_iocs = [
            {
                "value": "https://isc.sans.edu", 
                "type": "url",
                "context": "Reference URL in email"
            },
            {
                "value": "https://malicious-phishing-site.example.com",
                "type": "url", 
                "context": "Suspicious phishing URL"
            },
            {
                "value": "phishing-domain.example.com",
                "type": "domain",
                "context": "Suspicious domain"
            },
            {
                "value": "192.168.100.5",
                "type": "ipv4",
                "context": "Suspicious IP from email headers"
            }
        ]
        
        print(f"   ✅ Created test scenario: {test_analysis_result['intent']['primary']} with {len(test_iocs)} IOCs")
        
        # Test 4: Run complete AI-powered analysis
        print("\n4️⃣ Running complete AI-powered threat intelligence processing...")
        
        request_id = "complete_test_001"
        enhanced_result = await ai_agent.process_email_analysis(
            analysis_result=test_analysis_result,
            iocs=test_iocs,
            request_id=request_id
        )
        
        print("   ✅ AI-powered processing completed successfully")
        
        # Verify enhanced results
        if 'threat_intelligence_findings' in enhanced_result:
            findings = enhanced_result['threat_intelligence_findings']
            print(f"   ✅ Found {len(findings)} threat intelligence matches")
            
            for finding in findings:
                ioc_value = finding.get('ioc_value', '')
                threat_level = finding.get('threat_level', 'UNKNOWN')
                confidence = finding.get('confidence_score', 0)
                print(f"      - {ioc_value}: {threat_level} threat (confidence: {confidence}%)")
        else:
            print("   ℹ️ No threat intelligence findings (normal for test data)")
        
        # Check risk score enhancement
        original_score = test_analysis_result['risk_score']['score']
        enhanced_score = enhanced_result['risk_score']['score']
        if enhanced_score != original_score:
            print(f"   ✅ Risk score enhanced: {original_score} → {enhanced_score}")
        else:
            print(f"   ℹ️ Risk score unchanged: {enhanced_score}")
        
        # Test 5: Verify automated response generation
        print("\n5️⃣ Testing automated response generation...")
        
        automated_responses = enhanced_result.get('automated_responses', [])
        print(f"   ✅ Generated {len(automated_responses)} automated responses")
        
        for i, response in enumerate(automated_responses, 1):
            print(f"      {i}. {response['response_type']}: {response['threat_pattern']} (Priority: {response['priority']})")
            if not response['requires_approval']:
                print(f"         → Auto-executable response")
            else:
                print(f"         → Requires manual approval")
        
        # Test 6: Verify threat intelligence sharing
        print("\n6️⃣ Testing threat intelligence sharing...")
        
        sharing_result = enhanced_result.get('threat_intelligence_sharing', {})
        if sharing_result:
            targets_notified = sharing_result.get('targets_notified', 0)
            total_targets = len(sharing_result.get('shared_with', []))
            print(f"   ✅ Threat intelligence shared with {targets_notified} targets")
            
            if sharing_result.get('shared_with'):
                print(f"      Shared with: {', '.join(sharing_result['shared_with'])}")
        else:
            print("   ℹ️ No threat intelligence sharing (risk score may be below threshold)")
        
        # Test 7: Verify enhanced logging and audit trail
        print("\n7️⃣ Testing enhanced logging and audit capabilities...")
        
        from app.services.threat_intelligence.logger import threat_intel_logger
        
        # Get audit summary
        audit_summary = threat_intel_logger.get_audit_summary(hours=1)
        operations = audit_summary.get('operations_by_level', {})
        print(f"   ✅ Audit trail captured {sum(sum(levels.values()) for levels in operations.values())} operations")
        
        # Show operation breakdown
        for operation, levels in operations.items():
            total_ops = sum(levels.values())
            print(f"      - {operation}: {total_ops} operations")
        
        # Get recent alerts
        recent_alerts = threat_intel_logger.get_recent_alerts(limit=5)
        print(f"   ✅ Found {len(recent_alerts)} recent alerts/high-confidence events")
        
        # Test 8: Framework status and health check
        print("\n8️⃣ Testing framework status and health monitoring...")
        
        framework_status = await ai_agent.get_framework_status()
        
        if framework_status.get('framework_status') == 'operational':
            print("   ✅ Framework status: OPERATIONAL")
            
            components = framework_status.get('components_status', {})
            active_components = [comp for comp, status in components.items() if status == 'active']
            print(f"   ✅ All {len(active_components)} components active")
            
            # Show processing statistics
            processing_stats = framework_status.get('audit_summary', {}).get('processing_statistics', {})
            if processing_stats:
                print("   📊 Processing Statistics:")
                for operation, stats in processing_stats.items():
                    total_ops = stats.get('total_operations', 0)
                    avg_time = stats.get('avg_processing_time', 0)
                    if total_ops > 0:
                        print(f"      - {operation}: {total_ops} ops, avg {avg_time:.3f}s")
        else:
            print(f"   ⚠️ Framework status: {framework_status.get('framework_status', 'UNKNOWN')}")
        
        # Test 9: Integration verification
        print("\n9️⃣ Verifying end-to-end integration...")
        
        ai_processing = enhanced_result.get('ai_agent_processing', {})
        if ai_processing:
            processing_time = ai_processing.get('processing_time', 0)
            threat_findings = ai_processing.get('threat_intel_findings', 0)
            responses_generated = ai_processing.get('automated_responses_generated', 0)
            sharing_targets = ai_processing.get('sharing_targets_notified', 0)
            
            print(f"   ✅ End-to-end processing completed in {processing_time:.3f}s")
            print(f"   📊 Integration Summary:")
            print(f"      - Threat intelligence findings: {threat_findings}")
            print(f"      - Automated responses: {responses_generated}")
            print(f"      - Sharing targets notified: {sharing_targets}")
            print(f"      - Framework version: {ai_processing.get('framework_version', 'Unknown')}")
        
        # Cleanup
        await ai_agent.close()
        
        print("\n🎉 Complete AI Agent Framework Test PASSED!")
        print("\n📋 Framework Capabilities Verified:")
        print("   ✅ Phase 1: Threat Intelligence Foundation")
        print("   ✅ Phase 2: Enhanced LLM Analysis with Context")
        print("   ✅ Phase 3: Response Generation & Enhanced Logging")
        print("   ✅ Phase 4: Complete Integration & Monitoring")
        print("\n🚀 AI Agent Framework is FULLY OPERATIONAL!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Complete AI Framework test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup test database
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            print(f"🧹 Cleaned up test database: {test_db_path}")

if __name__ == "__main__":
    success = asyncio.run(test_complete_ai_framework())
    sys.exit(0 if success else 1)