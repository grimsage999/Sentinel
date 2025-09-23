#!/usr/bin/env python3
"""
Test script for MITRE ATT&CK integration
"""
import json
import asyncio
from app.services.mitre_attack_service import MitreAttackService
from app.services.prompt_builder import PromptBuilder


async def test_mitre_integration():
    """Test MITRE ATT&CK integration with sample analysis"""
    
    print("🔍 Testing MITRE ATT&CK Integration")
    print("=" * 50)
    
    # Initialize services
    mitre_service = MitreAttackService()
    prompt_builder = PromptBuilder()
    
    # Sample analysis result (simulating LLM output)
    sample_analysis = {
        "intent": {
            "primary": "credential_theft",
            "confidence": "high"
        },
        "deception_indicators": [
            {
                "type": "spoofing",
                "description": "Domain spoofing Microsoft login",
                "evidence": "microsft-login.com instead of microsoft.com",
                "severity": "high"
            },
            {
                "type": "suspicious_links",
                "description": "Malicious login link",
                "evidence": "Click here to verify your account",
                "severity": "high"
            }
        ],
        "risk_score": {
            "score": 9,
            "confidence": "high",
            "reasoning": "High-confidence credential theft attempt with domain spoofing"
        },
        "mitre_attack": {
            "techniques": ["T1566.002", "T1598.003", "T1036.005"],
            "tactics": ["initial-access", "collection", "defense-evasion"],
            "attack_narrative": "Spearphishing link for credential theft with domain masquerading"
        }
    }
    
    print("📧 Sample Analysis Result:")
    print(json.dumps(sample_analysis, indent=2))
    print()
    
    # Test MITRE technique analysis
    print("🎯 MITRE ATT&CK Technique Analysis:")
    print("-" * 40)
    
    techniques = mitre_service.analyze_email_techniques(sample_analysis)
    for technique in techniques:
        print(f"• {technique['technique_id']}: {technique['name']}")
        print(f"  Tactic: {technique['tactic']} - {technique['tactic_description']}")
        print(f"  Context: {technique['context']}")
        print(f"  URL: {technique['mitre_url']}")
        print()
    
    # Test recommendations
    print("🛡️  Defensive Recommendations:")
    print("-" * 40)
    
    recommendations = mitre_service.get_technique_recommendations(techniques)
    
    if recommendations['immediate_actions']:
        print("Immediate Actions:")
        for action in recommendations['immediate_actions']:
            print(f"  • {action}")
        print()
    
    if recommendations['security_controls']:
        print("Security Controls:")
        for control in recommendations['security_controls']:
            print(f"  • {control}")
        print()
    
    if recommendations['user_training']:
        print("User Training:")
        for training in recommendations['user_training']:
            print(f"  • {training}")
        print()
    
    if recommendations['monitoring']:
        print("Monitoring:")
        for monitor in recommendations['monitoring']:
            print(f"  • {monitor}")
        print()
    
    # Test attack narrative
    print("📖 Attack Narrative:")
    print("-" * 40)
    narrative = mitre_service.build_attack_narrative(techniques)
    print(narrative)
    print()
    
    # Test enhanced analysis
    print("🔬 Enhanced Analysis with MITRE:")
    print("-" * 40)
    
    enhanced_analysis = prompt_builder.enhance_analysis_with_mitre(sample_analysis)
    
    if 'mitre_attack_enhanced' in enhanced_analysis:
        enhanced = enhanced_analysis['mitre_attack_enhanced']
        
        print(f"Framework Version: {enhanced.get('framework_version', 'Unknown')}")
        print(f"Analysis Timestamp: {enhanced.get('analysis_timestamp', 'Unknown')}")
        print()
        
        print("Detailed Techniques:")
        for technique in enhanced.get('techniques_detailed', []):
            print(f"  • {technique['technique_id']}: {technique['name']}")
        print()
        
        print("Enhanced Attack Narrative:")
        print(enhanced.get('attack_narrative_detailed', 'No narrative available'))
        print()
    
    print("✅ MITRE ATT&CK Integration Test Complete!")


if __name__ == "__main__":
    asyncio.run(test_mitre_integration())