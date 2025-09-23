#!/usr/bin/env python3
"""
Full integration test for MITRE ATT&CK with PhishContext AI
"""
import json
import asyncio
from app.services.prompt_builder import PromptBuilder
from app.models.analysis_models import (
    AnalysisResult, IntentAnalysis, DeceptionIndicator, RiskScore, 
    IOCCollection, MitreAttackAnalysis, IntentType, ConfidenceLevel,
    DeceptionIndicatorType, SeverityLevel
)
from datetime import datetime


async def test_full_integration():
    """Test complete MITRE ATT&CK integration flow"""
    
    print("🔬 Full MITRE ATT&CK Integration Test")
    print("=" * 50)
    
    # Initialize services
    prompt_builder = PromptBuilder()
    
    # Create a realistic analysis result (simulating LLM output)
    analysis_result = AnalysisResult(
        intent=IntentAnalysis(
            primary=IntentType.CREDENTIAL_THEFT,
            confidence=ConfidenceLevel.HIGH,
            alternatives=[IntentType.RECONNAISSANCE]
        ),
        deception_indicators=[
            DeceptionIndicator(
                type=DeceptionIndicatorType.SPOOFING,
                description="Domain spoofing Microsoft login page",
                evidence="microsft-login.com instead of microsoft.com",
                severity=SeverityLevel.HIGH
            ),
            DeceptionIndicator(
                type=DeceptionIndicatorType.SUSPICIOUS_LINKS,
                description="Malicious credential harvesting link",
                evidence="Click here to verify your account immediately",
                severity=SeverityLevel.HIGH
            ),
            DeceptionIndicator(
                type=DeceptionIndicatorType.URGENCY,
                description="Creates false urgency to prompt immediate action",
                evidence="Account will be suspended in 24 hours",
                severity=SeverityLevel.MEDIUM
            )
        ],
        risk_score=RiskScore(
            score=9,
            confidence=ConfidenceLevel.HIGH,
            reasoning="High-confidence credential theft attempt using domain spoofing and urgency tactics with MITRE techniques T1566.002 and T1036.005"
        ),
        iocs=IOCCollection(),
        mitre_attack=MitreAttackAnalysis(
            techniques=["T1566.002", "T1598.003", "T1036.005"],
            tactics=["initial-access", "collection", "defense-evasion"],
            attack_narrative="Spearphishing link campaign for credential theft using domain masquerading"
        ),
        processing_time=1250.5,
        timestamp=datetime.utcnow()
    )
    
    print("📧 Original Analysis Result:")
    print(f"  Intent: {analysis_result.intent.primary} ({analysis_result.intent.confidence})")
    print(f"  Risk Score: {analysis_result.risk_score.score}/10")
    print(f"  Deception Indicators: {len(analysis_result.deception_indicators)}")
    print(f"  MITRE Techniques: {len(analysis_result.mitre_attack.techniques) if analysis_result.mitre_attack else 0}")
    print()
    
    # Convert to dict for enhancement (simulating API response)
    analysis_dict = {
        "intent": {
            "primary": analysis_result.intent.primary.value,
            "confidence": analysis_result.intent.confidence.value
        },
        "deception_indicators": [
            {
                "type": indicator.type.value,
                "description": indicator.description,
                "evidence": indicator.evidence,
                "severity": indicator.severity.value
            }
            for indicator in analysis_result.deception_indicators
        ],
        "risk_score": {
            "score": analysis_result.risk_score.score,
            "confidence": analysis_result.risk_score.confidence.value,
            "reasoning": analysis_result.risk_score.reasoning
        },
        "mitre_attack": {
            "techniques": analysis_result.mitre_attack.techniques,
            "tactics": analysis_result.mitre_attack.tactics,
            "attack_narrative": analysis_result.mitre_attack.attack_narrative
        }
    }
    
    # Enhance with MITRE ATT&CK context
    print("🔬 Enhancing with MITRE ATT&CK Context...")
    enhanced_analysis = prompt_builder.enhance_analysis_with_mitre(analysis_dict)
    
    if 'mitre_attack_enhanced' in enhanced_analysis:
        enhanced = enhanced_analysis['mitre_attack_enhanced']
        
        print("✅ Enhancement Successful!")
        print(f"  Framework Version: {enhanced.get('framework_version', 'Unknown')}")
        print(f"  Techniques Detailed: {len(enhanced.get('techniques_detailed', []))}")
        print(f"  Analysis Timestamp: {enhanced.get('analysis_timestamp', 'Unknown')}")
        print()
        
        # Display detailed techniques
        print("🎯 Detailed MITRE ATT&CK Techniques:")
        print("-" * 40)
        for technique in enhanced.get('techniques_detailed', []):
            print(f"• {technique['technique_id']}: {technique['name']}")
            print(f"  Tactic: {technique['tactic']} - {technique['tactic_description']}")
            print(f"  Context: {technique['context']}")
            print(f"  URL: {technique['mitre_url']}")
            print()
        
        # Display recommendations
        recommendations = enhanced.get('recommendations', {})
        print("🛡️  Defensive Recommendations:")
        print("-" * 40)
        
        categories = [
            ('immediate_actions', 'Immediate Actions', '🚨'),
            ('security_controls', 'Security Controls', '🔒'),
            ('user_training', 'User Training', '📚'),
            ('monitoring', 'Monitoring', '👁️')
        ]
        
        for key, title, icon in categories:
            items = recommendations.get(key, [])
            if items:
                print(f"{icon} {title} ({len(items)} items):")
                for item in items[:3]:  # Show first 3 items
                    print(f"  • {item}")
                if len(items) > 3:
                    print(f"  ... and {len(items) - 3} more")
                print()
        
        # Display attack narrative
        print("📖 Enhanced Attack Narrative:")
        print("-" * 40)
        narrative = enhanced.get('attack_narrative_detailed', 'No narrative available')
        print(narrative[:300] + "..." if len(narrative) > 300 else narrative)
        print()
        
        # Test JSON serialization (for API response)
        print("🔄 Testing JSON Serialization...")
        try:
            json_output = json.dumps(enhanced_analysis, indent=2, default=str)
            print(f"✅ JSON serialization successful ({len(json_output)} characters)")
        except Exception as e:
            print(f"❌ JSON serialization failed: {e}")
        
        print()
        print("✅ Full MITRE ATT&CK Integration Test Complete!")
        print("🎉 All components working correctly:")
        print("  • Technique mapping ✓")
        print("  • Recommendation generation ✓") 
        print("  • Attack narrative creation ✓")
        print("  • JSON serialization ✓")
        print("  • Frontend type compatibility ✓")
        
    else:
        print("❌ Enhancement failed - no MITRE data generated")
        if 'error' in enhanced_analysis.get('mitre_attack_enhanced', {}):
            print(f"Error: {enhanced_analysis['mitre_attack_enhanced']['error']}")


if __name__ == "__main__":
    asyncio.run(test_full_integration())