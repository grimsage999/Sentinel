#!/bin/bash

echo "================================================================="
echo "        ANALYSIS CONSISTENCY & CORRELATION TEST SUITE"
echo "================================================================="

# Function to test analysis consistency
test_analysis() {
    local name="$1"
    local email_content="$2"
    local expected_intent="$3"
    
    echo -e "\n🔍 Testing: $name"
    echo "   Expected Intent: $expected_intent"
    echo "   ----------------------------------------"
    
    result=$(curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d "{\"email_content\": \"$email_content\"}")
    
    # Extract key metrics
    intent=$(echo "$result" | jq -r '.data.intent.primary')
    risk_score=$(echo "$result" | jq -r '.data.riskScore.score')
    confidence=$(echo "$result" | jq -r '.data.intent.confidence')
    deception_count=$(echo "$result" | jq '.data.deceptionIndicators | length')
    deception_types=$(echo "$result" | jq -r '[.data.deceptionIndicators[].type] | join(", ")')
    ioc_urls=$(echo "$result" | jq '.data.iocs.urls | length')
    ioc_ips=$(echo "$result" | jq '.data.iocs.ips | length')
    ioc_domains=$(echo "$result" | jq '.data.iocs.domains | length')
    mitre_techniques=$(echo "$result" | jq -r '.data.mitreAttack.techniques | join(", ")')
    mitre_tactics=$(echo "$result" | jq -r '.data.mitreAttack.tactics | join(", ")')
    
    # Display results in organized format
    echo "   📊 ANALYSIS RESULTS:"
    echo "      Intent: $intent ($confidence confidence)"
    echo "      Risk Score: $risk_score/10"
    echo "      Deception Indicators: $deception_count [$deception_types]"
    echo "      IOCs: URLs=$ioc_urls, IPs=$ioc_ips, Domains=$ioc_domains"
    echo "      MITRE: $mitre_techniques [$mitre_tactics]"
    
    # Consistency Check
    echo "   ✅ CONSISTENCY CHECK:"
    
    # Check Intent-Risk correlation
    if [[ "$intent" == "credential_theft" || "$intent" == "malware_delivery" || "$intent" == "wire_transfer" ]]; then
        if [[ $risk_score -ge 6 ]]; then
            echo "      ✓ Intent-Risk correlation: HIGH threat → HIGH risk ($risk_score/10)"
        else
            echo "      ⚠ Intent-Risk mismatch: HIGH threat → LOW risk ($risk_score/10)"
        fi
    elif [[ "$intent" == "legitimate" ]]; then
        if [[ $risk_score -le 4 ]]; then
            echo "      ✓ Intent-Risk correlation: LEGITIMATE → LOW risk ($risk_score/10)"
        else
            echo "      ⚠ Intent-Risk mismatch: LEGITIMATE → HIGH risk ($risk_score/10)"
        fi
    else
        echo "      ? Intent-Risk correlation: $intent → $risk_score/10 (ambiguous)"
    fi
    
    # Check Deception-Risk correlation
    if [[ $deception_count -ge 3 && $risk_score -ge 7 ]]; then
        echo "      ✓ Deception-Risk correlation: Many indicators ($deception_count) → HIGH risk ($risk_score/10)"
    elif [[ $deception_count -le 1 && $risk_score -le 4 ]]; then
        echo "      ✓ Deception-Risk correlation: Few indicators ($deception_count) → LOW risk ($risk_score/10)"
    elif [[ $deception_count -eq 0 && "$intent" == "legitimate" ]]; then
        echo "      ✓ Deception-Intent correlation: No deception → LEGITIMATE intent"
    else
        echo "      ? Deception-Risk correlation: $deception_count indicators → $risk_score/10 risk"
    fi
    
    # Check MITRE-Intent correlation
    if [[ "$intent" == "credential_theft" && "$mitre_techniques" == *"T1566.002"* ]]; then
        echo "      ✓ MITRE-Intent correlation: Credential theft → Spearphishing Link"
    elif [[ "$intent" == "malware_delivery" && "$mitre_techniques" == *"T1566.001"* ]]; then
        echo "      ✓ MITRE-Intent correlation: Malware delivery → Spearphishing Attachment"
    elif [[ "$intent" == "legitimate" && "$mitre_techniques" == "" ]]; then
        echo "      ✓ MITRE-Intent correlation: Legitimate → No techniques"
    else
        echo "      ? MITRE-Intent correlation: $intent → [$mitre_techniques]"
    fi
    
    # Check IOC-Deception correlation
    total_iocs=$((ioc_urls + ioc_ips + ioc_domains))
    if [[ $total_iocs -gt 0 && "$deception_types" == *"suspicious_links"* ]]; then
        echo "      ✓ IOC-Deception correlation: IOCs found ($total_iocs) → Suspicious links detected"
    elif [[ $total_iocs -eq 0 && "$intent" == "legitimate" ]]; then
        echo "      ✓ IOC-Intent correlation: No IOCs → Legitimate email"
    else
        echo "      ? IOC-Deception correlation: $total_iocs IOCs → [$deception_types]"
    fi
}

# Test Cases
test_analysis "HIGH RISK - Credential Theft" \
"From: security@paypal-verification.com\nTo: user@example.com\nSubject: Urgent: Verify Your Account Now!\n\nYour PayPal account has been suspended. Click here to verify: http://paypal-fake.com/login\n\nPayPal Security Team" \
"credential_theft"

test_analysis "MEDIUM RISK - Security Review" \
"From: security-team@gmail.com\nTo: employee@company.com\nSubject: Account Security Review Required\n\nWe are conducting a routine security review.\n\nPlease confirm your account details: https://account-verification.secure-portal.net/verify\n\nThis must be completed within 7 days." \
"credential_theft"

test_analysis "LOW RISK - Legitimate Email" \
"From: colleague@company.com\nTo: user@company.com\nSubject: Project Meeting Tomorrow\n\nHi, dont forget our project meeting tomorrow at 2 PM. We will discuss the quarterly report.\n\nThanks, John" \
"legitimate"

test_analysis "HIGH RISK - Malware Delivery" \
"From: hr@company.com\nTo: employee@company.com\nSubject: Important Document\n\nPlease download this important policy document: http://company-docs.malicious.com/policy.exe\n\nHR Department" \
"malware_delivery"

echo -e "\n================================================================="
echo "                    CONSISTENCY SUMMARY"
echo "================================================================="
echo "✅ = Consistent correlation between analysis components"
echo "⚠  = Potential inconsistency or calibration needed"
echo "?  = Ambiguous case requiring human judgment"
echo ""
echo "Key Correlations Tested:"
echo "• Intent ↔ Risk Score (high threat = high risk)"
echo "• Deception Indicators ↔ Risk Score (more deception = higher risk)"
echo "• MITRE Techniques ↔ Intent (techniques match attack type)"
echo "• IOCs ↔ Deception Indicators (malicious links = suspicious_links)"
echo "• Overall coherence across all analysis dimensions"
