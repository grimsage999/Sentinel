#!/bin/bash

echo "🎯 PhishContext AI - Simple Test Suite"
echo "======================================"

# Test 1: The email from line 443 (currently selected in your IDE)
echo -e "\n📧 TEST 1: Security Review Email (From your current file)"
echo "Expected: Medium-High risk credential theft"
echo "------------------------------------------------------"

curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: security-team@gmail.com\nTo: employee@company.com\nSubject: Account Security Review Required\n\nHello,\n\nWe are conducting a routine security review of all company accounts.\n\nYour account has been selected for verification as part of our enhanced security measures.\n\nPlease confirm your account details by clicking the link below:\nhttps://account-verification.secure-portal.net/verify\n\nThis verification must be completed within 7 days to maintain account access.\n\nIf you have questions, contact our security team."
}' | jq '{
  "INTENT": .data.intent.primary,
  "RISK_SCORE": .data.riskScore.score,
  "DECEPTION_COUNT": (.data.deceptionIndicators | length),
  "MALICIOUS_URLS": (.data.iocs.urls | length),
  "MITRE_TECHNIQUES": .data.mitreAttack.techniques
}'

echo -e "\n📧 TEST 2: High-Risk PayPal Phishing"
echo "Expected: High risk with multiple red flags"
echo "------------------------------------------------------"

curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: security@paypal-verification.com\nSubject: URGENT: Account Suspended!\n\nYour PayPal account is SUSPENDED!\n\nClick here immediately: http://paypal-fake.malicious.com/login\n\nAccount deleted in 24 hours!\n\nPayPal Security"
}' | jq '{
  "INTENT": .data.intent.primary,
  "RISK_SCORE": .data.riskScore.score,
  "DECEPTION_COUNT": (.data.deceptionIndicators | length),
  "MALICIOUS_URLS": (.data.iocs.urls | length),
  "MITRE_TECHNIQUES": .data.mitreAttack.techniques
}'

echo -e "\n📧 TEST 3: Legitimate Business Email"
echo "Expected: Low risk, no threats detected"
echo "------------------------------------------------------"

curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: manager@company.com\nSubject: Team Meeting Thursday\n\nHi Team,\n\nOur weekly meeting is Thursday at 2 PM in Conference Room B.\n\nAgenda: Project updates and Q4 planning.\n\nThanks,\nSarah"
}' | jq '{
  "INTENT": .data.intent.primary,
  "RISK_SCORE": .data.riskScore.score,
  "DECEPTION_COUNT": (.data.deceptionIndicators | length),
  "MALICIOUS_URLS": (.data.iocs.urls | length),
  "MITRE_TECHNIQUES": .data.mitreAttack.techniques
}'

echo -e "\n🎯 RESULTS INTERPRETATION:"
echo "=========================="
echo "Risk Scores: 1-3=LOW ✅ | 4-6=MEDIUM 🟡 | 7-10=HIGH 🔴"
echo "Deception: 0-1=Clean ✅ | 2-3=Suspicious 🟡 | 4+=Malicious 🔴"
echo "MITRE: []=No Attack ✅ | T1566.002=Phishing Link 🔴"
echo "URLs: 0=Safe ✅ | 1+=Malicious Links Found 🔴"
