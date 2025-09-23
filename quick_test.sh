#!/bin/bash

echo "🎯 PhishContext AI - Quick Test Suite"
echo "======================================"

# Test the email from line 443 (currently selected)
echo -e "\n📧 TEST 1: Security Review Email (From your current file - line 443)"
echo "Expected: Medium-High risk credential theft attempt"
echo "------------------------------------------------------"

curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: security-team@gmail.com\nTo: employee@company.com\nSubject: Account Security Review Required\n\nHello,\n\nWe are conducting a routine security review of all company accounts.\n\nYour account has been selected for verification as part of our enhanced security measures.\n\nPlease confirm your account details by clicking the link below:\nhttps://account-verification.secure-portal.net/verify\n\nThis verification must be completed within 7 days to maintain account access.\n\nIf you have questions, contact our security team."
}' | jq '{
  "🎯 INTENT": .data.intent.primary,
  "⚡ RISK_SCORE": "\(.data.riskScore.score)/10",
  "🚨 DECEPTION_INDICATORS": (.data.deceptionIndicators | length),
  "🔗 MALICIOUS_URLS": (.data.iocs.urls | length),
  "⚔️ MITRE_TECHNIQUES": .data.mitreAttack.techniques,
  "📝 SUMMARY": .data.riskScore.reasoning[0:100] + "..."
}'

echo -e "\n📧 TEST 2: Obvious PayPal Phishing"
echo "Expected: High risk credential theft with multiple IOCs"
echo "------------------------------------------------------"

curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: security@paypal-verification.com\nTo: user@example.com\nSubject: URGENT: Your Account Will Be Closed!\n\nDear Customer,\n\nYour PayPal account has been SUSPENDED due to suspicious activity.\n\nIMMEDIATE ACTION REQUIRED:\nClick here NOW: http://paypal-fake-login.malicious.com/verify\n\nAccount will be PERMANENTLY DELETED in 24 hours!\n\nPayPal Security Team"
}' | jq '{
  "🎯 INTENT": .data.intent.primary,
  "⚡ RISK_SCORE": "\(.data.riskScore.score)/10", 
  "🚨 DECEPTION_INDICATORS": (.data.deceptionIndicators | length),
  "🔗 MALICIOUS_URLS": (.data.iocs.urls | length),
  "⚔️ MITRE_TECHNIQUES": .data.mitreAttack.techniques,
  "📝 SUMMARY": .data.riskScore.reasoning[0:100] + "..."
}'

echo -e "\n📧 TEST 3: Malware Delivery Attempt"
echo "Expected: High risk malware delivery with .exe file"
echo "------------------------------------------------------"

curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: hr@company.com\nTo: employee@company.com\nSubject: URGENT: New Company Policy Document\n\nDear Employee,\n\nPlease download and install this URGENT policy update immediately.\n\nDownload: http://company-updates.suspicious.com/policy-update.exe\n\nThis must be installed by end of day or your access will be suspended.\n\nHR Department"
}' | jq '{
  "🎯 INTENT": .data.intent.primary,
  "⚡ RISK_SCORE": "\(.data.riskScore.score)/10",
  "🚨 DECEPTION_INDICATORS": (.data.deceptionIndicators | length),
  "🔗 MALICIOUS_URLS": (.data.iocs.urls | length),
  "⚔️ MITRE_TECHNIQUES": .data.mitreAttack.techniques,
  "📝 SUMMARY": .data.riskScore.reasoning[0:100] + "..."
}'

echo -e "\n📧 TEST 4: Legitimate Business Email"
echo "Expected: Low risk, legitimate classification"
echo "------------------------------------------------------"

curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: manager@company.com\nTo: team@company.com\nSubject: Weekly Team Meeting - Project Updates\n\nHi Team,\n\nOur weekly meeting is scheduled for Thursday at 2 PM in Conference Room B.\n\nAgenda:\n- Project Alpha status update\n- Budget review for Q4\n- New team member introduction\n\nPlease bring your quarterly reports.\n\nThanks,\nSarah"
}' | jq '{
  "🎯 INTENT": .data.intent.primary,
  "⚡ RISK_SCORE": "\(.data.riskScore.score)/10",
  "🚨 DECEPTION_INDICATORS": (.data.deceptionIndicators | length),
  "🔗 MALICIOUS_URLS": (.data.iocs.urls | length),
  "⚔️ MITRE_TECHNIQUES": .data.mitreAttack.techniques,
  "📝 SUMMARY": .data.riskScore.reasoning[0:100] + "..."
}'

echo -e "\n🎯 QUICK INTERPRETATION GUIDE:"
echo "================================"
echo "📊 Risk Scores:"
echo "   1-3/10 = ✅ LOW (likely legitimate)"
echo "   4-6/10 = 🟡 MEDIUM (suspicious, investigate)" 
echo "   7-10/10 = 🔴 HIGH (likely phishing/malware)"
echo ""
echo "🚨 Deception Indicators:"
echo "   0-1 = ✅ Clean email"
echo "   2-3 = 🟡 Some red flags"
echo "   4+ = 🔴 Multiple attack indicators"
echo ""
echo "⚔️ MITRE Techniques:"
echo "   [] = ✅ No attack techniques"
echo "   T1566.002 = 🔴 Spearphishing Link"
echo "   T1566.001 = 🔴 Spearphishing Attachment"
echo ""
echo "🔗 IOCs (Indicators of Compromise):"
echo "   0 URLs = ✅ No malicious links"
echo "   1+ URLs = 🔴 Suspicious/malicious links found"
