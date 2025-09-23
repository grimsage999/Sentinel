#!/bin/bash

echo "=========================================="
echo "     MITRE ATT&CK Analysis Test Suite"
echo "=========================================="

# Test 1: Legitimate Email - Should show NO techniques
echo -e "\n1. 🟢 LEGITIMATE EMAIL (No Techniques Expected):"
echo "   Testing: Project meeting email..."
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: colleague@company.com\nTo: user@company.com\nSubject: Project Meeting Tomorrow\n\nHi,\n\nDont forget about our project meeting tomorrow at 2 PM in conference room A.\n\nWe will discuss the quarterly report and upcoming deadlines.\n\nThanks,\nJohn"
}' | jq -r '.data.mitreAttack | "   Techniques: \(.techniques | join(", ") | if . == "" then "NONE" else . end)\n   Narrative: \(.attackNarrative)"'

# Test 2: Ambiguous Email - Should show NO specific techniques  
echo -e "\n2. 🟡 AMBIGUOUS EMAIL (No Specific Techniques Expected):"
echo "   Testing: Generic newsletter..."
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: info@newsletter.com\nTo: subscriber@example.com\nSubject: Weekly Newsletter\n\nHello,\n\nHere is your weekly newsletter with updates and news.\n\nBest regards,\nNewsletter Team"
}' | jq -r '.data.mitreAttack | "   Techniques: \(.techniques | join(", ") | if . == "" then "NONE" else . end)\n   Narrative: \(.attackNarrative)"'

# Test 3: Credential Theft - Should show T1566.002
echo -e "\n3. 🔴 CREDENTIAL THEFT (T1566.002 Expected):"
echo "   Testing: Fake bank verification..."
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: security@bank-verification.com\nTo: customer@example.com\nSubject: Urgent: Verify Your Account\n\nYour account has been suspended. Please verify your login credentials immediately.\n\nClick here to verify: http://fake-bank.com/login\n\nSecurity Team"
}' | jq -r '.data.mitreAttack | "   Techniques: \(.techniques | join(", "))\n   Tactics: \(.tactics | join(", "))\n   Narrative: \(.attackNarrative)"'

# Test 4: Malware Delivery - Should show T1566.001, T1204.001
echo -e "\n4. 🔴 MALWARE DELIVERY (T1566.001 + T1204.001 Expected):"
echo "   Testing: Malicious executable download..."
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: hr@company.com\nTo: employee@company.com\nSubject: Important Document\n\nPlease download and review this important document.\n\nDownload: http://malicious-site.com/document.exe\n\nHR Department"
}' | jq -r '.data.mitreAttack | "   Techniques: \(.techniques | join(", "))\n   Tactics: \(.tactics | join(", "))\n   Narrative: \(.attackNarrative)"'

# Test 5: Wire Transfer Fraud
echo -e "\n5. 🔴 WIRE TRANSFER FRAUD (T1566.002 + T1534 Expected):"
echo "   Testing: CEO impersonation for wire transfer..."
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: ceo@company.com\nTo: finance@company.com\nSubject: Urgent Wire Transfer Required\n\nI need you to process an urgent wire transfer of $50,000 to our new supplier.\n\nTransfer details: Account 123456789\nBank: First National\n\nThis is confidential and time-sensitive.\n\nCEO"
}' | jq -r '.data.mitreAttack | "   Techniques: \(.techniques | join(", "))\n   Tactics: \(.tactics | join(", "))\n   Narrative: \(.attackNarrative)"'

# Test 6: PayPal Sophisticated Phishing
echo -e "\n6. 🔴 SOPHISTICATED PHISHING (Multiple Techniques Expected):"
echo "   Testing: PayPal account suspension with multiple IOCs..."
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: security@paypal-verification.com\nTo: user@example.com\nSubject: Urgent: Verify Your Account Now!\n\nDear Customer,\n\nYour PayPal account has been temporarily suspended due to suspicious activity.\n\nIMMEDIATE ACTION REQUIRED:\nClick here to verify: http://paypal-secure-login.malicious-site.com/verify\n\nIf you do not verify within 24 hours, your account will be permanently closed.\n\nBest regards,\nPayPal Security Team"
}' | jq -r '.data.mitreAttack | "   Techniques: \(.techniques | join(", "))\n   Tactics: \(.tactics | join(", "))\n   Narrative: \(.attackNarrative)"'

echo -e "\n=========================================="
echo "              Test Complete!"
echo "=========================================="
echo -e "\n📋 MITRE ATT&CK Technique Reference:"
echo "   T1566.001 = Spearphishing Attachment"
echo "   T1566.002 = Spearphishing Link"
echo "   T1204.001 = User Execution: Malicious Link"
echo "   T1534     = Internal Spearphishing"
echo "   T1598.003 = Spearphishing for Information"
echo -e "\n💡 Note: System is in DEMO MODE. Configure API keys for full LLM analysis."
