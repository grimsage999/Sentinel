#!/bin/bash

echo "🔧 TESTING FRONTEND MITRE FIX"
echo "============================="
echo ""
echo "Testing if frontend now shows MITRE techniques from backend..."
echo ""

# Test a phishing email that should have MITRE techniques
echo "📧 Testing PayPal Phishing Email:"
echo "Expected: Should show MITRE techniques in frontend"
echo ""

response=$(curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: security@paypal-verification.com\nTo: user@example.com\nSubject: Urgent: Verify Your Account Now!\n\nDear Customer,\n\nYour PayPal account has been temporarily suspended due to suspicious activity detected on your account.\n\nIMMEDIATE ACTION REQUIRED:\nClick here to verify your identity: http://paypal-secure-login.malicious-site.com/verify\n\nIf you do not verify within 24 hours, your account will be permanently closed and all funds will be frozen.\n\nBest regards,\nPayPal Security Team"
}')

# Extract key data for frontend debugging
intent=$(echo "$response" | jq -r '.data.intent.primary')
risk_score=$(echo "$response" | jq -r '.data.riskScore.score')
mitre_techniques=$(echo "$response" | jq -r '.data.mitreAttack.techniques[]' | tr '\n' ',' | sed 's/,$//')
mitre_enhanced=$(echo "$response" | jq -r '.data.mitreAttackEnhanced // "null"')
attack_narrative=$(echo "$response" | jq -r '.data.mitreAttack.attackNarrative')

echo "🔍 BACKEND RESPONSE ANALYSIS:"
echo "  Intent: $intent"
echo "  Risk Score: $risk_score/10"
echo "  MITRE Techniques (basic): [$mitre_techniques]"
echo "  MITRE Enhanced: $mitre_enhanced"
echo "  Attack Narrative: ${attack_narrative:0:100}..."
echo ""

if [[ "$mitre_techniques" != "" && "$mitre_techniques" != "null" ]]; then
    echo "✅ BACKEND: MITRE techniques are being returned"
    echo ""
    echo "🎯 FRONTEND SHOULD NOW DISPLAY:"
    echo "  - Attack Techniques: $mitre_techniques"
    echo "  - Tactics: $(echo "$response" | jq -r '.data.mitreAttack.tactics[]' | tr '\n' ',' | sed 's/,$//')"
    echo "  - Attack Narrative: Present"
    echo ""
    echo "📱 TO TEST FRONTEND:"
    echo "  1. Open http://localhost:3000 in browser"
    echo "  2. Paste the test email into the analysis form"
    echo "  3. Submit for analysis"
    echo "  4. Check MITRE ATT&CK section - should show techniques, NOT 'No specific attack techniques identified'"
    echo ""
    echo "🐛 IF STILL SHOWING 'No specific attack techniques identified':"
    echo "  1. Check browser console for errors"
    echo "  2. Verify frontend is using the updated MitreAttackDisplay component"
    echo "  3. Check if frontend build is up to date"
else
    echo "❌ BACKEND: No MITRE techniques found - backend issue still exists"
fi

echo ""
echo "🔧 DEBUGGING INFO FOR FRONTEND:"
echo "================================"
echo "The frontend MitreAttackDisplay component has been updated to:"
echo "1. Accept both 'mitreAttackEnhanced' and 'mitreAttack' (basic) data"
echo "2. Display basic MITRE data when enhanced data is not available"
echo "3. Show techniques as clickable badges linking to MITRE ATT&CK"
echo ""
echo "Backend returns:"
echo "- mitreAttack: { techniques: [...], tactics: [...], attackNarrative: '...' }"
echo "- mitreAttackEnhanced: null (not implemented yet)"
echo ""
echo "Frontend now uses mitreAttack when mitreAttackEnhanced is null."
