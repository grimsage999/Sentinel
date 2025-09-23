# MITRE ATT&CK Analysis Test Suite

This document provides comprehensive test cases to validate the MITRE ATT&CK analysis functionality in PhishContext AI.

## Test Scenarios

### 1. No Attack Techniques (Legitimate Email)
**Expected Result**: "No attack is present. The email is benign."

```bash
curl -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: colleague@company.com\nTo: user@company.com\nSubject: Project Meeting Tomorrow\n\nHi,\n\nDont forget about our project meeting tomorrow at 2 PM in conference room A.\n\nWe will discuss the quarterly report and upcoming deadlines.\n\nThanks,\nJohn"
}' | jq '.data.mitreAttack'
```

### 2. No Specific Techniques (Ambiguous Email)
**Expected Result**: "No specific attack techniques identified. Email appears benign."

```bash
curl -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: info@newsletter.com\nTo: subscriber@example.com\nSubject: Weekly Newsletter\n\nHello,\n\nHere is your weekly newsletter with updates and news.\n\nBest regards,\nNewsletter Team"
}' | jq '.data.mitreAttack'
```

### 3. Credential Theft - T1566.002 (Spearphishing Link)
**Expected Techniques**: T1566.002

```bash
curl -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: security@bank-verification.com\nTo: customer@example.com\nSubject: Urgent: Verify Your Account\n\nYour account has been suspended. Please verify your login credentials immediately.\n\nClick here to verify: http://fake-bank.com/login\n\nSecurity Team"
}' | jq '.data.mitreAttack'
```

### 4. Malware Delivery - T1566.001 + T1204.001
**Expected Techniques**: T1566.001 (Spearphishing Attachment), T1204.001 (User Execution)

```bash
curl -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: hr@company.com\nTo: employee@company.com\nSubject: Important Document\n\nPlease download and review this important document.\n\nDownload: http://malicious-site.com/document.exe\n\nHR Department"
}' | jq '.data.mitreAttack'
```

### 5. Wire Transfer Fraud - T1566.002 + T1534
**Expected Techniques**: T1566.002 (Spearphishing Link), T1534 (Internal Spearphishing)

```bash
curl -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: ceo@company.com\nTo: finance@company.com\nSubject: Urgent Wire Transfer Required\n\nI need you to process an urgent wire transfer of $50,000 to our new supplier.\n\nTransfer details: Account 123456789\nBank: First National\n\nThis is confidential and time-sensitive.\n\nCEO"
}' | jq '.data.mitreAttack'
```

### 6. Reconnaissance - T1598.003
**Expected Techniques**: T1598.003 (Spearphishing for Information)

```bash
curl -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{
  "email_content": "From: survey@research.com\nTo: employee@company.com\nSubject: Company Information Survey\n\nWe are conducting research on company structures. Please provide information about your organization, employee count, and IT infrastructure.\n\nResearch Team"
}' | jq '.data.mitreAttack'
```

## Quick Test Script

Run all tests at once:

```bash
#!/bin/bash

echo "=== MITRE ATT&CK Analysis Test Suite ==="

echo "1. Testing Legitimate Email (No Techniques Expected):"
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{"email_content": "From: colleague@company.com\nTo: user@company.com\nSubject: Project Meeting Tomorrow\n\nHi,\n\nDont forget about our project meeting tomorrow at 2 PM in conference room A.\n\nWe will discuss the quarterly report and upcoming deadlines.\n\nThanks,\nJohn"}' | jq '.data.mitreAttack'

echo -e "\n2. Testing Ambiguous Email (No Specific Techniques Expected):"
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{"email_content": "From: info@newsletter.com\nTo: subscriber@example.com\nSubject: Weekly Newsletter\n\nHello,\n\nHere is your weekly newsletter with updates and news.\n\nBest regards,\nNewsletter Team"}' | jq '.data.mitreAttack'

echo -e "\n3. Testing Credential Theft (T1566.002 Expected):"
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{"email_content": "From: security@bank-verification.com\nTo: customer@example.com\nSubject: Urgent: Verify Your Account\n\nYour account has been suspended. Please verify your login credentials immediately.\n\nClick here to verify: http://fake-bank.com/login\n\nSecurity Team"}' | jq '.data.mitreAttack'

echo -e "\n4. Testing Malware Delivery (T1566.001 + T1204.001 Expected):"
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{"email_content": "From: hr@company.com\nTo: employee@company.com\nSubject: Important Document\n\nPlease download and review this important document.\n\nDownload: http://malicious-site.com/document.exe\n\nHR Department"}' | jq '.data.mitreAttack'

echo -e "\n5. Testing Wire Transfer (T1566.002 + T1534 Expected):"
curl -s -X POST http://localhost:8000/api/analyze -H "Content-Type: application/json" -d '{"email_content": "From: ceo@company.com\nTo: finance@company.com\nSubject: Urgent Wire Transfer Required\n\nI need you to process an urgent wire transfer of $50,000 to our new supplier.\n\nTransfer details: Account 123456789\nBank: First National\n\nThis is confidential and time-sensitive.\n\nCEO"}' | jq '.data.mitreAttack'

echo -e "\n=== Test Complete ==="
```

## Expected Results Summary

| Test Case | Intent Type | MITRE Techniques | Narrative |
|-----------|-------------|------------------|-----------|
| Legitimate Email | `legitimate` | `[]` | "No attack is present. The email is benign." |
| Ambiguous Email | `other` | `[]` | "No specific attack techniques identified. Email appears benign." |
| Credential Theft | `credential_theft` | `["T1566.002"]` | "Credential theft attack using spearphishing link detected" |
| Malware Delivery | `malware_delivery` | `["T1566.001", "T1204.001"]` | "Malware delivery via spearphishing attachment detected" |
| Wire Transfer | `wire_transfer` | `["T1566.002", "T1534"]` | "Wire transfer fraud using social engineering detected" |
| Reconnaissance | `reconnaissance` | `["T1598.003"]` | "Information gathering attempt detected" |

## MITRE ATT&CK Technique Reference

- **T1566.001**: Spearphishing Attachment
- **T1566.002**: Spearphishing Link  
- **T1204.001**: User Execution: Malicious Link
- **T1534**: Internal Spearphishing
- **T1598.003**: Spearphishing for Information

## Usage Notes

1. The system is currently in **demo mode** - configure API keys for full LLM-powered analysis
2. Demo mode uses keyword-based pattern matching for classification
3. With real API keys, the analysis would be more sophisticated and accurate
4. The "No specific attack techniques identified" message appears when emails have no deception indicators and are classified as benign
