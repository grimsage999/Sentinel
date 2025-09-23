# PhishContext AI - User Acceptance Testing Guide

## Overview

This document provides comprehensive user acceptance testing procedures for PhishContext AI, validating that all requirements are met and the system performs as expected in real-world SOC analyst workflows.

## Testing Environment Setup

### Prerequisites

- Node.js 18+
- Python 3.9+
- Valid API keys for LLM providers (OpenAI, Anthropic, or Google)
- VirusTotal API key (optional but recommended)

### Environment Configuration

1. **Backend Setup**

   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   cp .env.example .env
   # Configure .env with your API keys
   ```

2. **Frontend Setup**

   ```bash
   cd frontend
   npm install
   cp .env.example .env.local
   # Configure .env.local if needed
   ```

3. **Start Services**

   ```bash
   # Terminal 1 - Backend
   cd backend
   source venv/bin/activate
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

   # Terminal 2 - Frontend
   cd frontend
   npm run dev
   ```

4. **Access Application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

## Test Data

### Sample Phishing Emails

#### 1. Credential Theft Phishing

```
From: security@amazon-security.com
To: victim@company.com
Subject: Urgent: Your Amazon Account Has Been Compromised
Date: Mon, 1 Jan 2024 12:00:00 +0000

Dear Customer,

We have detected suspicious activity on your Amazon account. Your account has been temporarily suspended for your protection.

To restore access to your account, please verify your identity immediately by clicking the link below:

https://amazon-security-verification.com/verify-account

You have 24 hours to complete this verification, or your account will be permanently closed.

Thank you,
Amazon Security Team
```

#### 2. Wire Transfer Fraud (BEC)

```
From: ceo@company.com
To: finance@company.com
Subject: Urgent Wire Transfer Request
Date: Mon, 1 Jan 2024 15:30:00 +0000

Hi,

I need you to process an urgent wire transfer today. We have a confidential acquisition opportunity that requires immediate payment.

Please transfer $50,000 to:
Account: 1234567890
Routing: 987654321
Bank: First National Bank

This is time-sensitive and confidential. Please handle this personally and confirm once completed.

Thanks,
John Smith
CEO
```

#### 3. Malware Delivery

```
From: hr@company-benefits.com
To: employees@company.com
Subject: Updated Employee Handbook - Action Required
Date: Mon, 1 Jan 2024 09:00:00 +0000

Dear Team,

Please find attached the updated employee handbook that goes into effect immediately. All employees must review and acknowledge receipt.

Download the handbook here: https://company-benefits.com/handbook.pdf

The document requires Adobe Reader to view properly. If you don't have it installed, please download it from: https://adobe-reader-download.com/install

Best regards,
HR Department
```

#### 4. Legitimate Email (Control)

```
From: noreply@github.com
To: developer@company.com
Subject: [GitHub] Security alert: new SSH key added
Date: Mon, 1 Jan 2024 14:20:00 +0000

Hi developer,

A new SSH key was added to your GitHub account.

Key fingerprint: SHA256:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz

If this was you, you can safely ignore this email. If not, please secure your account immediately.

View your SSH keys: https://github.com/settings/keys

Thanks,
The GitHub Team
```

## User Acceptance Test Cases

### UAT-001: Basic Email Analysis Workflow

**Objective**: Verify the complete email analysis workflow from input to results display.

**Prerequisites**: Application is running and accessible.

**Test Steps**:

1. Navigate to http://localhost:3000
2. Verify the application loads with the PhishContext AI interface
3. Paste the "Credential Theft Phishing" sample email into the text area
4. Click "Analyze Email" button
5. Wait for analysis to complete (should be under 30 seconds)
6. Review the analysis results

**Expected Results**:

- ✅ Application loads without errors
- ✅ Text area accepts the full email content including headers
- ✅ Analysis completes within 30 seconds
- ✅ Results display shows:
  - Intent classification (likely "Credential Theft")
  - Risk score (likely 7-9/10)
  - Deception indicators (sender spoofing, urgency tactics)
  - IOCs extracted (malicious URL)
  - VirusTotal links for IOCs

**Pass Criteria**: All expected results are met.

---

### UAT-002: Intent Classification Accuracy

**Objective**: Verify the system correctly identifies different types of phishing intents.

**Test Steps**:

1. Test each sample email type:
   - Credential Theft Phishing
   - Wire Transfer Fraud (BEC)
   - Malware Delivery
   - Legitimate Email (Control)
2. For each email, verify the intent classification matches expectations
3. Check confidence levels are appropriate
4. Verify alternative intents are shown when applicable

**Expected Results**:

- ✅ Credential Theft email → "Credential Theft" intent
- ✅ BEC email → "Wire Transfer Fraud" intent
- ✅ Malware email → "Malware Delivery" intent
- ✅ Legitimate email → "Other" or "Legitimate" with low risk score
- ✅ Confidence levels are displayed (High/Medium/Low)
- ✅ Brief reasoning provided for each classification

**Pass Criteria**: Intent classification is accurate for at least 3 out of 4 test emails.

---

### UAT-003: Deception Indicator Detection

**Objective**: Verify the system identifies key social engineering tactics.

**Test Steps**:

1. Use the "Credential Theft Phishing" sample email
2. Analyze and review deception indicators section
3. Verify specific indicators are identified with evidence

**Expected Results**:

- ✅ Sender spoofing detected (domain mismatch)
- ✅ Urgency tactics identified (time pressure language)
- ✅ Authority impersonation noted (Amazon branding)
- ✅ Suspicious links flagged
- ✅ Specific evidence quoted from email content

**Pass Criteria**: At least 3 different deception indicators are correctly identified.

---

### UAT-004: IOC Extraction and VirusTotal Integration

**Objective**: Verify automatic extraction of indicators of compromise and VirusTotal integration.

**Test Steps**:

1. Use an email containing URLs, IP addresses, and domains
2. Analyze the email
3. Review the IOCs section
4. Test VirusTotal links
5. Test copy-to-clipboard functionality

**Expected Results**:

- ✅ URLs are extracted and displayed
- ✅ IP addresses are extracted (if present)
- ✅ Domain names are extracted
- ✅ IOCs are categorized correctly
- ✅ VirusTotal links open in new tabs
- ✅ Copy buttons work for each IOC
- ✅ IOC counts are accurate

**Pass Criteria**: All IOCs are extracted correctly and VirusTotal integration works.

---

### UAT-005: Error Handling and Recovery

**Objective**: Verify the system handles errors gracefully and provides recovery options.

**Test Steps**:

1. Test with empty email content
2. Test with malformed email content
3. Test with extremely large email content (>1MB)
4. Simulate network connectivity issues
5. Test recovery mechanisms

**Expected Results**:

- ✅ Empty content shows appropriate validation message
- ✅ Malformed content shows clear error message
- ✅ Large content is rejected with size limit message
- ✅ Network errors show retry options
- ✅ Error messages are user-friendly and actionable
- ✅ Form state is preserved during errors

**Pass Criteria**: All error scenarios are handled gracefully with clear user guidance.

---

### UAT-006: Performance Under Load

**Objective**: Verify the system maintains performance under realistic SOC analyst usage.

**Test Steps**:

1. Perform 10 consecutive analyses with different emails
2. Measure response times for each analysis
3. Monitor system resource usage
4. Test concurrent usage (if multiple users available)

**Expected Results**:

- ✅ Each analysis completes within 60 seconds
- ✅ Average response time is under 30 seconds
- ✅ No memory leaks or performance degradation
- ✅ UI remains responsive during analysis
- ✅ System handles multiple concurrent requests

**Pass Criteria**: All analyses complete within time limits with stable performance.

---

### UAT-007: Security and Data Handling

**Objective**: Verify sensitive email content is handled securely.

**Test Steps**:

1. Analyze an email containing sensitive information (PII, credentials, etc.)
2. Complete the analysis
3. Clear the form
4. Check browser storage and network traffic
5. Verify no sensitive data persists

**Expected Results**:

- ✅ Analysis completes successfully
- ✅ Sensitive data is not logged in browser console
- ✅ No sensitive data in localStorage/sessionStorage
- ✅ Form clears completely
- ✅ Network requests use HTTPS
- ✅ No sensitive data in URL parameters

**Pass Criteria**: No sensitive data persists after analysis completion.

---

### UAT-008: User Interface and Accessibility

**Objective**: Verify the interface is intuitive and accessible for SOC analysts.

**Test Steps**:

1. Navigate the interface using only keyboard
2. Test with screen reader (if available)
3. Verify responsive design on different screen sizes
4. Test color contrast and readability
5. Verify all interactive elements are accessible

**Expected Results**:

- ✅ All functionality accessible via keyboard
- ✅ Proper ARIA labels and roles
- ✅ Responsive design works on mobile/tablet/desktop
- ✅ Sufficient color contrast for readability
- ✅ Loading states are announced to screen readers
- ✅ Error messages are accessible

**Pass Criteria**: Interface meets basic accessibility standards and is usable across devices.

---

### UAT-009: Real-World SOC Workflow Integration

**Objective**: Verify the system fits into typical SOC analyst workflows.

**Test Steps**:

1. Test with forwarded emails (common SOC format)
2. Test with emails containing security headers
3. Test rapid analysis of multiple emails
4. Verify export/copy functionality for reporting
5. Test integration with existing SOC tools (manual verification)

**Expected Results**:

- ✅ Handles forwarded email formats correctly
- ✅ Parses emails with extensive headers
- ✅ Supports rapid sequential analysis
- ✅ Results can be easily copied/exported
- ✅ Analysis fits into existing incident response workflow

**Pass Criteria**: System integrates smoothly into typical SOC analyst workflows.

---

### UAT-010: System Reliability and Uptime

**Objective**: Verify system stability over extended periods.

**Test Steps**:

1. Run continuous analysis for 1 hour
2. Monitor for memory leaks or crashes
3. Test system recovery after errors
4. Verify health check endpoints
5. Test graceful degradation under high load

**Expected Results**:

- ✅ System remains stable over extended use
- ✅ No memory leaks or resource exhaustion
- ✅ Automatic recovery from transient errors
- ✅ Health checks report accurate status
- ✅ Graceful degradation when overloaded

**Pass Criteria**: System demonstrates production-ready stability.

## Performance Benchmarks

### Response Time Requirements

- **Target**: Analysis completes within 30 seconds
- **Maximum**: Analysis completes within 60 seconds
- **Measurement**: Time from clicking "Analyze" to results display

### Accuracy Requirements

- **Intent Classification**: >80% accuracy on test dataset
- **IOC Extraction**: >95% recall for URLs, IPs, domains
- **Deception Indicators**: >75% accuracy for common tactics

### Reliability Requirements

- **Uptime**: >99% availability during testing period
- **Error Rate**: <5% of requests result in errors
- **Recovery**: System recovers from errors within 30 seconds

## Test Execution Checklist

### Pre-Testing Setup

- [ ] Backend service is running and healthy
- [ ] Frontend application is accessible
- [ ] API keys are configured correctly
- [ ] Test data is prepared
- [ ] Network connectivity is stable

### During Testing

- [ ] Document all test results
- [ ] Capture screenshots of issues
- [ ] Record response times
- [ ] Note any unexpected behavior
- [ ] Test with different browsers (Chrome, Firefox, Safari)

### Post-Testing Validation

- [ ] All UAT test cases completed
- [ ] Performance benchmarks met
- [ ] Security requirements validated
- [ ] Accessibility standards verified
- [ ] Documentation updated with findings

## Acceptance Criteria

The system is considered ready for production deployment when:

1. **Functional Requirements**: All 10 UAT test cases pass
2. **Performance Requirements**: All benchmarks are met
3. **Security Requirements**: No sensitive data leakage detected
4. **Reliability Requirements**: System demonstrates stable operation
5. **User Experience**: Interface is intuitive and accessible

## Issue Reporting

When issues are identified during UAT:

1. **Severity Levels**:

   - **Critical**: System unusable or data security compromised
   - **High**: Core functionality broken or significantly impaired
   - **Medium**: Feature works but with limitations or poor UX
   - **Low**: Minor cosmetic or enhancement issues

2. **Required Information**:

   - Test case number and description
   - Steps to reproduce
   - Expected vs actual results
   - Screenshots or error messages
   - Browser and system information
   - Impact on SOC analyst workflow

3. **Resolution Process**:
   - Critical/High issues must be resolved before production
   - Medium issues should be resolved or documented as known limitations
   - Low issues can be addressed in future releases

## Sign-off

**User Acceptance Testing Completed By**:

- SOC Analyst Representative: **\*\*\*\***\_**\*\*\*\*** Date: \***\*\_\*\***
- Security Team Lead: **\*\*\*\***\_**\*\*\*\*** Date: \***\*\_\*\***
- IT Operations: **\*\*\*\***\_**\*\*\*\*** Date: \***\*\_\*\***
- Project Manager: **\*\*\*\***\_**\*\*\*\*** Date: \***\*\_\*\***

**Production Deployment Approved**: ☐ Yes ☐ No

**Comments**:

---

---

---
