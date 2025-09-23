# PhishContext AI - Test Email Collection

This document contains 10 test emails for validating the PhishContext AI system with VirusTotal integration. Copy and paste these emails into the analysis interface to test different phishing scenarios and legitimate emails.

## 🎯 Test Categories

- **8 Phishing Emails**: Various attack types with IOCs
- **2 Legitimate Emails**: Control group for false positive testing

---

## 📧 Test Email 1: PayPal Credential Theft

```
From: security@paypal-verification.com
To: user@example.com
Subject: Urgent: Verify Your Account Now!

Dear Customer,

Your PayPal account has been temporarily suspended due to suspicious activity detected on your account.

IMMEDIATE ACTION REQUIRED:
Click here to verify your identity: http://paypal-secure-login.malicious-site.com/verify

If you do not verify within 24 hours, your account will be permanently closed and all funds will be frozen.

For immediate assistance, visit: https://paypal-verification.suspicious-domain.net
Or contact our security team at: support@paypal-help.fake-domain.org

You can also reach us at our secure server: 203.0.113.45

Best regards,
PayPal Security Team
security@paypal.com
```

**Expected IOCs:**

- URLs: 2 malicious links
- IPs: 1 suspicious IP
- Domains: 0 (filtered legitimate domains)

---

## 📧 Test Email 2: Amazon Account Phishing

```
From: security@amazon-verification.com
To: customer@example.com
Subject: Your Amazon Account Has Been Compromised

Dear Valued Customer,

We have detected unauthorized access attempts on your Amazon account from the following IP address: 198.51.100.42

To secure your account immediately, please verify your information at:
https://amazon-security-verification.com/verify-account

Failure to verify within 12 hours will result in permanent account suspension.

Alternative verification link: http://amazon-secure.fake-verification.net/login

Contact our security department: security@amazon-help.suspicious.org

Thank you,
Amazon Security Team
```

**Expected IOCs:**

- URLs: 2 malicious links
- IPs: 1 suspicious IP
- Domains: 0 (filtered)

---

## 📧 Test Email 3: Microsoft Office 365 Phishing

```
From: noreply@microsoft-security.com
To: employee@company.com
Subject: Action Required: Office 365 Security Alert

Your Office 365 account will expire in 24 hours.

Security Alert Details:
- Suspicious login from: 192.0.2.100
- Location: Unknown
- Time: Today 3:47 AM

Verify your account to maintain access:
https://office365-verification.malicious-domain.org/signin

Alternative access: http://microsoft-secure-login.fake-site.net/office365

If you cannot access the links above, contact support at: help@microsoft-support.suspicious.com

Microsoft Security Team
```

**Expected IOCs:**

- URLs: 2 malicious links
- IPs: 1 suspicious IP
- Domains: 0 (filtered)

---

## 📧 Test Email 4: Banking Phishing with Multiple IOCs

```
From: alerts@chase-security.com
To: customer@example.com
Subject: URGENT: Suspicious Activity Detected

Dear Chase Customer,

We have detected the following suspicious activities on your account:

1. Login attempt from IP: 203.0.113.200
2. Transaction attempt from: 198.51.100.150
3. Password reset request from: suspicious-location.fake-bank.org

Immediate verification required:
Primary Link: https://chase-secure-banking.malicious-site.com/verify
Backup Link: http://chase-verification.fake-domain.net/secure

Mobile verification: https://m.chase-mobile.suspicious.org/app

Contact our fraud department: fraud@chase-help.fake-support.com

Chase Bank Security
```

**Expected IOCs:**

- URLs: 3 malicious links
- IPs: 2 suspicious IPs
- Domains: 1 suspicious domain

---

## 📧 Test Email 5: Apple ID Phishing

```
From: appleid@apple-security.com
To: user@example.com
Subject: Your Apple ID has been locked

Your Apple ID has been locked due to security concerns.

Unlock your account immediately: https://appleid-verification.malicious-apple.com/unlock

If the above link doesn't work, try: http://apple-secure.fake-id.net/verify

Your account was accessed from:
- IP Address: 192.0.2.75
- Device: Unknown iPhone
- Location: Suspicious

Restore access: https://apple-account-recovery.suspicious.org/restore

Apple Security Team
support@apple-help.fake.com
```

**Expected IOCs:**

- URLs: 3 malicious links
- IPs: 1 suspicious IP
- Domains: 0 (filtered)

---

## 📧 Test Email 6: Cryptocurrency Exchange Phishing

```
From: security@coinbase-alerts.com
To: trader@example.com
Subject: Urgent: Withdraw Your Funds Before Account Closure

SECURITY ALERT: Your Coinbase account will be permanently closed in 6 hours.

Reason: Suspicious trading activity detected from IP 203.0.113.88

Immediate action required to save your funds:
Emergency withdrawal: https://coinbase-emergency.malicious-crypto.com/withdraw

Alternative access: http://coinbase-secure.fake-exchange.net/emergency

Mobile access: https://m.coinbase-rescue.suspicious.org/mobile

Contact emergency support: emergency@coinbase-help.fake.org
Server location: 198.51.100.99

Coinbase Security Team
```

**Expected IOCs:**

- URLs: 3 malicious links
- IPs: 2 suspicious IPs
- Domains: 0 (filtered)

---

## 📧 Test Email 7: Social Engineering with Malware Links

```
From: hr@company-updates.com
To: employee@company.com
Subject: Mandatory: Updated Employee Handbook - Download Required

Dear Employee,

Please download and review the updated employee handbook immediately.

Download links:
Primary: https://company-handbook.malicious-site.com/download.exe
Mirror: http://employee-resources.fake-company.net/handbook.pdf
Backup: https://hr-documents.suspicious.org/files/handbook.zip

The document server is hosted at: 192.0.2.150

If you experience issues, contact IT support: it-support@company-help.fake.com

This is mandatory for all employees by end of day.

HR Department
```

**Expected IOCs:**

- URLs: 3 malicious links (including .exe file)
- IPs: 1 suspicious IP
- Domains: 0 (filtered)

---

## 📧 Test Email 8: Government/Tax Phishing

```
From: noreply@irs-refund.com
To: taxpayer@example.com
Subject: IRS Tax Refund - Action Required

You are eligible for a tax refund of $2,847.00

Process your refund immediately: https://irs-refund-portal.malicious-gov.com/claim

Alternative processing: http://tax-refund.fake-irs.net/process

Refund processing server: 203.0.113.175

If you cannot access the online portal, contact our refund department:
Phone verification: https://irs-phone-verify.suspicious.org/call
Email: refunds@irs-help.fake-gov.com

This refund expires in 48 hours.

Internal Revenue Service
```

**Expected IOCs:**

- URLs: 3 malicious links
- IPs: 1 suspicious IP
- Domains: 0 (filtered)

---

## ✅ Test Email 9: LEGITIMATE - Company Newsletter (Control)

```
From: newsletter@company.com
To: employee@company.com
Subject: Weekly Company Newsletter - March Updates

Dear Team,

Welcome to this week's company newsletter!

This Week's Highlights:
- Q1 results exceeded expectations
- New office opening in Austin
- Employee appreciation event next Friday

Upcoming Events:
- All-hands meeting: March 25th at 2 PM
- Team building event: March 30th
- Quarterly review sessions start April 1st

Resources:
- Employee portal: https://portal.company.com
- HR policies: https://hr.company.com/policies
- IT support: https://support.company.com

Contact us:
- HR: hr@company.com
- IT Support: support@company.com
- General inquiries: info@company.com

Best regards,
Communications Team
```

**Expected Results:**

- Intent: Legitimate/Informational
- Risk Score: Low (1-3)
- IOCs: Legitimate company domains (should be filtered)
- Deception Indicators: None or minimal

---

## ✅ Test Email 10: LEGITIMATE - Bank Statement Notification (Control)

```
From: statements@chase.com
To: customer@example.com
Subject: Your March Statement is Ready

Dear Valued Customer,

Your March 2024 account statement is now available for viewing.

Statement Details:
- Account: ****1234
- Statement Period: March 1-31, 2024
- Statement Date: April 1, 2024

To view your statement:
1. Log in to your Chase online banking at https://www.chase.com
2. Navigate to "Statements & Documents"
3. Select your March 2024 statement

You can also access statements through:
- Chase Mobile App (available on App Store and Google Play)
- Visit any Chase branch location
- Call customer service: 1-800-935-9935

Important Reminders:
- Review your statement for any unauthorized transactions
- Set up account alerts for added security
- Update your contact information if needed

Thank you for banking with Chase.

Chase Bank
Customer Service Team
```

**Expected Results:**

- Intent: Legitimate/Informational
- Risk Score: Low (1-3)
- IOCs: Legitimate chase.com domain (should be filtered)
- Deception Indicators: None
- No suspicious URLs, IPs, or domains

---

## 🧪 Testing Instructions

1. **Copy each email** from the code blocks above
2. **Paste into PhishContext AI** analysis interface
3. **Click "Analyze Email"**
4. **Review results** for:
   - Intent classification accuracy
   - Risk score appropriateness
   - IOC extraction completeness
   - VirusTotal link functionality
5. **Click VT buttons** to verify direct links to VirusTotal analysis pages

## 📊 Expected Performance

**Phishing Emails (1-8):**

- Risk Score: 7-10
- Intent: credential_theft, malware_delivery, or social_engineering
- Multiple IOCs extracted with working VT links

**Legitimate Emails (9-10):**

- Risk Score: 1-3
- Intent: legitimate or informational
- Minimal or no IOCs (legitimate domains filtered)
- No deception indicators

## 🎯 Success Criteria

- ✅ All phishing emails detected with high risk scores
- ✅ Legitimate emails classified as low risk
- ✅ IOCs correctly extracted and categorized
- ✅ VirusTotal links open to correct analysis pages
- ✅ No false positives on legitimate emails
- ✅ Consistent performance across different phishing types

---

## 📧 Test Email 11: LOW RISK (1-3) - Legitimate Software Update

```
From: noreply@microsoft.com
To: user@company.com
Subject: Windows Security Update Available

Dear Windows User,

A new security update is available for your Windows system.

Update Details:
- Update: KB5029331 - Security Update for Windows 11
- Release Date: September 2024
- Size: 127 MB
- Installation Time: Approximately 15 minutes

This update includes important security improvements and bug fixes. Your system will automatically download and install this update during your next restart.

To manually install now:
1. Go to Settings > Update & Security
2. Click "Check for updates"
3. Install available updates

For more information, visit: https://support.microsoft.com/updates

Best regards,
Microsoft Windows Update Team
```

**Expected Results:**
- Intent: `legitimate`
- Risk Score: 1-2
- IOCs: Legitimate microsoft.com domain
- Deception Indicators: None

---

## 📧 Test Email 12: LOW-MEDIUM RISK (3-4) - Suspicious but Unclear

```
From: security-team@gmail.com
To: employee@company.com
Subject: Account Security Review Required

Hello,

We are conducting a routine security review of all company accounts.

Your account has been selected for verification as part of our enhanced security measures.

Please confirm your account details by clicking the link below:
https://account-verification.secure-portal.net/verify

This verification must be completed within 7 days to maintain account access.

If you have questions, contact our security team.

Thank you for your cooperation.

Security Team
```

**Expected Results:**
- Intent: `credential_theft` or `reconnaissance`
- Risk Score: 3-4
- IOCs: Suspicious domain (secure-portal.net)
- Deception Indicators: Vague authority, suspicious domain

---

## 📧 Test Email 13: MEDIUM RISK (4-6) - Suspicious Characteristics

```
From: billing@paypal-services.org
To: customer@example.com
Subject: Payment Verification Required - Account Limitation

Dear PayPal Customer,

We have detected unusual activity on your PayPal account and have temporarily limited some features.

Account Status: Limited Access
Reason: Suspicious transaction patterns
Action Required: Verify payment information

To restore full access to your account, please verify your payment information:
https://paypal-secure.verification-center.com/restore-access

Please complete verification within 48 hours to avoid permanent account suspension.

If you believe this is an error, contact customer support immediately.

PayPal Security Department
```

**Expected Results:**
- Intent: `credential_theft`
- Risk Score: 4-6
- IOCs: Suspicious domain (paypal-services.org, verification-center.com)
- Deception Indicators: Urgency, authority impersonation, suspicious links

---

## 📧 Test Email 14: HIGH RISK (7-8) - Clear Phishing Attempt

```
From: security@amazon-account-services.net
To: customer@example.com
Subject: URGENT: Your Amazon Account Will Be Closed in 24 Hours!

IMMEDIATE ACTION REQUIRED!

Your Amazon account has been SUSPENDED due to suspicious login attempts from multiple locations.

⚠️ WARNING: Account will be PERMANENTLY DELETED in 24 hours unless you verify immediately!

Suspicious Activity Detected:
- Login from: Unknown Device (IP: 192.168.1.1)
- Location: Russia
- Time: Today 3:47 AM

CLICK HERE NOW TO SAVE YOUR ACCOUNT:
https://amazon-emergency-verification.secure-login.net/urgent-verify

DO NOT IGNORE THIS MESSAGE!

If you fail to verify within 24 hours:
❌ Account will be deleted
❌ Order history will be lost  
❌ Prime membership cancelled
❌ Gift card balance forfeited

Verify Now: https://amazon-account-restore.emergency-portal.org/verify-now

Amazon Security Alert System
```

**Expected Results:**
- Intent: `credential_theft`
- Risk Score: 7-8
- IOCs: Multiple suspicious domains
- Deception Indicators: Extreme urgency, authority impersonation, suspicious links, threatening language

---

## 📧 Test Email 15: VERY HIGH RISK (9-10) - Sophisticated Phishing

```
From: ceo@company-domain.com
To: finance@company.com
Subject: Re: Urgent Wire Transfer - Acquisition Deal

Hi Sarah,

Following up on our call yesterday about the confidential acquisition.

The seller's legal team needs the wire transfer completed today to secure the deal before our competitors find out.

Transfer Details:
Amount: $2,847,500.00
Recipient: Meridian Capital Holdings LLC
Account: 4471-8829-3344-7721
Routing: 021000021
Bank: Deutsche Bank AG, Frankfurt
SWIFT: DEUTDEFF

This is time-sensitive - please process immediately and confirm once sent. The board is expecting this to close by EOD.

I'm in meetings all day but you can reach me on my mobile if urgent: +1-555-0147

Thanks,
Michael Chen
CEO, TechCorp Industries

P.S. - Please keep this confidential until we announce publicly next week.
```

**Expected Results:**
- Intent: `wire_transfer`
- Risk Score: 9-10
- IOCs: Potentially spoofed domain, suspicious phone number
- Deception Indicators: Authority impersonation, urgency, wire transfer request, social engineering

---

## 🧪 **Testing Instructions for New Emails**

### **Risk Level Validation:**

**Low Risk (1-3):**
- Email 11: Should be classified as legitimate Microsoft communication

**Medium Risk (4-6):**
- Email 12: Vague but suspicious verification request
- Email 13: PayPal impersonation with suspicious domains

**High Risk (7-10):**
- Email 14: Obvious Amazon phishing with extreme urgency
- Email 15: Sophisticated BEC (Business Email Compromise) attack

### **Expected IOC Extraction:**

**Email 11:** `https://support.microsoft.com/updates` (legitimate)
**Email 12:** `https://account-verification.secure-portal.net/verify` (suspicious)
**Email 13:** `https://paypal-secure.verification-center.com/restore-access` (malicious)
**Email 14:** Multiple malicious domains
**Email 15:** Potential domain spoofing

### **Success Criteria:**

- ✅ Risk scores align with expected ranges
- ✅ Intent classification matches attack type
- ✅ Deception indicators accurately identify techniques
- ✅ IOCs extracted with working VirusTotal links
- ✅ No false positives on legitimate content
- ✅ Proper escalation from suspicious to high-risk

**These emails provide comprehensive coverage of the risk spectrum from legitimate communications to sophisticated attacks!**