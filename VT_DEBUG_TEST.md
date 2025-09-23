# VirusTotal Debug Test Emails

Use these emails to test VirusTotal integration with URLs that are more likely to have existing analysis data.

## 🧪 Test Email 1: Known Malicious URL (EICAR Test)

```
From: test@malware-test.com
To: user@example.com
Subject: Test Malware Link

This is a test email with a known test malware URL.

Download test file: http://malware.wicar.org/data/eicar.com

This URL should have VirusTotal analysis data.
```

**Expected VT URL:** `https://www.virustotal.com/gui/url/ab302ebc1e243ee089bee075e603f5146d08462e4a59a7b27270611c9f1ad82d`

## 🧪 Test Email 2: Popular Website (Should have VT data)

```
From: test@example.com
To: user@example.com
Subject: Test with Popular URL

Visit our website: https://google.com

Also check: http://example.com

These popular URLs should have VirusTotal analysis data.
```

**Expected VT URLs:**
- Google: `https://www.virustotal.com/gui/url/05046f26c83e8c88b3ddab2eab63d0d16224ac1e564535fc75cdceee47a0938d`
- Example: `https://www.virustotal.com/gui/url/f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4`

## 🔧 Debug Steps:

1. **Test the VT button** - should open existing analysis
2. **Test the Submit button** - should open submission page with URL pre-filled
3. **Check if URLs show "No data available"** - use Submit button instead
4. **Verify both buttons work** for different scenarios

## 🎯 New Button Behavior:

- **Blue VT Button**: Direct link to analysis page (may show "no data" for new URLs)
- **Green Submit Button**: VirusTotal submission page with URL pre-filled (always works)

This gives users two options:
1. Quick check for existing analysis
2. Submit for new analysis if no data exists