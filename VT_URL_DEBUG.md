# VirusTotal URL Debug Guide

## 🔍 Browser Console Debugging Steps

### Step 1: Open Browser Developer Tools
1. **Right-click** on your PhishContext AI page
2. **Select "Inspect"** or press `F12`
3. **Go to Console tab**

### Step 2: Test VirusTotal URL Generation
Paste this code in the browser console to test URL generation:

```javascript
// Test URL encoding
const testUrl = "https://amazon-security-verification.com/verify-account";
const encodedUrl = encodeURIComponent(testUrl);
const vtUrl = `https://www.virustotal.com/gui/home/url?url=${encodedUrl}`;

console.log("Original URL:", testUrl);
console.log("Encoded URL:", encodedUrl);
console.log("VirusTotal URL:", vtUrl);
console.log("Click to test:", vtUrl);

// Test opening the URL
window.open(vtUrl, '_blank');
```

### Step 3: Debug IOC Button Clicks
Add this to console to monitor button clicks:

```javascript
// Monitor all VirusTotal button clicks
document.addEventListener('click', function(e) {
    if (e.target.textContent.includes('VirusTotal') || e.target.textContent.includes('VT')) {
        console.log('VirusTotal button clicked!');
        console.log('Button element:', e.target);
        
        // Find the IOC data
        const iocContainer = e.target.closest('[data-testid*="ioc"]') || e.target.closest('.bg-white');
        if (iocContainer) {
            console.log('IOC container:', iocContainer);
            
            // Look for URL in the container
            const urlElement = iocContainer.querySelector('.font-mono');
            if (urlElement) {
                console.log('Found URL:', urlElement.textContent);
            }
        }
    }
});
```

### Step 4: Check Network Requests
1. **Go to Network tab** in DevTools
2. **Analyze an email** with URLs
3. **Look for the API response** (`/api/analyze`)
4. **Check the IOCs data** in the response

### Step 5: Manual VirusTotal URL Testing

Test these URLs directly in your browser:

#### Test URL 1: Amazon Phishing
```
https://www.virustotal.com/gui/home/url?url=https%3A%2F%2Famazon-security-verification.com%2Fverify-account
```

#### Test URL 2: PayPal Phishing  
```
https://www.virustotal.com/gui/home/url?url=http%3A%2F%2Fpaypal-secure-login.malicious-site.com%2Fverify
```

#### Test URL 3: Known Malicious (Should have data)
```
https://www.virustotal.com/gui/home/url?url=http%3A%2F%2Fmalware.wicar.org%2Fdata%2Feicar.com
```

## 🧪 Debug Test Email

Use this email to test VirusTotal integration:

```
From: security@test-phishing.com
To: user@example.com
Subject: Debug Test - Multiple URLs

Dear User,

Test URLs for VirusTotal debugging:

1. Fake Amazon: https://amazon-security-verification.com/verify-account
2. Fake PayPal: http://paypal-secure-login.malicious-site.com/verify
3. Test malware: http://malware.wicar.org/data/eicar.com
4. Google (should work): https://google.com

Best regards,
Test Team
```

## 🔧 Expected Behavior

### What Should Happen:
1. **Click VirusTotal button**
2. **New tab opens** with VirusTotal
3. **URL is pre-filled** in the submission form
4. **Either shows**:
   - Existing analysis results, OR
   - "Scan it" button to submit for analysis

### What Might Go Wrong:
1. **URL not pre-filled** → Encoding issue
2. **Opens wrong page** → URL format issue  
3. **Shows "Item not found"** → URL not in VirusTotal database
4. **Button doesn't work** → JavaScript error

## 🐛 Common Issues & Fixes

### Issue 1: URL Not Pre-filled
**Problem**: VirusTotal opens but URL field is empty
**Debug**: Check URL encoding in console
**Fix**: Verify `encodeURIComponent()` is working

### Issue 2: Wrong VirusTotal Page
**Problem**: Opens VirusTotal home instead of URL submission
**Fix**: Check URL format matches: `/gui/home/url?url=`

### Issue 3: "Item Not Found"
**Problem**: VirusTotal shows no data
**Solution**: This is normal for new URLs - click "Scan it"

### Issue 4: Button Not Working
**Problem**: Nothing happens when clicking
**Debug**: Check browser console for JavaScript errors

## 📊 Debug Checklist

- [ ] Browser console shows correct URL encoding
- [ ] Network tab shows IOCs in API response
- [ ] VirusTotal button opens new tab
- [ ] URL is pre-filled in VirusTotal form
- [ ] Can submit URL for analysis
- [ ] Results appear after scanning

## 🎯 Quick Debug Commands

### Check API Response:
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"email_content": "Test: https://amazon-security-verification.com/verify-account"}' \
  | jq '.data.iocs.urls[0].vtLink'
```

### Test URL Encoding:
```javascript
const url = "https://amazon-security-verification.com/verify-account";
console.log("Encoded:", encodeURIComponent(url));
```

### Monitor Button Clicks:
```javascript
document.querySelectorAll('button').forEach(btn => {
    if (btn.textContent.includes('VirusTotal')) {
        btn.addEventListener('click', () => console.log('VT clicked:', btn));
    }
});
```