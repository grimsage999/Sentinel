# 🔗 MITRE ATT&CK Links Guide

## **What Each Link Does in Your Frontend**

### 🌐 **"View Framework →" Link**
**URL**: `https://attack.mitre.org/`

**Opens**: Main MITRE ATT&CK Framework Homepage

**What You'll See**:
- Complete ATT&CK Matrix with all tactics and techniques
- Enterprise, Mobile, and ICS frameworks
- Search functionality for techniques
- Latest framework updates and resources
- Threat group profiles and software

**Use Case**: General reference to explore the entire MITRE ATT&CK framework

---

### 🎯 **Individual Technique Links (e.g., T1566.002)**
**URL Pattern**: `https://attack.mitre.org/techniques/{TECHNIQUE_ID}/`

**Example URLs**:
- T1566.002: `https://attack.mitre.org/techniques/T1566/002/`
- T1566.001: `https://attack.mitre.org/techniques/T1566/001/`
- T1534: `https://attack.mitre.org/techniques/T1534/`

**What You'll See on Each Technique Page**:

#### **📋 Technique Details**:
- **Name**: "Spearphishing Link"
- **ID**: T1566.002
- **Tactic**: Initial Access
- **Platforms**: Linux, macOS, Windows
- **Data Sources**: Application Log, File, Network Traffic

#### **📖 Description**:
Detailed explanation of how adversaries use this technique

#### **🔍 Procedure Examples**:
Real-world examples from threat groups:
- "APT1 has sent spearphishing emails containing malicious links"
- "Lazarus Group used spearphishing links to deliver malware"

#### **🛡️ Mitigations**:
- User Training
- Email Security Software  
- Network Intrusion Prevention
- Restrict Web-Based Content

#### **🔎 Detection**:
- Monitor for suspicious email attachments
- Analyze network traffic patterns
- Check for unusual user behavior

#### **📊 Data Sources**:
- Email Gateway logs
- Web proxy logs
- Network traffic analysis
- User behavior analytics

---

## **🧪 Live Example - T1566.002 (Spearphishing Link)**

When your frontend shows `T1566.002` and you click on it, you'll see:

### **Page Title**: "Spearphishing Link - T1566.002"

### **Description**:
> "Adversaries may send spearphishing emails with a malicious link in an effort to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing..."

### **Real Threat Group Examples**:
- **APT28**: Used spearphishing links in campaigns against government targets
- **FIN7**: Sent malicious links to steal payment card data
- **Lazarus Group**: Used links to deliver banking trojans

### **Detection Methods**:
- Email security gateways analyzing URLs
- User reports of suspicious emails
- Network monitoring for malicious domains
- Behavioral analysis of user clicks

### **Mitigation Strategies**:
- Security awareness training
- Email filtering and sandboxing
- URL reputation checking
- Network segmentation

---

## **🎯 How This Helps SOC Analysts**

### **Immediate Value**:
1. **Context**: Understand exactly what attack technique was detected
2. **Threat Intelligence**: See which threat groups use this technique
3. **Detection**: Learn how to detect this technique in your environment
4. **Response**: Get mitigation and response strategies

### **Workflow Integration**:
```
PhishContext AI Analysis → MITRE Technique → Official Documentation → Response Action
```

### **Example Workflow**:
1. **Email Analyzed**: PayPal phishing detected
2. **Technique Identified**: T1566.002 (Spearphishing Link)
3. **Click Technique Link**: Opens MITRE page with full details
4. **Review Mitigations**: Implement user training, email filtering
5. **Set Detection Rules**: Configure SIEM alerts for similar patterns

---

## **🚀 Frontend Implementation Details**

### **In Your Component**:
```typescript
// Main framework link
<a href="https://attack.mitre.org/" target="_blank">
  View Framework →
</a>

// Individual technique links
{techniques.map(technique => (
  <a href={`https://attack.mitre.org/techniques/${technique}/`} target="_blank">
    {technique} 🔗
  </a>
))}
```

### **User Experience**:
- ✅ Links open in new tabs (don't lose analysis context)
- ✅ Visual indicators show external links
- ✅ Hover effects for better UX
- ✅ Accessible with proper ARIA labels

---

## **💡 Pro Tips for SOC Analysts**

1. **Bookmark Common Techniques**: Save frequently seen techniques for quick reference
2. **Study Procedure Examples**: Learn how real threat groups use each technique  
3. **Review Mitigations**: Implement suggested security controls
4. **Set Up Detection**: Use data sources info to configure monitoring
5. **Share with Team**: Use MITRE IDs for consistent threat communication

---

## **🔗 Quick Reference Links**

| **Technique** | **Name** | **Direct Link** |
|---------------|----------|-----------------|
| T1566.002 | Spearphishing Link | https://attack.mitre.org/techniques/T1566/002/ |
| T1566.001 | Spearphishing Attachment | https://attack.mitre.org/techniques/T1566/001/ |
| T1534 | Internal Spearphishing | https://attack.mitre.org/techniques/T1534/ |
| T1204.001 | User Execution: Malicious Link | https://attack.mitre.org/techniques/T1204/001/ |

**Main Framework**: https://attack.mitre.org/

---

**🎯 Bottom Line**: These links connect your phishing analysis directly to the world's most comprehensive cybersecurity knowledge base, giving SOC analysts immediate access to threat intelligence, detection methods, and response strategies!
