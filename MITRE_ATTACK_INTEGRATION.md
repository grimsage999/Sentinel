# MITRE ATT&CK Framework Integration

## Overview

PhishContext AI now integrates the MITRE ATT&CK framework to provide structured threat intelligence and explain the "why" behind phishing email classifications. This integration maps detected phishing techniques to standardized attack patterns and provides actionable defensive recommendations.

## Features

### 🎯 Technique Mapping
- Automatically maps phishing indicators to MITRE ATT&CK techniques
- Identifies attack tactics (Initial Access, Execution, Credential Access, etc.)
- Provides context-specific technique descriptions

### 📖 Attack Narratives
- Generates human-readable attack chain explanations
- Links techniques to show progression through attack lifecycle
- Explains adversary objectives at each stage

### 🛡️ Defensive Recommendations
- **Immediate Actions**: Urgent response steps for active threats
- **Security Controls**: Technical controls to prevent similar attacks
- **User Training**: Awareness and education recommendations
- **Monitoring**: Detection and alerting improvements

### 🔗 Framework Integration
- Links to official MITRE ATT&CK technique pages
- Uses standardized technique IDs (e.g., T1566.002)
- Maintains compatibility with MITRE ATT&CK v13.1

## Implementation

### Backend Services

#### MitreAttackService
```python
from app.services.mitre_attack_service import MitreAttackService

mitre_service = MitreAttackService()

# Analyze techniques from email analysis
techniques = mitre_service.analyze_email_techniques(analysis_result)

# Get defensive recommendations
recommendations = mitre_service.get_technique_recommendations(techniques)

# Generate attack narrative
narrative = mitre_service.build_attack_narrative(techniques)
```

#### Enhanced Prompt Builder
The prompt builder now includes MITRE ATT&CK context in system prompts:
- Guides LLM to identify specific techniques
- Includes technique IDs in reasoning
- Maps attack patterns to framework taxonomy

#### Automatic Enhancement
Analysis results are automatically enhanced with MITRE context:
```python
# In LLM analyzer
analysis_result = self.prompt_builder.enhance_analysis_with_mitre(analysis_result)
```

### Frontend Components

#### MitreAttackDisplay Component
Interactive display with three tabs:
- **Techniques**: Detailed technique information with links
- **Attack Chain**: Narrative explanation of attack progression
- **Recommendations**: Categorized defensive actions

#### Integration in AnalysisResults
MITRE ATT&CK analysis appears as a dedicated section in analysis results.

## Supported Techniques

### Phishing Techniques (T1566)
- **T1566.001**: Spearphishing Attachment
- **T1566.002**: Spearphishing Link  
- **T1566.003**: Spearphishing via Service

### Information Gathering (T1598)
- **T1598.001**: Spearphishing Service
- **T1598.002**: Spearphishing Attachment
- **T1598.003**: Spearphishing Link

### User Execution (T1204)
- **T1204.001**: Malicious Link
- **T1204.002**: Malicious File

### Defense Evasion (T1036)
- **T1036.005**: Match Legitimate Name or Location

### Credential Access (T1110, T1056)
- **T1110.003**: Password Spraying
- **T1056.003**: Web Portal Capture

## Example Analysis Output

```json
{
  "mitreAttack": {
    "techniques": ["T1566.002", "T1598.003", "T1036.005"],
    "tactics": ["initial-access", "collection", "defense-evasion"],
    "attackNarrative": "Spearphishing link for credential theft with domain masquerading"
  },
  "mitreAttackEnhanced": {
    "techniquesDetailed": [
      {
        "techniqueId": "T1566.002",
        "name": "Spearphishing Link",
        "description": "Adversaries may send spearphishing emails with a malicious link",
        "tactic": "initial-access",
        "tacticDescription": "The adversary is trying to get into your network",
        "context": "Credential harvesting via phishing link",
        "mitreUrl": "https://attack.mitre.org/techniques/T1566/002"
      }
    ],
    "recommendations": {
      "immediateActions": [
        "Block sender domain/email address",
        "Check for similar emails in organization"
      ],
      "securityControls": [
        "Implement email authentication (SPF, DKIM, DMARC)",
        "Multi-factor authentication (MFA)"
      ],
      "userTraining": [
        "Phishing awareness training",
        "Simulated phishing exercises"
      ],
      "monitoring": [
        "Monitor for credential stuffing attempts",
        "Unusual login location alerts"
      ]
    },
    "attackNarrativeDetailed": "**Initial Access**: The attacker uses Spearphishing Link to gain initial access...",
    "frameworkVersion": "MITRE ATT&CK v13.1",
    "analysisTimestamp": "2025-09-21T19:50:14.097512Z"
  }
}
```

## Benefits

### For Security Analysts
- **Standardized Language**: Common terminology across security teams
- **Contextual Understanding**: Clear explanation of attack methods
- **Actionable Intelligence**: Specific recommendations for defense

### for Incident Response
- **Rapid Classification**: Quick identification of attack patterns
- **Response Prioritization**: Risk-based action recommendations
- **Knowledge Transfer**: Consistent analysis across team members

### For Security Operations
- **Detection Engineering**: Guidance for monitoring improvements
- **Control Assessment**: Evaluation of existing security measures
- **Training Programs**: Targeted awareness initiatives

## Testing

Run the MITRE ATT&CK integration test:
```bash
cd backend
python test_mitre_integration.py
```

This validates:
- Technique mapping accuracy
- Recommendation generation
- Attack narrative creation
- Framework compatibility

## Future Enhancements

### Planned Features
- **Custom Technique Mapping**: Organization-specific technique definitions
- **Threat Intelligence Integration**: External threat feed correlation
- **Historical Analysis**: Trend analysis across attack patterns
- **Automated Playbooks**: Integration with SOAR platforms

### Framework Updates
- Regular updates to match new MITRE ATT&CK releases
- Sub-technique granularity improvements
- Additional tactic coverage

## Configuration

### Environment Variables
No additional configuration required - MITRE ATT&CK integration is enabled by default.

### Customization
Modify technique mappings in `backend/app/services/mitre_attack_service.py`:
- Add new technique definitions
- Customize recommendation templates
- Adjust tactic descriptions

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [Phishing Techniques](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

## Support

For questions about MITRE ATT&CK integration:
1. Review this documentation
2. Check the test examples
3. Examine the MitreAttackService implementation
4. Refer to official MITRE ATT&CK documentation