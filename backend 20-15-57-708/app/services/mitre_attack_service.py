"""
MITRE ATT&CK Framework Integration Service
Provides threat intelligence context for phishing email analysis
"""
import json
from typing import Dict, List, Optional, Any
from enum import Enum


class AttackTactic(Enum):
    """MITRE ATT&CK Tactics relevant to phishing"""
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class MitreAttackService:
    """Service for MITRE ATT&CK framework integration"""
    
    def __init__(self):
        self.phishing_techniques = self._load_phishing_techniques()
        self.tactic_descriptions = self._load_tactic_descriptions()
    
    def _load_phishing_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK techniques relevant to phishing"""
        return {
            "T1566": {
                "name": "Phishing",
                "tactic": AttackTactic.INITIAL_ACCESS.value,
                "description": "Adversaries may send phishing messages to gain access to victim systems",
                "sub_techniques": {
                    "T1566.001": {
                        "name": "Spearphishing Attachment",
                        "description": "Adversaries may send spearphishing emails with a malicious attachment"
                    },
                    "T1566.002": {
                        "name": "Spearphishing Link", 
                        "description": "Adversaries may send spearphishing emails with a malicious link"
                    },
                    "T1566.003": {
                        "name": "Spearphishing via Service",
                        "description": "Adversaries may send spearphishing messages via third-party services"
                    }
                }
            },
            "T1204": {
                "name": "User Execution",
                "tactic": AttackTactic.EXECUTION.value,
                "description": "Adversaries may rely upon specific actions by a user in order to gain execution",
                "sub_techniques": {
                    "T1204.001": {
                        "name": "Malicious Link",
                        "description": "Adversaries may rely upon a user clicking a malicious link"
                    },
                    "T1204.002": {
                        "name": "Malicious File",
                        "description": "Adversaries may rely upon a user opening a malicious file"
                    }
                }
            },
            "T1598": {
                "name": "Phishing for Information",
                "tactic": AttackTactic.COLLECTION.value,
                "description": "Adversaries may send phishing messages to elicit sensitive information",
                "sub_techniques": {
                    "T1598.001": {
                        "name": "Spearphishing Service",
                        "description": "Adversaries may send spearphishing messages via third-party services"
                    },
                    "T1598.002": {
                        "name": "Spearphishing Attachment",
                        "description": "Adversaries may send spearphishing emails with malicious attachments"
                    },
                    "T1598.003": {
                        "name": "Spearphishing Link",
                        "description": "Adversaries may send spearphishing emails with malicious links"
                    }
                }
            },
            "T1110": {
                "name": "Brute Force",
                "tactic": AttackTactic.CREDENTIAL_ACCESS.value,
                "description": "Adversaries may use brute force techniques to gain access to accounts",
                "sub_techniques": {
                    "T1110.003": {
                        "name": "Password Spraying",
                        "description": "Adversaries may use a single or small list of commonly used passwords"
                    }
                }
            },
            "T1056": {
                "name": "Input Capture",
                "tactic": AttackTactic.COLLECTION.value,
                "description": "Adversaries may use methods of capturing user input",
                "sub_techniques": {
                    "T1056.003": {
                        "name": "Web Portal Capture",
                        "description": "Adversaries may install code on websites to harvest credentials"
                    }
                }
            },
            "T1036": {
                "name": "Masquerading",
                "tactic": AttackTactic.DEFENSE_EVASION.value,
                "description": "Adversaries may attempt to manipulate features to make malicious content appear legitimate",
                "sub_techniques": {
                    "T1036.005": {
                        "name": "Match Legitimate Name or Location",
                        "description": "Adversaries may match or approximate the name or location of legitimate files"
                    }
                }
            }
        }
    
    def _load_tactic_descriptions(self) -> Dict[str, str]:
        """Load MITRE ATT&CK tactic descriptions"""
        return {
            AttackTactic.INITIAL_ACCESS.value: "The adversary is trying to get into your network",
            AttackTactic.EXECUTION.value: "The adversary is trying to run malicious code",
            AttackTactic.PERSISTENCE.value: "The adversary is trying to maintain their foothold",
            AttackTactic.PRIVILEGE_ESCALATION.value: "The adversary is trying to gain higher-level permissions",
            AttackTactic.DEFENSE_EVASION.value: "The adversary is trying to avoid being detected",
            AttackTactic.CREDENTIAL_ACCESS.value: "The adversary is trying to steal account names and passwords",
            AttackTactic.DISCOVERY.value: "The adversary is trying to figure out your environment",
            AttackTactic.COLLECTION.value: "The adversary is trying to gather data of interest",
            AttackTactic.COMMAND_AND_CONTROL.value: "The adversary is trying to communicate with compromised systems",
            AttackTactic.EXFILTRATION.value: "The adversary is trying to steal data",
            AttackTactic.IMPACT.value: "The adversary is trying to manipulate, interrupt, or destroy systems and data"
        }
    
    def analyze_email_techniques(self, email_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze email and map to MITRE ATT&CK techniques
        
        Args:
            email_analysis: Analysis results from LLM
            
        Returns:
            List of applicable MITRE ATT&CK techniques with context
        """
        applicable_techniques = []
        
        # Extract key indicators from analysis (handle Pydantic model)
        intent = ''
        if hasattr(email_analysis, 'intent') and email_analysis.intent:
            intent = getattr(email_analysis.intent.primary, 'value', str(email_analysis.intent.primary))
        
        deception_indicators = getattr(email_analysis, 'deception_indicators', [])
        risk_score = getattr(email_analysis.risk_score, 'score', 0) if hasattr(email_analysis, 'risk_score') else 0
        
        # Map intent to techniques
        if intent == 'credential_theft':
            applicable_techniques.extend([
                self._build_technique_context("T1566.002", "Credential harvesting via phishing link"),
                self._build_technique_context("T1598.003", "Information gathering through credential phishing"),
                self._build_technique_context("T1056.003", "Web portal credential capture")
            ])
        
        elif intent == 'malware_delivery':
            applicable_techniques.extend([
                self._build_technique_context("T1566.001", "Malware delivery via email attachment"),
                self._build_technique_context("T1204.002", "User execution of malicious file"),
                self._build_technique_context("T1566.002", "Malware delivery via malicious link")
            ])
        
        elif intent == 'wire_transfer':
            applicable_techniques.extend([
                self._build_technique_context("T1566.003", "Business Email Compromise (BEC) via spearphishing service"),
                self._build_technique_context("T1534", "Internal spearphishing for wire transfer fraud"),
                self._build_technique_context("T1565.001", "Data manipulation to facilitate fraudulent transfer")
            ])
        
        elif intent == 'reconnaissance':
            applicable_techniques.extend([
                self._build_technique_context("T1598.001", "Information gathering via phishing service"),
                self._build_technique_context("T1598.003", "Reconnaissance through spearphishing")
            ])
        
        # Map deception indicators to techniques
        for indicator in deception_indicators:
            indicator_type = indicator.get('type', '')
            
            if indicator_type == 'spoofing':
                applicable_techniques.append(
                    self._build_technique_context("T1036.005", "Domain/sender spoofing for legitimacy")
                )
            
            elif indicator_type == 'suspicious_links':
                applicable_techniques.append(
                    self._build_technique_context("T1204.001", "Malicious link execution")
                )
        
        # Remove duplicates while preserving order
        seen_techniques = set()
        unique_techniques = []
        for technique in applicable_techniques:
            technique_id = technique['technique_id']
            if technique_id not in seen_techniques:
                seen_techniques.add(technique_id)
                unique_techniques.append(technique)
        
        return unique_techniques
    
    def _build_technique_context(self, technique_id: str, context: str) -> Dict[str, Any]:
        """Build technique context with MITRE ATT&CK details"""
        # Extract main technique ID (before sub-technique)
        main_technique_id = technique_id.split('.')[0]
        
        if main_technique_id in self.phishing_techniques:
            technique_data = self.phishing_techniques[main_technique_id]
            
            # Check if it's a sub-technique
            if '.' in technique_id and technique_id in technique_data.get('sub_techniques', {}):
                sub_technique = technique_data['sub_techniques'][technique_id]
                name = sub_technique['name']
                description = sub_technique['description']
            else:
                name = technique_data['name']
                description = technique_data['description']
            
            tactic = technique_data['tactic']
            tactic_description = self.tactic_descriptions.get(tactic, "")
            
            return {
                'technique_id': technique_id,
                'name': name,
                'description': description,
                'tactic': tactic,
                'tactic_description': tactic_description,
                'context': context,
                'mitre_url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
            }
        
        # Fallback for unknown techniques
        return {
            'technique_id': technique_id,
            'name': 'Unknown Technique',
            'description': context,
            'tactic': 'unknown',
            'tactic_description': '',
            'context': context,
            'mitre_url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
        }
    
    def get_technique_recommendations(self, techniques: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """
        Get defensive recommendations based on identified techniques
        
        Args:
            techniques: List of applicable MITRE ATT&CK techniques
            
        Returns:
            Dictionary of recommendations by category
        """
        recommendations = {
            'immediate_actions': [],
            'security_controls': [],
            'user_training': [],
            'monitoring': []
        }
        
        technique_ids = [t['technique_id'] for t in techniques]
        
        # Phishing-specific recommendations
        if any(tid.startswith('T1566') for tid in technique_ids):
            recommendations['immediate_actions'].extend([
                'Block sender domain/email address',
                'Check for similar emails in organization',
                'Verify legitimacy through separate communication channel'
            ])
            
            recommendations['security_controls'].extend([
                'Implement email authentication (SPF, DKIM, DMARC)',
                'Deploy advanced email security gateway',
                'Enable safe links/attachment scanning'
            ])
            
            recommendations['user_training'].extend([
                'Phishing awareness training',
                'Simulated phishing exercises',
                'Reporting suspicious emails procedure'
            ])
        
        # Credential theft specific
        if any(tid in ['T1598.003', 'T1056.003'] for tid in technique_ids):
            recommendations['security_controls'].extend([
                'Multi-factor authentication (MFA)',
                'Conditional access policies',
                'Password policy enforcement'
            ])
            
            recommendations['monitoring'].extend([
                'Monitor for credential stuffing attempts',
                'Unusual login location alerts',
                'Failed authentication monitoring'
            ])
        
        # Malware delivery specific
        if any(tid in ['T1566.001', 'T1204.002'] for tid in technique_ids):
            recommendations['security_controls'].extend([
                'Endpoint detection and response (EDR)',
                'Application whitelisting',
                'Attachment sandboxing'
            ])
            
            recommendations['monitoring'].extend([
                'File execution monitoring',
                'Network traffic analysis',
                'Behavioral analysis alerts'
            ])
        
        return recommendations
    
    def build_attack_narrative(self, techniques: List[Dict[str, Any]]) -> str:
        """
        Build a narrative explaining the attack chain using MITRE ATT&CK
        
        Args:
            techniques: List of applicable MITRE ATT&CK techniques
            
        Returns:
            Human-readable attack narrative
        """
        if not techniques:
            return "No specific attack techniques identified."
        
        # Group techniques by tactic
        tactics_map = {}
        for technique in techniques:
            tactic = technique['tactic']
            if tactic not in tactics_map:
                tactics_map[tactic] = []
            tactics_map[tactic].append(technique)
        
        # Build narrative based on attack chain
        narrative_parts = []
        
        # Initial Access
        if AttackTactic.INITIAL_ACCESS.value in tactics_map:
            techniques_list = tactics_map[AttackTactic.INITIAL_ACCESS.value]
            narrative_parts.append(
                f"**Initial Access**: The attacker uses {', '.join([t['name'] for t in techniques_list])} "
                f"to gain initial access to the target environment."
            )
        
        # Execution
        if AttackTactic.EXECUTION.value in tactics_map:
            techniques_list = tactics_map[AttackTactic.EXECUTION.value]
            narrative_parts.append(
                f"**Execution**: The attack relies on {', '.join([t['name'] for t in techniques_list])} "
                f"to execute malicious code or actions."
            )
        
        # Credential Access
        if AttackTactic.CREDENTIAL_ACCESS.value in tactics_map:
            techniques_list = tactics_map[AttackTactic.CREDENTIAL_ACCESS.value]
            narrative_parts.append(
                f"**Credential Access**: The attacker attempts {', '.join([t['name'] for t in techniques_list])} "
                f"to steal user credentials."
            )
        
        # Collection
        if AttackTactic.COLLECTION.value in tactics_map:
            techniques_list = tactics_map[AttackTactic.COLLECTION.value]
            narrative_parts.append(
                f"**Collection**: The attack involves {', '.join([t['name'] for t in techniques_list])} "
                f"to gather sensitive information."
            )
        
        # Defense Evasion
        if AttackTactic.DEFENSE_EVASION.value in tactics_map:
            techniques_list = tactics_map[AttackTactic.DEFENSE_EVASION.value]
            narrative_parts.append(
                f"**Defense Evasion**: The attacker uses {', '.join([t['name'] for t in techniques_list])} "
                f"to avoid detection."
            )
        
        return "\n\n".join(narrative_parts)