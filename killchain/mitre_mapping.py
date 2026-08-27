# killchain/mitre_mapping.py
from typing import Dict, Any, Optional


MITRE_TECHNIQUES = {
    "Brute Force Authentication Attempt": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary attempts to gain initial access or escalate privileges by guessing user credentials.",
        "severity_modifier": 1.1
    },
    "Possible Credential Compromise": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversary used compromised or guessed user account credentials to gain initial access.",
        "severity_modifier": 1.2
    },
    # ── Network-Traffic-Specific Mappings (SIH26153) ──
    "Port Scan to Exploit Attempt": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversary scanned network services then attempted exploitation of discovered ports.",
        "severity_modifier": 1.3
    },
    "DoS Traffic Spike": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "High-volume traffic spike from single source indicating denial-of-service activity.",
        "severity_modifier": 1.25
    }
}


def get_mitre_mapping(pattern: str) -> Optional[Dict[str, Any]]:
    """Get MITRE ATT&CK mapping for a pattern."""
    return MITRE_TECHNIQUES.get(pattern)


def enrich_incident_with_mitre(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich incident with MITRE ATT&CK technique information."""
    pattern = incident.get("pattern")
    mitre_mapping = get_mitre_mapping(pattern)
    
    if mitre_mapping:
        incident["mitre"] = mitre_mapping
        # Adjust confidence based on technique severity
        incident["confidence"] = min(
            incident.get("confidence", 0.5) * mitre_mapping["severity_modifier"],
            1.0
        )
    else:
        incident["mitre"] = {
            "technique_id": "UNKNOWN",
            "technique_name": "Unknown",
            "tactic": "Unknown",
            "description": "Technique not mapped in current MITRE database."
        }
    
    return incident
