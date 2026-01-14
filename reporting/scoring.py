# reporting/scoring.py
from typing import Dict, Any


def calculate_risk_score(incident: Dict[str, Any]) -> int:
    """
    Calculate risk score for incident prioritization.
    
    Scoring model:
    - Severity: 0-40 points
    - Confidence: 0-40 points
    - MITRE alignment: 0-20 points
    
    Total: 0-100 (higher = more urgent)
    """
    score = 0
    
    # Severity scoring
    severity = incident.get("severity", "MEDIUM")
    if severity == "HIGH":
        score += 40
    elif severity == "MEDIUM":
        score += 25
    else:
        score += 10
    
    # Confidence scoring (0-40 points)
    confidence = incident.get("confidence", 0)
    score += int(confidence * 40)
    
    # MITRE enrichment bonus (0-20 points)
    if incident.get("mitre") and incident["mitre"].get("technique_id") != "UNKNOWN":
        score += 20
    
    # Cap at 100
    return min(int(score), 100)


def prioritize_incidents(incidents: list) -> list:
    """
    Sort incidents by risk score (highest first).
    """
    scored = [
        {
            **incident,
            "risk_score": calculate_risk_score(incident)
        }
        for incident in incidents
    ]
    
    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)


def get_priority_label(risk_score: int) -> str:
    """Convert risk score to priority label."""
    if risk_score >= 80:
        return "CRITICAL"
    elif risk_score >= 60:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"
