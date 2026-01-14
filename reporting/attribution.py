# reporting/attribution.py
from typing import Dict, Any, List
from ingestion.schemas import NormalizedEvent
from killchain.mitre_mapping import enrich_incident_with_mitre


def attribute_threat_actor(incident: Dict[str, Any]) -> str:
    """
    Infer threat actor profile based on incident characteristics.
    Honest, heuristic-based (not speculative).
    """
    sources = set()
    for event in incident.get("events", []):
        src_ip = event.metadata.get("src_ip")
        if src_ip:
            sources.add(src_ip)
    
    event_count = incident.get("event_count", 0)
    confidence = incident.get("confidence", 0)
    pattern = incident.get("pattern", "")
    
    # Heuristic 1: Multiple sources suggests automated attack
    if len(sources) >= 3:
        return "Likely automated attack (botnet/spray)"
    
    # Heuristic 2: High confidence + specific pattern suggests targeted
    if confidence > 0.85 and "Credential" in pattern:
        return "Likely targeted credential attack"
    
    # Heuristic 3: High event count suggests persistent effort
    if event_count >= 5:
        return "Persistent attack (human-guided or coordinated)"
    
    # Default: uncertain
    return "Unknown/Opportunistic activity"


def generate_incident_explanation(incident: Dict[str, Any]) -> str:
    """Generate analyst-readable explanation of incident."""
    entity = incident.get("entity", "UNKNOWN")
    pattern = incident.get("pattern", "Unknown pattern")
    event_count = incident.get("event_count", 0)
    confidence = incident.get("confidence", 0)
    
    # Get MITRE info (if enriched)
    mitre = incident.get("mitre", {})
    technique_id = mitre.get("technique_id", "UNKNOWN")
    technique_name = mitre.get("technique_name", "Unknown")
    tactic = mitre.get("tactic", "Unknown")
    
    explanation = (
        f"A {pattern} was detected targeting entity '{entity}' "
        f"involving {event_count} authentication event(s). "
        f"Detection confidence: {int(confidence * 100)}%. "
        f"Mapped to MITRE ATT&CK technique {technique_id} ({technique_name}) "
        f"under the {tactic} tactic."
    )
    
    return explanation


def score_incident_confidence(incident: Dict[str, Any]) -> float:
    """
    Score confidence in incident classification.
    
    Factors:
    - Event count (more events = higher confidence)
    - Pattern specificity
    """
    event_count = incident.get("event_count", 0)
    pattern = incident.get("pattern", "")
    
    # Base score on event count
    confidence = min(event_count / 5, 0.7)  # 5+ events = 0.7 base
    
    # Add pattern-specific bonuses
    if pattern == "Brute Force Authentication Attempt":
        confidence += 0.3  # High confidence pattern
    elif pattern == "Possible Credential Compromise":
        confidence += 0.25  # Medium-high confidence pattern
    
    return round(min(confidence, 1.0), 2)


def generate_incident_report(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate comprehensive incident report with all enrichments.
    """
    # Score confidence if not already scored
    if "confidence" not in incident:
        incident["confidence"] = score_incident_confidence(incident)
    
    # Enrich with MITRE
    incident = enrich_incident_with_mitre(incident)
    
    # Attribute threat actor
    attribution = attribute_threat_actor(incident)
    
    # Generate explanation
    explanation = generate_incident_explanation(incident)
    
    return {
        "summary": {
            "entity": incident.get("entity"),
            "pattern": incident.get("pattern"),
            "kill_chain_stage": incident.get("kill_chain_stage"),
            "event_count": incident.get("event_count"),
            "confidence": incident.get("confidence"),
        },
        "severity": determine_severity(incident),
        "attribution": attribution,
        "mitre": incident.get("mitre"),
        "explanation": explanation,
        "timeline_length": len(incident.get("events", [])),
    }


def determine_severity(incident: Dict[str, Any]) -> str:
    """Determine incident severity."""
    pattern = incident.get("pattern", "")
    event_count = incident.get("event_count", 0)
    confidence = incident.get("confidence", 0)
    
    # Severity is based on pattern type and confidence
    if pattern == "Possible Credential Compromise":
        return "HIGH" if confidence > 0.7 else "MEDIUM"
    elif pattern == "Brute Force Authentication Attempt":
        if event_count >= 5 and confidence > 0.8:
            return "HIGH"
        elif event_count >= 3:
            return "MEDIUM"
        return "LOW"
    
    return "MEDIUM"
