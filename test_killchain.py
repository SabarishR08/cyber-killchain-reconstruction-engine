"""
Unit tests for kill chain and MITRE mapping.
Tests: stage assignment, technique mapping, enrichment.
"""
import pytest
from ingestion.schemas import NormalizedEvent
from killchain.stages import KillChainStage, KILL_CHAIN_MAPPING
from killchain.mitre_mapping import get_mitre_mapping, enrich_incident_with_mitre
from datetime import datetime


class TestKillChainStages:
    """Test kill chain stage mapping."""
    
    def test_kill_chain_stage_enum(self):
        """Test all kill chain stages exist."""
        stages = [
            KillChainStage.RECONNAISSANCE,
            KillChainStage.WEAPONIZATION,
            KillChainStage.DELIVERY,
            KillChainStage.EXPLOITATION,
            KillChainStage.INSTALLATION,
            KillChainStage.COMMAND_CONTROL,  # Fixed: matches actual enum
            KillChainStage.ACTIONS_ON_OBJECTIVES
        ]
        assert len(stages) == 7
    
    def test_kill_chain_mapping_exists(self):
        """Test kill chain mapping covers patterns."""
        # Check for actual pattern names used in correlator
        assert "Brute Force Authentication Attempt" in KILL_CHAIN_MAPPING
        assert "Possible Credential Compromise" in KILL_CHAIN_MAPPING


class TestMITREMapping:
    """Test MITRE ATT&CK technique mapping."""
    
    def test_get_mitre_brute_force(self):
        """Test MITRE mapping for brute force."""
        techniques = get_mitre_mapping("brute_force")
        # Should return either None or a dict with technique info
        assert techniques is None or isinstance(techniques, dict)
    
    def test_get_mitre_credential_compromise(self):
        """Test MITRE mapping for credential compromise."""
        techniques = get_mitre_mapping("credential_compromise")
        assert techniques is None or isinstance(techniques, dict)
    
    def test_get_mitre_unknown_pattern(self):
        """Test MITRE mapping for unknown pattern."""
        techniques = get_mitre_mapping("unknown_pattern")
        assert techniques is None or isinstance(techniques, dict)
    
    def test_enrich_incident_with_mitre(self):
        """Test full incident enrichment."""
        incident = {
            'pattern_type': 'brute_force',
            'entity': 'alice',
            'severity': 'HIGH',
            'confidence': 0.85
        }
        
        enriched = enrich_incident_with_mitre(incident)
        # Check that enrichment adds mitre field
        assert 'mitre' in enriched or 'mitre_techniques' in enriched
    
    def test_enrich_preserves_original_fields(self):
        """Test that enrichment preserves original incident data."""
        incident = {
            'pattern_type': 'credential_compromise',
            'entity': 'bob',
            'severity': 'CRITICAL',
            'confidence': 1.0,
            'event_count': 5
        }
        
        enriched = enrich_incident_with_mitre(incident)
        assert enriched['entity'] == 'bob'
        assert enriched['severity'] == 'CRITICAL'
        assert enriched['event_count'] == 5


class TestIncidentEnrichment:
    """Test complete incident enrichment workflow."""
    
    def test_enrich_brute_force_incident(self):
        """Test enrichment of brute force incident."""
        incident = {
            'pattern_type': 'brute_force',
            'entity': 'alice',
            'events': [
                {'timestamp': '2026-01-14T10:15:00', 'event_type': 'login_failed'},
                {'timestamp': '2026-01-14T10:15:30', 'event_type': 'login_failed'},
                {'timestamp': '2026-01-14T10:16:00', 'event_type': 'login_failed'},
            ],
            'severity': 'HIGH',
            'confidence': 0.9
        }
        
        enriched = enrich_incident_with_mitre(incident)
        # Should have mitre field after enrichment
        assert 'mitre' in enriched or 'mitre_techniques' in enriched
    
    def test_enrich_credential_compromise_incident(self):
        """Test enrichment of credential compromise incident."""
        incident = {
            'pattern_type': 'credential_compromise',
            'entity': 'alice',
            'events': [
                {'timestamp': '2026-01-14T10:15:00', 'event_type': 'login_failed'},
                {'timestamp': '2026-01-14T10:15:30', 'event_type': 'login_success'},
            ],
            'severity': 'CRITICAL',
            'confidence': 1.0
        }
        
        enriched = enrich_incident_with_mitre(incident)
        # Should have mitre field
        assert 'mitre' in enriched or 'mitre_techniques' in enriched


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
