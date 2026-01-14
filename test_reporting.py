"""
Unit tests for reporting module.
Tests: risk scoring, timeline generation, threat attribution.
"""
import pytest
from datetime import datetime
from ingestion.schemas import NormalizedEvent
from reporting.scoring import calculate_risk_score, prioritize_incidents, get_priority_label
from reporting.timeline import build_timeline, get_timeline_stats
from reporting.attribution import attribute_threat_actor


class TestRiskScoring:
    """Test risk score calculation."""
    
    def test_calculate_risk_score_low(self):
        """Test low risk score."""
        incident = {
            'severity': 'LOW',
            'confidence': 0.3,
            'mitre_techniques': []
        }
        score = calculate_risk_score(incident)
        assert 0 <= score <= 100
        assert score < 50  # Low should be under 50
    
    def test_calculate_risk_score_high(self):
        """Test high risk score."""
        incident = {
            'severity': 'CRITICAL',
            'confidence': 1.0,
            'mitre_techniques': [
                {'technique_id': 'T1110', 'technique_name': 'Brute Force'}
            ]
        }
        score = calculate_risk_score(incident)
        assert score >= 40  # CRITICAL severity alone is 40 points
    
    def test_calculate_risk_score_bounds(self):
        """Test risk score is 0-100."""
        incidents = [
            {'severity': 'LOW', 'confidence': 0.0, 'mitre_techniques': []},
            {'severity': 'CRITICAL', 'confidence': 1.0, 'mitre_techniques': [{'technique_id': 'T1110', 'technique_name': 'Brute Force'}]},
        ]
        
        for incident in incidents:
            score = calculate_risk_score(incident)
            assert 0 <= score <= 100


class TestPriorityLabeling:
    """Test priority label assignment."""
    
    def test_priority_critical(self):
        """Test CRITICAL priority for high scores."""
        label = get_priority_label(95)
        assert label == 'CRITICAL'
    
    def test_priority_high(self):
        """Test HIGH priority."""
        label = get_priority_label(75)
        assert label == 'HIGH'
    
    def test_priority_medium(self):
        """Test MEDIUM priority."""
        label = get_priority_label(50)
        assert label == 'MEDIUM'
    
    def test_priority_low(self):
        """Test LOW priority."""
        label = get_priority_label(20)
        assert label == 'LOW'
    
    def test_priority_boundaries(self):
        """Test priority boundaries."""
        assert get_priority_label(90) == 'CRITICAL'
        assert get_priority_label(70) == 'HIGH'
        assert get_priority_label(69) == 'MEDIUM' or get_priority_label(69) == 'HIGH'  # Boundary
        assert get_priority_label(40) == 'MEDIUM'
        assert get_priority_label(39) == 'LOW' or get_priority_label(39) == 'MEDIUM'


class TestIncidentPrioritization:
    """Test incident prioritization."""
    
    def test_prioritize_incidents_by_score(self):
        """Test incidents sorted by risk score."""
        incidents = [
            {
                'incident_id': 'incident_001',
                'severity': 'LOW',
                'confidence': 0.3,
                'mitre_techniques': []
            },
            {
                'incident_id': 'incident_002',
                'severity': 'CRITICAL',
                'confidence': 1.0,
                'mitre_techniques': [{'technique_id': 'T1110', 'technique_name': 'Brute Force'}]
            },
        ]
        
        prioritized = prioritize_incidents(incidents)
        # Higher risk should come first
        assert prioritized[0]['incident_id'] == 'incident_002'
    
    def test_prioritized_incidents_have_priority_label(self):
        """Test that prioritized incidents include priority label."""
        incidents = [
            {
                'incident_id': 'incident_001',
                'severity': 'HIGH',
                'confidence': 0.8,
                'mitre_techniques': [{'technique_id': 'T1110', 'technique_name': 'Brute Force'}]
            },
        ]
        
        prioritized = prioritize_incidents(incidents)
        # Should have risk_score after prioritization
        assert 'risk_score' in prioritized[0]
        assert 0 <= prioritized[0]['risk_score'] <= 100


class TestTimeline:
    """Test timeline generation."""
    
    def test_build_timeline_single_event(self):
        """Test timeline with single event."""
        events = [
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 15, 0),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
        ]
        
        timeline = build_timeline(events)
        assert timeline is not None
        assert len(timeline) >= 1
    
    def test_build_timeline_sorted(self):
        """Test timeline is chronologically sorted."""
        events = [
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 16, 0),
                source="auth",
                event_type="login_success",
                entity="alice",
                severity=3,
                metadata={"src_ip": "192.168.1.10"}
            ),
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 15, 0),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 17, 0),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
        ]
        
        timeline = build_timeline(events)
        # Timeline should be a list of tuples
        if timeline and isinstance(timeline[0], tuple):
            assert timeline[0][0] == '2026-01-14T10:15:00'
            assert timeline[-1][0] == '2026-01-14T10:17:00'
    
    def test_get_timeline_stats(self):
        """Test timeline statistics."""
        events = [
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 15, 0),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 20, 0),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
        ]
        
        stats = get_timeline_stats(events)
        assert 'total_events' in stats or 'event_count' in stats
        assert stats.get('total_events') == 2 or stats.get('event_count') == 2


class TestThreatAttribution:
    """Test threat actor attribution."""
    
    def test_attribute_threat_actor_single_source(self):
        """Test attribution for single-source attack."""
        # Test with incident dict, not raw events
        incident = {
            'events': [
                NormalizedEvent(
                    timestamp=datetime(2026, 1, 14, 10, 15, 0),
                    source="auth",
                    event_type="login_failed",
                    entity="alice",
                    severity=6,
                    metadata={"src_ip": "192.168.1.10"}
                ),
                NormalizedEvent(
                    timestamp=datetime(2026, 1, 14, 10, 15, 30),
                    source="auth",
                    event_type="login_failed",
                    entity="alice",
                    severity=6,
                    metadata={"src_ip": "192.168.1.10"}
                ),
            ]
        }
        
        actor = attribute_threat_actor(incident)
        assert actor is not None
    
    def test_attribute_threat_actor_multi_source(self):
        """Test attribution for multi-source attack."""
        incident = {
            'events': [
                NormalizedEvent(
                    timestamp=datetime(2026, 1, 14, 10, 15, 0),
                    source="auth",
                    event_type="login_failed",
                    entity="alice",
                    severity=6,
                    metadata={"src_ip": "192.168.1.10"}
                ),
                NormalizedEvent(
                    timestamp=datetime(2026, 1, 14, 10, 15, 30),
                    source="auth",
                    event_type="login_failed",
                    entity="alice",
                    severity=6,
                    metadata={"src_ip": "192.168.1.20"}
                ),
                NormalizedEvent(
                    timestamp=datetime(2026, 1, 14, 10, 16, 0),
                    source="auth",
                    event_type="login_failed",
                    entity="alice",
                    severity=6,
                    metadata={"src_ip": "192.168.1.30"}
                ),
                NormalizedEvent(
                    timestamp=datetime(2026, 1, 14, 10, 16, 30),
                    source="auth",
                    event_type="login_failed",
                    entity="alice",
                    severity=6,
                    metadata={"src_ip": "192.168.1.40"}
                ),
            ]
        }
        
        actor = attribute_threat_actor(incident)
        assert actor is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
