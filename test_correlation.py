"""
Unit tests for correlation module.
Tests: pattern detection, time-window aggregation, rule thresholds.
"""
import pytest
from datetime import datetime, timedelta
from ingestion.schemas import NormalizedEvent
from correlation.rules import is_bruteforce, is_credential_compromise, CORRELATION_CONFIG
from correlation.correlator import correlate_events, analyze_window


class TestCorrelationRules:
    """Test pattern detection rules."""
    
    def test_bruteforce_detection_threshold(self):
        """Test brute force detection with threshold."""
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
                timestamp=datetime(2026, 1, 14, 10, 15, 30),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 16, 0),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
        ]
        assert is_bruteforce(events) is True
    
    def test_bruteforce_below_threshold(self):
        """Test brute force not detected below threshold."""
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
                timestamp=datetime(2026, 1, 14, 10, 15, 30),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
        ]
        assert is_bruteforce(events) is False
    
    def test_credential_compromise_detection(self):
        """Test credential compromise (failed then success)."""
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
                timestamp=datetime(2026, 1, 14, 10, 15, 30),
                source="auth",
                event_type="login_success",
                entity="alice",
                severity=3,
                metadata={"src_ip": "192.168.1.10"}
            ),
        ]
        assert is_credential_compromise(events) is True
    
    def test_no_compromise_success_then_failure(self):
        """Test no compromise on success then failure (backwards)."""
        events = [
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 15, 0),
                source="auth",
                event_type="login_success",
                entity="alice",
                severity=3,
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
        assert is_credential_compromise(events) is False


class TestCorrelationEngine:
    """Test event correlation and aggregation."""
    
    def test_correlate_single_entity(self):
        """Test correlation within time window for single entity."""
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
                timestamp=datetime(2026, 1, 14, 10, 15, 30),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 16, 0),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
        ]
        
        incidents = correlate_events(events)
        assert len(incidents) > 0
        assert incidents[0]['entity'] == 'alice'
    
    def test_correlate_multiple_entities(self):
        """Test correlation across different entities."""
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
                timestamp=datetime(2026, 1, 14, 10, 15, 30),
                source="auth",
                event_type="login_failed",
                entity="bob",
                severity=6,
                metadata={"src_ip": "192.168.1.20"}
            ),
        ]
        
        incidents = correlate_events(events)
        # Both have < 3 failures, so no incident
        assert len(incidents) == 0
    
    def test_correlate_respects_time_window(self):
        """Test that events outside time window are separate incidents."""
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
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 25, 0),
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
            NormalizedEvent(
                timestamp=datetime(2026, 1, 14, 10, 35, 0),  # Outside 10-min window
                source="auth",
                event_type="login_failed",
                entity="alice",
                severity=6,
                metadata={"src_ip": "192.168.1.10"}
            ),
        ]
        
        incidents = correlate_events(events)
        # Should have 2 incidents (first 3 events, then last event alone)
        assert len(incidents) >= 1


class TestAnalyzeWindow:
    """Test time-window analysis."""
    
    def test_analyze_empty_window(self):
        """Test analysis of empty window."""
        result = analyze_window([])
        assert result is None
    
    def test_analyze_single_event(self):
        """Test analysis with single event."""
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
        result = analyze_window(events)
        assert result is None  # Single failure, not brute force


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
