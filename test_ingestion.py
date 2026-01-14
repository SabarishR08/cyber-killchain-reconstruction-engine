"""
Unit tests for ingestion module.
Tests: log_parser validation, error handling, timestamp formats.
"""
import pytest
from datetime import datetime
from ingestion.log_parser import parse_auth_log
from ingestion.schemas import NormalizedEvent


class TestLogParser:
    """Test log parsing and validation."""
    
    def test_valid_fail_login(self):
        """Test parsing valid failed login."""
        raw = {
            "timestamp": "2026-01-14 10:15:02",
            "user": "alice",
            "src_ip": "192.168.1.10",
            "status": "FAIL"
        }
        event = parse_auth_log(raw)
        
        assert isinstance(event, NormalizedEvent)
        assert event.event_type == "login_failed"
        assert event.severity == 6
        assert event.entity == "alice"
        assert event.metadata["src_ip"] == "192.168.1.10"
    
    def test_valid_success_login(self):
        """Test parsing valid successful login."""
        raw = {
            "timestamp": "2026-01-14 10:15:02",
            "user": "bob",
            "src_ip": "10.0.0.5",
            "status": "SUCCESS"
        }
        event = parse_auth_log(raw)
        
        assert event.event_type == "login_success"
        assert event.severity == 3
        assert event.entity == "bob"
    
    def test_iso_timestamp_format(self):
        """Test ISO 8601 timestamp parsing."""
        raw = {
            "timestamp": "2026-01-14T10:15:02",
            "user": "alice",
            "src_ip": "192.168.1.10",
            "status": "FAIL"
        }
        event = parse_auth_log(raw)
        assert isinstance(event.timestamp, datetime)
    
    def test_missing_required_field(self):
        """Test error on missing required field."""
        raw = {
            "timestamp": "2026-01-14 10:15:02",
            "user": "alice",
            # Missing src_ip and status
        }
        with pytest.raises(ValueError, match="Missing required field"):
            parse_auth_log(raw)
    
    def test_invalid_status(self):
        """Test error on invalid status value."""
        raw = {
            "timestamp": "2026-01-14 10:15:02",
            "user": "alice",
            "src_ip": "192.168.1.10",
            "status": "MAYBE"
        }
        with pytest.raises(ValueError, match="Invalid status"):
            parse_auth_log(raw)
    
    def test_invalid_timestamp(self):
        """Test error on malformed timestamp."""
        raw = {
            "timestamp": "not-a-timestamp",
            "user": "alice",
            "src_ip": "192.168.1.10",
            "status": "FAIL"
        }
        with pytest.raises(ValueError, match="Invalid timestamp format"):
            parse_auth_log(raw)
    
    def test_multiple_timestamp_formats(self):
        """Test parsing multiple timestamp formats."""
        formats = [
            "2026-01-14 10:15:02",
            "2026-01-14T10:15:02",
            "2026-01-14T10:15:02.123456"
        ]
        
        for fmt in formats:
            raw = {
                "timestamp": fmt,
                "user": "alice",
                "src_ip": "192.168.1.10",
                "status": "FAIL"
            }
            event = parse_auth_log(raw)
            assert isinstance(event.timestamp, datetime)
    
    def test_metadata_preservation(self):
        """Test that extra fields are preserved in metadata."""
        raw = {
            "timestamp": "2026-01-14 10:15:02",
            "user": "alice",
            "src_ip": "192.168.1.10",
            "status": "FAIL",
            "auth_method": "password",
            "geo_location": "US"
        }
        event = parse_auth_log(raw)
        assert event.metadata["auth_method"] == "password"
        assert event.metadata["geo_location"] == "US"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
