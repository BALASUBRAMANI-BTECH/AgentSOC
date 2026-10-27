import pytest
from app.models.event import SecurityEvent
from app.correlation.engine import correlation_engine
from app.database.mongodb import db_repo


@pytest.mark.asyncio
async def test_event_correlation_and_timeline():
    event1 = SecurityEvent(
        source_ip="192.168.1.55",
        username="admin",
        event_type="login_failed",
        message="Failed password attempt #1"
    )
    detection = {
        "threat_detected": True,
        "threat_type": "Brute Force Attack",
        "rule_name": "RULE_EXCESSIVE_FAILED_LOGINS",
        "confidence": 0.95,
        "mitre_technique": "T1110",
        "evidence": ["Threshold exceeded"]
    }

    # First event creates new incident
    inc1 = await correlation_engine.correlate_event(event1, detection)
    assert inc1 is not None
    assert inc1.event_count == 1
    assert len(inc1.timeline) == 1
    incident_id = inc1.incident_id

    # Second event from same source correlates into the same incident
    event2 = SecurityEvent(
        source_ip="192.168.1.55",
        username="admin",
        event_type="login_failed",
        message="Failed password attempt #2"
    )
    inc2 = await correlation_engine.correlate_event(event2, detection)
    assert inc2.incident_id == incident_id
    assert inc2.event_count == 2
    assert len(inc2.timeline) == 2

