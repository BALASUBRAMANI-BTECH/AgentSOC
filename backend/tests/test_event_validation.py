import pytest
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentSeverity, IncidentStatus


def test_security_event_validation():
    event = SecurityEvent(
        source_ip="192.168.1.50",
        username="admin",
        event_type="login_failed",
        message="Failed password attempt"
    )
    assert event.event_id.startswith("evt_")
    assert event.source_ip == "192.168.1.50"
    assert event.username == "admin"
    assert event.severity == "LOW"


def test_incident_model_validation():
    inc = Incident(
        title="Test Brute Force",
        description="Testing incident model",
        attack_type="Brute Force Attack",
        severity=IncidentSeverity.CRITICAL,
        risk_score=94,
        source_ip="192.168.1.50",
        username="admin"
    )
    assert inc.incident_id.startswith("INC-")
    assert inc.risk_score == 94
    assert inc.severity == IncidentSeverity.CRITICAL
    assert inc.status == IncidentStatus.OPEN

