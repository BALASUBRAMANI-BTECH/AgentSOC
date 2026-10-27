import pytest
from app.models.incident import Incident, IncidentSeverity
from app.agents.graph import investigation_service


def test_langgraph_multi_agent_investigation():
    inc = Incident(
        title="Brute force incident",
        description="Investigation test",
        attack_type="Brute Force Attack",
        source_ip="192.168.1.50",
        username="admin",
        event_count=347
    )

    report = investigation_service.investigate(inc)
    assert report.incident_id == inc.incident_id
    assert report.status == "COMPLETED"
    assert report.mitre_technique == "T1110"
    assert len(report.recommended_responses) >= 2
    assert "Block IP" in report.recommended_responses[0]
    assert len(report.agent_logs) == 5

    # Verify 5 distinct agents executed sequentially
    agent_names = [log.agent_name for log in report.agent_logs]
    assert "Detection Agent" in agent_names
    assert "Threat Intel Agent" in agent_names
    assert "Investigation Agent" in agent_names
    assert "Risk Analysis Agent" in agent_names
    assert "Response Agent" in agent_names

