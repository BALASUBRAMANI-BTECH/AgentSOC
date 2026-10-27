import pytest
from app.models.incident import Incident, IncidentSeverity
from app.scoring.risk_engine import risk_engine
from app.mitre.mapper import mitre_mapper


def test_mitre_mapping():
    mapping = mitre_mapper.map_attack("Brute Force Attack")
    assert mapping["technique_id"] == "T1110"
    assert mapping["technique_name"] == "Brute Force"
    assert "Credential Access" in mapping["tactic"]
    assert mapping["mapping_confidence"] >= 0.90


def test_risk_scoring_calibration():
    # Benchmark requirement: High-frequency brute-force on admin from high-abuse IP -> ~94 CRITICAL
    inc = Incident(
        title="Brute force test",
        description="Benchmark simulation",
        attack_type="Brute Force Attack",
        source_ip="192.168.1.50",
        username="admin",
        event_count=347
    )
    threat_intel = {"abuse_score": 88, "reputation": "SUSPICIOUS_HIGH"}
    score, severity, factors = risk_engine.calculate_risk(inc, threat_intel)

    assert score == 94
    assert severity == IncidentSeverity.CRITICAL
    assert len(factors) >= 3


def test_risk_scoring_low_severity():
    inc = Incident(
        title="Low threat",
        description="Isolated issue",
        attack_type="Suspicious Activity",
        source_ip="10.0.1.2",
        username="guest",
        event_count=1
    )
    threat_intel = {"abuse_score": 10, "reputation": "INTERNAL_CLEAN"}
    score, severity, factors = risk_engine.calculate_risk(inc, threat_intel, detection_confidence=0.6)

    assert score < 50
    assert severity in [IncidentSeverity.LOW, IncidentSeverity.MEDIUM]

