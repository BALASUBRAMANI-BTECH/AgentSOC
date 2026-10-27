import pytest
from app.models.event import SecurityEvent
from app.detection.rule_engine import rule_engine
from app.detection.ml_engine import ml_engine
from app.services.redis_stream import redis_service


def test_rule_engine_below_threshold():
    test_ip = "192.168.100.1"
    redis_service.reset_counter(test_ip)

    event = SecurityEvent(
        source_ip=test_ip,
        username="user1",
        event_type="login_failed",
        message="1st failed login"
    )
    result = rule_engine.evaluate_event(event)
    assert result["threat_detected"] is False
    assert result["failed_attempts"] == 1


def test_rule_engine_reaches_threshold():
    test_ip = "192.168.100.2"
    redis_service.reset_counter(test_ip)

    event = SecurityEvent(
        source_ip=test_ip,
        username="admin",
        event_type="login_failed",
        message="Failed login"
    )

    result = None
    for _ in range(5):
        result = rule_engine.evaluate_event(event)

    assert result["threat_detected"] is True
    assert result["threat_type"] == "Brute Force Attack"
    assert result["failed_attempts"] >= 5
    assert "T1110" in result["mitre_technique"]


def test_ml_engine_anomaly_prediction():
    event = SecurityEvent(
        source_ip="192.168.1.50",
        username="admin",
        event_type="login_failed",
        message="High velocity failure burst"
    )
    res = ml_engine.predict_anomaly(event, velocity=15)
    assert res["detected"] is True
    assert "Brute-Force" in res["attack_type"]
    assert res["confidence"] >= 0.60

