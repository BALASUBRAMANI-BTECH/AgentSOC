import pytest
from app.services.simulation_service import simulation_service
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_simulation_scenarios_listing():
    scenarios = simulation_service.get_available_scenarios()
    assert len(scenarios) >= 5
    ids = [s["id"] for s in scenarios]
    assert "brute_force" in ids
    assert "port_scan" in ids
    assert "credential_stuffing" in ids
    assert "privilege_abuse" in ids
    assert "data_exfiltration" in ids


def test_simulation_event_generation():
    events = simulation_service.generate_events("port_scan", count_override=5)
    assert len(events) == 5
    assert events[0].event_type == "port_scan"
    assert events[0].source_ip == "10.0.1.99"


def test_simulation_api_endpoint():
    res = client.post("/simulation/trigger", json={"scenario": "port_scan", "count": 3})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["events_injected"] == 3
