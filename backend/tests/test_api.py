import pytest
import sys
from pathlib import Path
from fastapi.testclient import TestClient

backend_path = Path(__file__).resolve().parent.parent
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_auth_login_and_me():
    # Admin login with locked master password
    admin_res = client.post("/auth/login", json={"password": "24282428"})
    assert admin_res.status_code == 200
    admin_data = admin_res.json()
    assert admin_data["user"]["role"] == "SOC_ADMIN"
    admin_token = admin_data["access_token"]

    # Verify session
    me_res = client.get("/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "admin"

    # Analyst login
    analyst_res = client.post("/auth/login", json={"password": "any_other_password"})
    assert analyst_res.status_code == 200
    assert analyst_res.json()["user"]["role"] == "SOC_ANALYST"


def test_events_and_incident_generation():
    test_ip = "192.168.200.5"
    res = None
    for i in range(5):
        res = client.post("/events", json={
            "source_ip": test_ip,
            "username": "admin",
            "event_type": "login_failed",
            "message": f"Credential failure #{i+1}"
        })
        assert res.status_code == 200

    data = res.json()
    assert data["status"] == "received"
    assert data["threat_detected"] is True
    assert data["incident"] is not None

    incident_id = data["incident"]["incident_id"]

    # Fetch incident detail
    inc_res = client.get(f"/incidents/{incident_id}")
    assert inc_res.status_code == 200
    assert inc_res.json()["incident_id"] == incident_id

    # Fetch timeline
    tl_res = client.get(f"/incidents/{incident_id}/timeline")
    assert tl_res.status_code == 200
    assert len(tl_res.json()) >= 1

    # Fetch risk analysis
    risk_res = client.get(f"/incidents/{incident_id}/risk")
    assert risk_res.status_code == 200
    assert "risk_score" in risk_res.json()

    # Fetch MITRE mapping
    mitre_res = client.get(f"/incidents/{incident_id}/mitre")
    assert mitre_res.status_code == 200
    assert mitre_res.json()["technique_id"] == "T1110"


def test_dashboard_stats():
    res = client.get("/dashboard/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "total_events" in stats
    assert "active_incidents" in stats


def test_ai_copilot_assistant():
    res = client.post("/assistant/chat", json={
        "message": "What is the status of active critical threats?"
    })
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert len(data["suggestions"]) >= 1


def test_rbac_analyst_restriction_and_admin_execution():
    # Login as analyst
    analyst_res = client.post("/auth/login", json={"password": "analyst_pass"})
    analyst_token = analyst_res.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Trigger incident
    ev_res = client.post("/events", json={
        "source_ip": "192.168.200.99",
        "username": "admin",
        "event_type": "login_failed",
        "message": "Threshold test"
    })
    incident_id = ev_res.json()["incident"]["incident_id"] if ev_res.json().get("incident") else None

    if not incident_id:
        # Generate enough to reach threshold
        for _ in range(5):
            ev_res = client.post("/events", json={
                "source_ip": "192.168.200.99",
                "username": "admin",
                "event_type": "login_failed",
                "message": "Threshold trigger"
            })
        incident_id = ev_res.json()["incident"]["incident_id"]

    # Analyst blocked from status mutation -> 403
    patch_res = client.patch(
        f"/incidents/{incident_id}/status?status=CONTAINED",
        headers=analyst_headers
    )
    assert patch_res.status_code == 403

    # Analyst blocked from executing responses -> 403
    resp_res = client.post(
        f"/responses/{incident_id}",
        json={"action_type": "BLOCK_IP", "simulated": True},
        headers=analyst_headers
    )
    assert resp_res.status_code == 403

    # Admin execution succeeds -> 200
    admin_res = client.post("/auth/login", json={"password": "24282428"})
    admin_token = admin_res.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    admin_resp = client.post(
        f"/responses/{incident_id}",
        json={"action_type": "BLOCK_IP", "simulated": True},
        headers=admin_headers
    )
    assert admin_resp.status_code == 200
    assert admin_resp.json()["action_type"] == "BLOCK_IP"

