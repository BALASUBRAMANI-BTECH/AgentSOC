import pytest
from app.models.incident import Incident, IncidentSeverity
from app.services.report_exporter import report_exporter
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_markdown_report_generation():
    inc = Incident(
        title="APT-29 Tor Relay Ingress",
        description="State-sponsored credential spraying",
        attack_type="Brute Force Attack",
        severity=IncidentSeverity.CRITICAL,
        risk_score=94,
        source_ip="185.220.101.5",
        username="admin",
        event_count=50
    )
    md = report_exporter.generate_markdown_report(inc)
    assert "# AGENTSOC — INCIDENT FORENSIC DOSSIER" in md
    assert "APT-29 Tor Relay Ingress" in md
    assert "185.220.101.5" in md
    assert "94 / 100" in md
    assert "MITRE ATT&CK" in md


def test_report_download_endpoint():
    # Ingest event to generate incident
    ev_res = client.post("/events", json={
        "source_ip": "198.51.100.23",
        "destination_ip": "10.0.0.1",
        "username": "admin",
        "event_type": "login_failed",
        "message": "Report test event"
    })
    incident_id = ev_res.json()["incident"]["incident_id"] if ev_res.json().get("incident") else None
    if not incident_id:
        # Force threshold
        for _ in range(5):
            r = client.post("/events", json={
                "source_ip": "198.51.100.23",
                "destination_ip": "10.0.0.1",
                "username": "admin",
                "event_type": "login_failed",
                "message": "Report threshold event"
            })
            if r.json().get("incident"):
                incident_id = r.json()["incident"]["incident_id"]
                break

    if incident_id:
        res = client.get(f"/incidents/{incident_id}/report/markdown")
        assert res.status_code == 200
        assert "AGENTSOC — INCIDENT FORENSIC DOSSIER" in res.text

        export_res = client.get(f"/incidents/{incident_id}/export")
        assert export_res.status_code == 200
        assert "incident" in export_res.json()
