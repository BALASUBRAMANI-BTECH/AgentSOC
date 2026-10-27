import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Header
from pydantic import BaseModel
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentStatus, IncidentTimelineEntry
from app.models.investigation import InvestigationReport
from app.models.response import ResponseAction, ResponseActionType, ResponseAuditRecord
from app.models.auth import (
    LoginRequest,
    LoginResponse,
    UserProfile,
    AssistantChatRequest,
    AssistantChatResponse
)
from app.database.mongodb import db_repo
from app.services.redis_stream import redis_service
from app.services.websocket_manager import ws_manager
from app.services.auth_service import auth_service
from app.services.threat_intel_service import threat_intel_service
from app.services.assistant_service import assistant_service
from app.detection.rule_engine import rule_engine
from app.detection.ml_engine import ml_engine
from app.correlation.engine import correlation_engine
from app.scoring.risk_engine import risk_engine
from app.mitre.mapper import mitre_mapper
from app.agents.graph import investigation_service
from app.response.engine import response_engine
from app.services.simulation_service import simulation_service
from app.services.report_exporter import report_exporter
from fastapi.responses import PlainTextResponse

logger = logging.getLogger(__name__)

router = APIRouter()


class ExecuteResponsePayload(BaseModel):
    action_type: ResponseActionType = ResponseActionType.BLOCK_IP
    target: Optional[str] = None
    simulated: bool = True


# ==========================================
# 1. AUTHENTICATION & RBAC
# ==========================================
@router.post("/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    """Authenticate SOC operator and return access token."""
    user = auth_service.authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials or locked admin password")
    token = auth_service.create_token(user)
    return LoginResponse(access_token=token, user=user)


@router.get("/auth/me", response_model=UserProfile)
async def get_current_user(authorization: Optional[str] = Header(None)):
    """Verify session token and return user profile."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer token")
    token = authorization.split(" ")[1]
    user = auth_service.verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Token expired or invalid")
    return user


@router.post("/auth/logout")
async def logout():
    return {"status": "logged_out", "message": "Session invalidated"}


# ==========================================
# 2. EVENT COLLECTOR & STREAMING
# ==========================================
@router.post("/events")
async def receive_event(event: SecurityEvent):
    """
    Event Collector API:
    Accepts, validates, streams to Redis, evaluates through Rule + ML engines,
    correlates into incidents, calculates risk scores, and broadcasts over WebSocket.
    """
    # 1. Save to MongoDB & Redis Stream
    await db_repo.save_event(event)
    redis_service.publish_event(event)

    # 2. Threat Detection (Rule Engine + Scikit-learn ML Engine)
    rule_result = rule_engine.evaluate_event(event)
    failed_attempts = redis_service.get_failed_logins(event.source_ip)
    ml_result = ml_engine.predict_anomaly(event, velocity=failed_attempts)

    # 3. Event Correlation Engine
    incident = await correlation_engine.correlate_event(
        event=event,
        detection=rule_result,
        ml_result=ml_result
    )

    # 4. If an incident was generated/updated, compute updated risk score, MITRE mapping & AI investigation
    if incident:
        intel = threat_intel_service.check_ip_reputation(incident.source_ip)
        risk_score, severity, factors = risk_engine.calculate_risk(
            incident=incident,
            threat_intel=intel,
            detection_confidence=max(rule_result.get("confidence", 0.8), ml_result.get("confidence", 0.8))
        )
        incident.risk_score = risk_score
        incident.severity = severity
        incident.evidence["contributing_factors"] = factors
        if not incident.target_user and incident.username:
            incident.target_user = incident.username

        # Map MITRE ATT&CK technique
        mapping = mitre_mapper.map_incident(incident)
        if isinstance(mapping, dict):
            incident.mitre_mapping = mapping
            incident.mitre_technique = mapping.get("technique_id", "T1110")
            incident.mitre_name = mapping.get("technique_name", "Brute Force")
        else:
            incident.mitre_mapping = mapping.model_dump(mode="json")
            incident.mitre_technique = mapping.technique_id
            incident.mitre_name = mapping.technique_name

        # Execute autonomous multi-agent LangGraph investigation
        report = investigation_service.investigate(incident)
        incident.investigation_report = report.model_dump(mode="json")
        await db_repo.save_investigation(report)

        await db_repo.save_incident(incident)

    # 5. Real-Time WebSocket Broadcast
    try:
        await ws_manager.broadcast({
            "type": "NEW_EVENT",
            "event": event.model_dump(mode="json"),
            "detection": rule_result,
            "ml_detection": ml_result,
            "incident": incident.model_dump(mode="json") if incident else None
        })
    except Exception as e:
        logger.debug(f"Broadcast error: {e}")

    return {
        "status": "received",
        "event_id": event.event_id,
        "threat_detected": rule_result.get("threat_detected") or ml_result.get("detected"),
        "rule_detection": rule_result,
        "ml_detection": ml_result,
        "incident": incident
    }


@router.get("/events", response_model=List[SecurityEvent])
async def get_events(limit: int = Query(default=50, ge=1, le=500)):
    """Retrieve recent security events."""
    return await db_repo.get_events(limit=limit)


# ==========================================
# 3. INCIDENTS & CORRELATION
# ==========================================
@router.get("/incidents", response_model=List[Incident])
async def get_incidents(
    status: Optional[str] = Query(default=None, description="Filter by status (OPEN, INVESTIGATING, CONTAINED, CLOSED)"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    limit: int = Query(default=50, ge=1, le=200)
):
    """Retrieve security incidents with optional status and severity filtering."""
    return await db_repo.get_incidents(status=status, severity=severity, limit=limit)


@router.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    """Retrieve detailed information for a specific security incident."""
    inc = await db_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return inc


@router.get("/incidents/{incident_id}/timeline", response_model=List[IncidentTimelineEntry])
async def get_incident_timeline(incident_id: str):
    """Retrieve the chronological event timeline for an incident."""
    inc = await db_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return inc.timeline


@router.patch("/incidents/{incident_id}/status", response_model=Incident)
async def update_incident_status(
    incident_id: str,
    status: IncidentStatus,
    authorization: Optional[str] = Header(None)
):
    """Update lifecycle status of an incident. Analyst role is restricted to read-only."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        user = auth_service.verify_token(token)
        if user and user.role == "SOC_ANALYST":
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Analyst role has read-only access. Only SOC Administrators can modify incident status."
            )

    inc = await db_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    inc.status = status
    await db_repo.save_incident(inc)

    # Broadcast update
    await ws_manager.broadcast({
        "type": "INCIDENT_UPDATE",
        "incident": inc.model_dump(mode="json")
    })
    return inc


# ==========================================
# 4. AI INVESTIGATION (LANGGRAPH)
# ==========================================
@router.post("/investigations/{incident_id}", response_model=InvestigationReport)
async def trigger_ai_investigation(
    incident_id: str,
    authorization: Optional[str] = Header(None)
):
    """
    Trigger LangGraph autonomous multi-agent AI investigation:
    Detection Agent -> Threat Intel Agent -> Investigation Agent -> Risk Agent -> Response Agent.
    Analyst role is restricted to read-only.
    """
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        user = auth_service.verify_token(token)
        if user and user.role == "SOC_ANALYST":
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Analyst role has read-only access. Only SOC Administrators can trigger new AI investigations."
            )

    inc = await db_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    # Set status to INVESTIGATING
    inc.status = IncidentStatus.INVESTIGATING
    await db_repo.save_incident(inc)

    # Run LangGraph multi-agent pipeline
    report = investigation_service.investigate(inc)
    await db_repo.save_investigation(report)

    # Sync calculated risk score back to incident
    inc.risk_score = report.risk_score
    inc.severity = report.severity
    await db_repo.save_incident(inc)

    await ws_manager.broadcast({
        "type": "INVESTIGATION_COMPLETED",
        "incident_id": incident_id,
        "report": report.model_dump(mode="json")
    })

    return report


@router.get("/incidents/{incident_id}/investigation", response_model=InvestigationReport)
@router.get("/investigations/{incident_id}", response_model=InvestigationReport)
async def get_investigation_report(incident_id: str):
    """Retrieve existing AI investigation report for an incident."""
    report = await db_repo.get_investigation(incident_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Investigation report for '{incident_id}' not found")
    return report


# ==========================================
# 5. RISK SCORING & MITRE ATT&CK
# ==========================================
@router.get("/incidents/{incident_id}/risk")
async def get_incident_risk(incident_id: str):
    """Explainable risk-score analysis breakdown."""
    inc = await db_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    intel = threat_intel_service.check_ip_reputation(inc.source_ip)
    score, severity, factors = risk_engine.calculate_risk(inc, intel)

    return {
        "incident_id": incident_id,
        "risk_score": score,
        "severity": severity.value,
        "contributing_factors": factors,
        "event_velocity": inc.event_count,
        "target_account": inc.username
    }


@router.get("/incidents/{incident_id}/mitre")
async def get_incident_mitre(incident_id: str):
    """MITRE ATT&CK technique mapping details for an incident."""
    inc = await db_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    return mitre_mapper.map_attack(inc.attack_type, inc.mitre_technique)


# ==========================================
# 6. RESPONSE ACTIONS & AUDITING
# ==========================================
@router.post("/incidents/{incident_id}/response", response_model=ResponseAction)
@router.post("/responses/{incident_id}", response_model=ResponseAction)
async def execute_response(
    incident_id: str,
    payload: ExecuteResponsePayload,
    authorization: Optional[str] = Header(None)
):
    """
    Execute or simulate containment actions (Block IP, Lock Account, Isolate Host).
    Analyst role is restricted to read-only.
    """
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        user = auth_service.verify_token(token)
        if user and user.role == "SOC_ANALYST":
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Analyst role has read-only access. Only SOC Administrators can authorize containment actions."
            )

    inc = await db_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    target = payload.target or (inc.username if payload.action_type == ResponseActionType.LOCK_ACCOUNT else inc.source_ip)

    action = await response_engine.execute_action(
        incident_id=incident_id,
        action_type=payload.action_type,
        target=target,
        simulated=payload.simulated
    )

    await ws_manager.broadcast({
        "type": "RESPONSE_EXECUTED",
        "action": action.model_dump(mode="json")
    })

    return action


@router.get("/incidents/{incident_id}/responses", response_model=List[ResponseAction])
@router.get("/responses/{incident_id}", response_model=List[ResponseAction])
async def get_incident_responses(incident_id: str):
    """Retrieve containment response history and audit actions for an incident."""
    return await response_engine.get_actions_for_incident(incident_id)


@router.get("/responses", response_model=List[ResponseAction])
async def get_all_responses():
    """Retrieve containment response history across all incidents."""
    return await db_repo.get_responses()


@router.get("/audit", response_model=List[ResponseAuditRecord])
async def get_audit_trail():
    """Retrieve global immutable containment audit trail."""
    return await db_repo.get_audit_records()


# ==========================================
# 7. DASHBOARD STATS & AI ASSISTANT
# ==========================================
@router.get("/dashboard/stats")
async def get_dashboard_stats():
    """Retrieve summary metrics for the SOC dashboard."""
    return await db_repo.get_stats()


@router.post("/assistant/chat", response_model=AssistantChatResponse)
async def assistant_chat(req: AssistantChatRequest):
    """Interactive AI Security Assistant chat endpoint."""
    return await assistant_service.chat(req.message, req.incident_id)


@router.get("/assistant/suggestions", response_model=List[str])
async def assistant_suggestions():
    """Suggested prompts for the SOC Copilot."""
    return assistant_service.DEFAULT_SUGGESTIONS


# ==========================================
# 8. THREAT INTELLIGENCE & IOC SCANNER
# ==========================================
@router.get("/threat-intel/lookup/{ioc:path}")
async def threat_intel_lookup(ioc: str):
    """Inspects reputation for an IP, domain, or hash IOC."""
    return threat_intel_service.lookup_ioc(ioc)


@router.get("/threat-intel/feed")
async def threat_intel_feed():
    """Returns curated active global threat intelligence feed."""
    return threat_intel_service.get_threat_feed()


# ==========================================
# 9. ATTACK SIMULATION HUB
# ==========================================
class SimulationTriggerRequest(BaseModel):
    scenario: str = "brute_force"
    count: Optional[int] = None


@router.get("/simulation/scenarios")
async def get_simulation_scenarios():
    """Retrieve available adversary attack simulation scenarios."""
    return simulation_service.get_available_scenarios()


@router.post("/simulation/trigger")
async def trigger_simulation(payload: SimulationTriggerRequest):
    """
    Triggers an automated adversary attack simulation scenario,
    ingesting events through detection, correlation, and multi-agent investigation.
    """
    events = simulation_service.generate_events(payload.scenario, payload.count)
    correlated_incident = None
    ingested_count = 0

    for ev in events:
        res = await receive_event(ev)
        ingested_count += 1
        if res.get("incident"):
            correlated_incident = res["incident"]

    return {
        "status": "SUCCESS",
        "scenario": payload.scenario,
        "events_injected": ingested_count,
        "correlated_incident": correlated_incident
    }


# ==========================================
# 10. FORENSIC DOSSIER & REPORT EXPORT
# ==========================================
@router.get("/incidents/{incident_id}/report/markdown")
async def get_incident_report_markdown(incident_id: str):
    """Generates and returns an executive forensic dossier in Markdown format."""
    inc = await db_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    report_content = report_exporter.generate_markdown_report(inc)
    return PlainTextResponse(
        content=report_content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="forensic-report-{incident_id}.md"'
        }
    )


@router.get("/incidents/{incident_id}/export")
async def export_incident_dossier(incident_id: str):
    """Exports full forensic incident JSON dossier including responses and investigation."""
    inc = await db_repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    responses = await response_engine.get_actions_for_incident(incident_id)
    return {
        "incident": inc.model_dump(mode="json"),
        "containment_actions": [r.model_dump(mode="json") for r in responses]
    }


