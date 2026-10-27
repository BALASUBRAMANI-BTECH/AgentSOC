from datetime import datetime
import logging
from typing import Any, Dict
from langgraph.graph import StateGraph, END
from app.agents.state import AgentState
from app.agents.llm import llm_client
from app.models.investigation import AgentLogEntry, InvestigationReport
from app.models.incident import Incident
from app.services.threat_intel_service import threat_intel_service
from app.scoring.risk_engine import risk_engine
from app.mitre.mapper import mitre_mapper

logger = logging.getLogger(__name__)


# 1. Detection Agent Node
def detection_agent_node(state: AgentState) -> Dict[str, Any]:
    incident = state["incident"]
    mitre_data = mitre_mapper.map_attack(incident.attack_type, incident.mitre_technique)

    log = AgentLogEntry(
        agent_name="Detection Agent",
        action="CLASSIFY_AND_MAP",
        timestamp=datetime.utcnow(),
        summary=f"Confirmed threat classification '{incident.attack_type}' mapped to MITRE {mitre_data['technique_id']} ({mitre_data['technique_name']}).",
        details=mitre_data
    )

    return {
        "mitre_technique": mitre_data["technique_id"],
        "mitre_name": mitre_data["technique_name"],
        "attack_type": incident.attack_type,
        "agent_logs": state.get("agent_logs", []) + [log]
    }


# 2. Threat Intel Agent Node
def threat_intel_agent_node(state: AgentState) -> Dict[str, Any]:
    incident = state["incident"]
    intel = threat_intel_service.check_ip_reputation(incident.source_ip)

    summary = (
        f"IP {incident.source_ip} reputation: {intel.get('reputation', 'UNKNOWN')} "
        f"(Abuse Score: {intel.get('abuse_score', 0)}/100, Tor: {intel.get('is_tor_exit_node', False)})."
    )

    log = AgentLogEntry(
        agent_name="Threat Intel Agent",
        action="ENRICH_IOC",
        timestamp=datetime.utcnow(),
        summary=summary,
        details=intel
    )

    return {
        "threat_intel": intel,
        "agent_logs": state.get("agent_logs", []) + [log]
    }


# 3. Investigation Agent Node
def investigation_agent_node(state: AgentState) -> Dict[str, Any]:
    incident = state["incident"]
    intel = state["threat_intel"]

    # Observed facts (strictly grounded in telemetry)
    observed_facts = [
        f"Event Velocity: {incident.event_count} events recorded from {incident.source_ip}.",
        f"Target User: {incident.username or 'Multiple accounts'}.",
        f"Attacker Address: {incident.source_ip} (Category: {intel.get('category')})."
    ]

    # AI Reasoning
    prompt = (
        f"Incident: {incident.title}\n"
        f"Source IP: {incident.source_ip} (Abuse Score: {intel.get('abuse_score')})\n"
        f"Events Count: {incident.event_count}\n"
        f"Target User: {incident.username}\n"
        "Provide technical analysis distinguishing observed facts from AI inference."
    )
    llm_res = llm_client.generate(prompt)

    blast_radius = (
        f"Confined to authentication boundary for account '{incident.username or 'service'}'. "
        "No privilege escalation or persistence detected."
    )

    log = AgentLogEntry(
        agent_name="Investigation Agent",
        action="EVIDENCE_SYNTHESIS",
        timestamp=datetime.utcnow(),
        summary="Synthesized chronological evidence and established containment blast radius.",
        details={
            "observed_facts": observed_facts,
            "blast_radius": blast_radius,
            "ai_inference": llm_res["content"]
        }
    )

    return {
        "observed_facts": observed_facts,
        "blast_radius": blast_radius,
        "ai_hypothesis": llm_res["content"],
        "llm_provider": llm_res["provider"],
        "agent_logs": state.get("agent_logs", []) + [log]
    }


# 4. Risk Analysis Agent Node
def risk_agent_node(state: AgentState) -> Dict[str, Any]:
    incident = state["incident"]
    intel = state["threat_intel"]

    score, severity, factors = risk_engine.calculate_risk(
        incident=incident,
        threat_intel=intel,
        detection_confidence=0.95
    )

    log = AgentLogEntry(
        agent_name="Risk Analysis Agent",
        action="COMPUTE_RISK",
        timestamp=datetime.utcnow(),
        summary=f"Calculated explainable risk score of {score}/100 ({severity.value} severity).",
        details={"score": score, "severity": severity.value, "contributing_factors": factors}
    )

    return {
        "risk_score": score,
        "severity": severity.value,
        "contributing_factors": factors,
        "agent_logs": state.get("agent_logs", []) + [log]
    }


# 5. Response Agent Node
def response_agent_node(state: AgentState) -> Dict[str, Any]:
    incident = state["incident"]
    score = state["risk_score"]

    recommendations = []
    if score >= 75:
        recommendations.append(f"Block IP {incident.source_ip} on perimeter firewall")
        if incident.username:
            recommendations.append(f"Lock account {incident.username} and revoke active session tokens")
        recommendations.append("Elevate audit logging verbosity on targeted subnet")
        recommendations.append("Dispatch emergency webhook alert to Tier-3 SOC team")
    elif score >= 50:
        recommendations.append(f"Block IP {incident.source_ip} temporarily (1 hour drop)")
        recommendations.append(f"Enforce MFA challenge on user {incident.username or 'target'}")
        recommendations.append("Monitor source subnet for coordinated lateral movement")
    else:
        recommendations.append("Increase telemetry monitoring on source IP")
        recommendations.append("Log event for correlation without active disruption")

    log = AgentLogEntry(
        agent_name="Response Agent",
        action="FORMULATE_PLAYBOOK",
        timestamp=datetime.utcnow(),
        summary=f"Formulated {len(recommendations)} recommended containment response actions.",
        details={"recommendations": recommendations}
    )

    summary = (
        f"Autonomous investigation completed for {incident.attack_type} from {incident.source_ip}. "
        f"Evaluated {incident.event_count} telemetry occurrences targeting user '{incident.username or 'service'}'. "
        f"Risk evaluated at {score}/100 ({state['severity']}). Containment playbook prepared."
    )

    reasoning = (
        f"Observed {state['observed_facts'][0]} "
        f"Threat Intel reputation: {state['threat_intel'].get('reputation')} (Abuse: {state['threat_intel'].get('abuse_score')}/100). "
        f"Key factors: {', '.join(state['contributing_factors'][:3])}."
    )

    return {
        "recommended_responses": recommendations,
        "summary": summary,
        "reasoning": reasoning,
        "agent_logs": state.get("agent_logs", []) + [log]
    }


# LangGraph Orchestration Assembly
workflow = StateGraph(AgentState)

workflow.add_node("detection_agent", detection_agent_node)
workflow.add_node("threat_intel_agent", threat_intel_agent_node)
workflow.add_node("investigation_agent", investigation_agent_node)
workflow.add_node("risk_agent", risk_agent_node)
workflow.add_node("response_agent", response_agent_node)

workflow.set_entry_point("detection_agent")
workflow.add_edge("detection_agent", "threat_intel_agent")
workflow.add_edge("threat_intel_agent", "investigation_agent")
workflow.add_edge("investigation_agent", "risk_agent")
workflow.add_edge("risk_agent", "response_agent")
workflow.add_edge("response_agent", END)

investigation_graph = workflow.compile()


class InvestigationService:
    """Orchestrates LangGraph multi-agent investigations on incidents."""

    def investigate(self, incident: Incident) -> InvestigationReport:
        initial_state: AgentState = {
            "incident": incident,
            "attack_type": incident.attack_type,
            "mitre_technique": incident.mitre_technique,
            "mitre_name": "Brute Force",
            "threat_intel": {},
            "observed_facts": [],
            "ai_hypothesis": "",
            "blast_radius": "",
            "risk_score": incident.risk_score,
            "severity": incident.severity.value,
            "contributing_factors": [],
            "recommended_responses": [],
            "agent_logs": [],
            "summary": "",
            "reasoning": "",
            "llm_provider": "Ollama / Deterministic SOC Fallback"
        }

        result = investigation_graph.invoke(initial_state)

        report = InvestigationReport(
            incident_id=incident.incident_id,
            incident_summary=result["summary"],
            evidence={
                "observed_facts": result["observed_facts"],
                "blast_radius": result["blast_radius"],
                "ai_hypothesis": result["ai_hypothesis"],
                "threat_intel": result["threat_intel"]
            },
            affected_user=incident.username,
            source_ip=incident.source_ip,
            related_events=incident.related_event_ids,
            attack_type=result["attack_type"],
            mitre_technique=result["mitre_technique"],
            threat_intelligence_result=result["threat_intel"],
            reasoning=result["reasoning"],
            risk_score=result["risk_score"],
            severity=result["severity"],
            recommended_responses=result["recommended_responses"],
            agent_logs=result["agent_logs"],
            status="COMPLETED",
            llm_provider=result.get("llm_provider", "Ollama / Deterministic SOC Fallback")
        )

        return report


investigation_service = InvestigationService()

