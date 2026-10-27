from typing import Any, Dict, List, Optional, TypedDict
from app.models.incident import Incident
from app.models.investigation import AgentLogEntry


class AgentState(TypedDict):
    incident: Incident
    attack_type: str
    mitre_technique: str
    mitre_name: str
    threat_intel: Dict[str, Any]
    observed_facts: List[str]
    ai_hypothesis: str
    blast_radius: str
    risk_score: int
    severity: str
    contributing_factors: List[str]
    recommended_responses: List[str]
    agent_logs: List[AgentLogEntry]
    summary: str
    reasoning: str
    llm_provider: str

