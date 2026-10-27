from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class AgentLogEntry(BaseModel):
    agent_name: str
    action: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    summary: str
    output_summary: Optional[str] = None
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)
    evidence: Optional[Dict[str, Any]] = None


class InvestigationReport(BaseModel):
    investigation_id: str = Field(default_factory=lambda: f"INV-{uuid.uuid4().hex[:8].upper()}")
    incident_id: str
    incident_summary: str
    summary: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    affected_user: Optional[str] = None
    source_ip: str
    related_events: List[Any] = Field(default_factory=list)
    attack_type: str
    mitre_technique: str = "T1110"
    threat_intelligence_result: Dict[str, Any] = Field(default_factory=dict)
    reasoning: str
    root_cause_hypothesis: Optional[str] = None
    confidence_score: Optional[int] = 95
    risk_score: int
    severity: str
    recommended_responses: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    observed_evidence: List[str] = Field(default_factory=list)
    agent_logs: List[AgentLogEntry] = Field(default_factory=list)
    investigated_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = "COMPLETED"
    llm_provider: str = "Ollama / Deterministic SOC Fallback"

