from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    CLOSED = "CLOSED"


class IncidentTimelineEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_id: str
    event_type: str
    description: str
    source_ip: str


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}")
    title: str
    description: str
    attack_type: str
    severity: IncidentSeverity = IncidentSeverity.LOW
    risk_score: int = Field(default=0, ge=0, le=100)
    mitre_technique: str = "T1110"
    mitre_name: Optional[str] = "Brute Force"
    status: IncidentStatus = IncidentStatus.OPEN
    source_ip: str
    username: Optional[str] = None
    target_user: Optional[str] = None
    affected_accounts: List[str] = Field(default_factory=list)
    event_count: int = 1
    related_event_ids: List[str] = Field(default_factory=list)
    mitre_mapping: Optional[Dict[str, Any]] = None
    investigation_report: Optional[Dict[str, Any]] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    recommended_responses: List[str] = Field(default_factory=list)
    timeline: List[IncidentTimelineEntry] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

