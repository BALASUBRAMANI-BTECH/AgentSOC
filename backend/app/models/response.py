from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field


class ResponseActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    LOCK_ACCOUNT = "LOCK_ACCOUNT"
    ISOLATE_HOST = "ISOLATE_HOST"
    CONTAIN_INCIDENT = "CONTAIN_INCIDENT"
    ESCALATE = "ESCALATE"


class ResponseAction(BaseModel):
    action_id: str = Field(default_factory=lambda: f"ACT-{uuid.uuid4().hex[:8].upper()}")
    incident_id: str
    action_type: ResponseActionType
    target: str
    status: str = "EXECUTED_SIMULATED"
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ResponseAuditRecord(BaseModel):
    audit_id: str = Field(default_factory=lambda: f"AUDIT-{uuid.uuid4().hex[:8].upper()}")
    incident_id: str
    action: ResponseActionType
    reason: str
    target: str
    operator: str = "SOC_ADMIN"
    status: str = "SUCCESS"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    simulated: bool = True

