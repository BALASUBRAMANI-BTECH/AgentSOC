from datetime import datetime
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    """
    Security Event model matching AgentSOC Event Collector specification.
    """
    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str
    destination_ip: Optional[str] = "10.0.0.1"
    username: Optional[str] = None
    event_type: str
    severity: str = "LOW"
    message: str
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

