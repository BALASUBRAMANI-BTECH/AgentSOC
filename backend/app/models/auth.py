from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: Optional[str] = None
    password: str


class UserProfile(BaseModel):
    username: str
    display_name: str
    role: str
    email: str
    permissions: List[str] = Field(default_factory=list)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile


class AssistantChatRequest(BaseModel):
    message: str
    incident_id: Optional[str] = None


class AssistantChatResponse(BaseModel):
    reply: str
    suggestions: List[str] = Field(default_factory=list)
    context_summary: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    provider: str = "AgentSOC AI Copilot"

