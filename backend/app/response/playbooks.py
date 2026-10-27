from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field
from app.models.response import ResponseAction, ResponseActionType, ResponseAuditRecord
from app.models.incident import IncidentStatus
from app.database.mongodb import db_repo
from app.services.websocket_manager import ws_manager


class StepActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    LOCK_ACCOUNT = "LOCK_ACCOUNT"
    ISOLATE_HOST = "ISOLATE_HOST"
    REVOKE_SESSION = "REVOKE_SESSION"
    RATE_LIMIT_IP = "RATE_LIMIT_IP"
    ELEVATE_LOGGING = "ELEVATE_LOGGING"
    NOTIFY_DISPATCH = "NOTIFY_DISPATCH"
    CONTAIN_INCIDENT = "CONTAIN_INCIDENT"


class PlaybookStep(BaseModel):
    step_number: int
    name: str
    action_type: StepActionType
    description: str
    target_field: str  # e.g., "source_ip", "username", "target_host"
    status: str = "PENDING"
    executed_at: Optional[datetime] = None
    output_message: Optional[str] = None


class Playbook(BaseModel):
    playbook_id: str
    name: str
    description: str
    category: str
    target_vector: str
    recommended_mitre: List[str]
    automated_eligible: bool = True
    steps: List[PlaybookStep]


class PlaybookExecution(BaseModel):
    execution_id: str = Field(default_factory=lambda: f"PBX-{uuid.uuid4().hex[:8].upper()}")
    playbook_id: str
    playbook_name: str
    incident_id: str
    target_ip: str
    target_user: Optional[str] = None
    operator: str = "SOC_ADMIN"
    status: str = "RUNNING"
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    step_results: List[Dict[str, Any]] = Field(default_factory=list)
    simulated: bool = True


class PlaybookEngine:
    """Orchestrates multi-step SOAR containment and response playbooks."""

    def __init__(self):
        self.executions: List[PlaybookExecution] = []
        self._init_default_playbooks()

    def _init_default_playbooks(self):
        self.playbooks: Dict[str, Playbook] = {
            "PB-BRUTE-FORCE-CONTAINMENT": Playbook(
                playbook_id="PB-BRUTE-FORCE-CONTAINMENT",
                name="Brute-Force & Credential Spray Containment",
                description="Rapidly halts credential-based adversary campaigns by dropping the source IP, terminating user sessions, and enforcing containment state.",
                category="Credential Access Remediation",
                target_vector="Brute Force / Password Guessing",
                recommended_mitre=["T1110", "T1110.001", "T1110.004"],
                automated_eligible=True,
                steps=[
                    PlaybookStep(
                        step_number=1,
                        name="Drop Ingress on Perimeter Firewall",
                        action_type=StepActionType.BLOCK_IP,
                        description="Injects immediate null-route drop on adversary source IP across perimeter security appliances.",
                        target_field="source_ip"
                    ),
                    PlaybookStep(
                        step_number=2,
                        name="Invalidate Active Authentication Tokens",
                        action_type=StepActionType.LOCK_ACCOUNT,
                        description="Revokes active Kerberos/JWT tickets and locks target account to prevent unauthorized persistence.",
                        target_field="username"
                    ),
                    PlaybookStep(
                        step_number=3,
                        name="Elevate Telemetry Verbosity",
                        action_type=StepActionType.ELEVATE_LOGGING,
                        description="Enables detailed packet and auth inspection on targeted subnet.",
                        target_field="source_ip"
                    ),
                    PlaybookStep(
                        step_number=4,
                        name="Mark Incident Lifecycle Contained",
                        action_type=StepActionType.CONTAIN_INCIDENT,
                        description="Updates incident status to CONTAINED in SOC repository and audit trail.",
                        target_field="incident_id"
                    )
                ]
            ),
            "PB-RANSOMWARE-DATA-EXFIL": Playbook(
                playbook_id="PB-RANSOMWARE-DATA-EXFIL",
                name="Ransomware & Data Exfiltration Immediate Quarantine",
                description="Isolates internal source host from corporate LAN, drops external C2 egress destinations, and invalidates API tokens.",
                category="Data Protection & Containment",
                target_vector="Data Exfiltration / Ransomware Staging",
                recommended_mitre=["T1048", "T1078", "T1486"],
                automated_eligible=True,
                steps=[
                    PlaybookStep(
                        step_number=1,
                        name="Sever Outbound C2 Network Flow",
                        action_type=StepActionType.BLOCK_IP,
                        description="Blocks egress destination address at gateway to prevent data leakage.",
                        target_field="source_ip"
                    ),
                    PlaybookStep(
                        step_number=2,
                        name="Quarantine Internal Host",
                        action_type=StepActionType.ISOLATE_HOST,
                        description="Places compromised endpoint into strict network quarantine VLAN.",
                        target_field="source_ip"
                    ),
                    PlaybookStep(
                        step_number=3,
                        name="Dispatch High-Priority Alert",
                        action_type=StepActionType.NOTIFY_DISPATCH,
                        description="Sends priority webhook notification to Tier-3 incident response commanders.",
                        target_field="incident_id"
                    ),
                    PlaybookStep(
                        step_number=4,
                        name="Transition Incident Status",
                        action_type=StepActionType.CONTAIN_INCIDENT,
                        description="Records successful multi-point quarantine.",
                        target_field="incident_id"
                    )
                ]
            ),
            "PB-TOR-ANOMALY-DROP": Playbook(
                playbook_id="PB-TOR-ANOMALY-DROP",
                name="Tor Relay & Proxy Perimeter Auto-Drop",
                description="Immediately drops verified Tor exit nodes, flags affected accounts for mandatory password reset, and dispatches incident telemetry.",
                category="Anonymized Threat Mitigation",
                target_vector="Tor Relay / Anonymous Ingress",
                recommended_mitre=["T1190", "T1078"],
                automated_eligible=True,
                steps=[
                    PlaybookStep(
                        step_number=1,
                        name="Blacklist Tor Exit Relay",
                        action_type=StepActionType.BLOCK_IP,
                        description="Inserts dynamic border firewall rule dropping all TCP/UDP traffic from Tor relay.",
                        target_field="source_ip"
                    ),
                    PlaybookStep(
                        step_number=2,
                        name="Enforce MFA Re-Verification",
                        action_type=StepActionType.LOCK_ACCOUNT,
                        description="Forces target account into mandatory out-of-band MFA verification challenge.",
                        target_field="username"
                    ),
                    PlaybookStep(
                        step_number=3,
                        name="Transition Incident to Contained",
                        action_type=StepActionType.CONTAIN_INCIDENT,
                        description="Marks threat vector neutral and updates immutable records.",
                        target_field="incident_id"
                    )
                ]
            ),
            "PB-PORT-RECON-QUARANTINE": Playbook(
                playbook_id="PB-PORT-RECON-QUARANTINE",
                name="Internal Port Reconnaissance Throttling",
                description="Enforces strict TCP SYN rate-limiting on probe IP and isolates reconnaissance scanners.",
                category="Reconnaissance Suppression",
                target_vector="Network Port Scan / Discovery",
                recommended_mitre=["T1046", "T1087"],
                automated_eligible=True,
                steps=[
                    PlaybookStep(
                        step_number=1,
                        name="Rate-Limit & Block Probe IP",
                        action_type=StepActionType.BLOCK_IP,
                        description="Applies perimeter drop and internal VLAN filter to suppress port reconnaissance.",
                        target_field="source_ip"
                    ),
                    PlaybookStep(
                        step_number=2,
                        name="Log Audit Trail Certification",
                        action_type=StepActionType.CONTAIN_INCIDENT,
                        description="Generates immutable record in response audit log.",
                        target_field="incident_id"
                    )
                ]
            )
        }

    def list_playbooks(self) -> List[Playbook]:
        return list(self.playbooks.values())

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self.playbooks.get(playbook_id)

    async def execute_playbook(
        self,
        playbook_id: str,
        incident_id: str,
        operator: str = "SOC_ADMIN",
        simulated: bool = True
    ) -> PlaybookExecution:
        playbook = self.get_playbook(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook '{playbook_id}' not found")

        incident = await db_repo.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        target_ip = incident.source_ip
        target_user = incident.target_user or incident.username

        execution = PlaybookExecution(
            playbook_id=playbook_id,
            playbook_name=playbook.name,
            incident_id=incident_id,
            target_ip=target_ip,
            target_user=target_user,
            operator=operator,
            simulated=simulated,
            status="RUNNING"
        )

        step_results = []
        for step in playbook.steps:
            target = target_ip if step.target_field == "source_ip" else (
                target_user or "system_account" if step.target_field == "username" else incident_id
            )

            # Map step action to response action type
            action_map = {
                StepActionType.BLOCK_IP: ResponseActionType.BLOCK_IP,
                StepActionType.LOCK_ACCOUNT: ResponseActionType.LOCK_ACCOUNT,
                StepActionType.ISOLATE_HOST: ResponseActionType.ISOLATE_HOST,
                StepActionType.CONTAIN_INCIDENT: ResponseActionType.CONTAIN_INCIDENT,
            }
            action_type = action_map.get(step.action_type, ResponseActionType.BLOCK_IP)

            action = ResponseAction(
                incident_id=incident_id,
                action_type=action_type,
                target=target,
                status="EXECUTED_SIMULATED" if simulated else "EXECUTED_LIVE",
                details={
                    "playbook_id": playbook_id,
                    "step": step.name,
                    "operator": operator
                }
            )
            await db_repo.save_response(action)

            # Audit record
            audit = ResponseAuditRecord(
                incident_id=incident_id,
                action=action_type,
                reason=f"Playbook [{playbook.name}] Step {step.step_number}: {step.name}",
                target=target,
                operator=operator,
                status="SUCCESS",
                simulated=simulated
            )
            await db_repo.save_audit_record(audit)

            step_results.append({
                "step_number": step.step_number,
                "name": step.name,
                "action_type": step.action_type.value,
                "target": target,
                "status": "SUCCESS",
                "timestamp": datetime.utcnow().isoformat()
            })

        # Update incident status to CONTAINED
        incident.status = IncidentStatus.CONTAINED
        incident.updated_at = datetime.utcnow()
        await db_repo.save_incident(incident)

        execution.status = "COMPLETED"
        execution.completed_at = datetime.utcnow()
        execution.step_results = step_results
        self.executions.insert(0, execution)

        try:
            await ws_manager.broadcast({
                "type": "PLAYBOOK_EXECUTED",
                "execution_id": execution.execution_id,
                "playbook_id": playbook_id,
                "incident_id": incident_id,
                "status": "COMPLETED"
            })
        except Exception:
            pass

        return execution

    def get_history(self) -> List[PlaybookExecution]:
        return self.executions


playbook_engine = PlaybookEngine()
