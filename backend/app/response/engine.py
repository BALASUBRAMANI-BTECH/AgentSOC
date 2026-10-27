import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from app.models.response import ResponseAction, ResponseActionType, ResponseAuditRecord
from app.models.incident import IncidentStatus
from app.database.mongodb import db_repo

logger = logging.getLogger(__name__)


class ResponseEngine:
    """
    Controlled Response and Containment Engine.
    Executes safe simulated or production mitigation actions (Block IP, Lock Account, etc.)
    and maintains immutable audit records.
    """

    def __init__(self):
        self.blocked_ips: set = set()
        self.locked_accounts: set = set()
        self.isolated_hosts: set = set()

    async def execute_action(
        self,
        incident_id: str,
        action_type: ResponseActionType,
        target: str,
        operator: str = "SOC_ADMIN",
        simulated: bool = True
    ) -> ResponseAction:
        """Executes a containment action, logs audit record, and updates incident status."""
        action = ResponseAction(
            incident_id=incident_id,
            action_type=action_type,
            target=target,
            status="EXECUTED_SIMULATED" if simulated else "EXECUTED_LIVE",
            executed_at=datetime.utcnow(),
            details={
                "operator": operator,
                "simulated": simulated,
                "mode": "Defensive Containment"
            }
        )

        # Apply state changes (simulated or live)
        if action_type == ResponseActionType.BLOCK_IP:
            self.blocked_ips.add(target)
            reason = f"Automated perimeter drop rule simulated for IP {target}."
        elif action_type == ResponseActionType.LOCK_ACCOUNT:
            self.locked_accounts.add(target)
            reason = f"Security lock placed on user account '{target}'."
        elif action_type == ResponseActionType.ISOLATE_HOST:
            self.isolated_hosts.add(target)
            reason = f"Simulated network quarantine isolation applied to host {target}."
        elif action_type == ResponseActionType.CONTAIN_INCIDENT:
            reason = f"Incident {incident_id} marked as contained by operator."
        else:
            reason = f"Incident {incident_id} escalated to Tier-3 incident commanders."

        audit_record = ResponseAuditRecord(
            incident_id=incident_id,
            action=action_type,
            reason=reason,
            target=target,
            operator=operator,
            status="SUCCESS",
            timestamp=datetime.utcnow(),
            simulated=simulated
        )

        # Persist to database / memory
        await db_repo.save_response(action)
        await db_repo.save_audit_record(audit_record)

        # Automatically update incident status to CONTAINED
        incident = await db_repo.get_incident(incident_id)
        if incident:
            incident.status = IncidentStatus.CONTAINED
            incident.updated_at = datetime.utcnow()
            await db_repo.save_incident(incident)

        logger.info(f"Executed response action {action.action_id} ({action_type}) on target {target}")
        return action

    async def get_actions_for_incident(self, incident_id: str) -> List[ResponseAction]:
        return await db_repo.get_responses(incident_id)


response_engine = ResponseEngine()

