import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentSeverity, IncidentStatus, IncidentTimelineEntry
from app.database.mongodb import db_repo

logger = logging.getLogger(__name__)

CORRELATION_WINDOW_SECONDS = 900  # 15 minutes


class CorrelationEngine:
    """
    Groups related events across source IP, username, event type, and sliding time window
    into singular correlated security incidents with continuous event timelines.
    """

    def __init__(self):
        # Maps (source_ip, attack_type) -> incident_id
        self._active_correlations: Dict[str, str] = {}

    def _get_correlation_key(self, source_ip: str, attack_type: str) -> str:
        return f"{source_ip}:{attack_type}"

    async def correlate_event(
        self,
        event: SecurityEvent,
        detection: Dict[str, Any],
        ml_result: Optional[Dict[str, Any]] = None
    ) -> Optional[Incident]:
        """
        Correlates an incoming event with existing incidents or creates a new one.
        Returns the correlated Incident if a threat is detected.
        """
        if not detection.get("threat_detected") and not (ml_result and ml_result.get("detected")):
            return None

        attack_type = detection.get("threat_type") or (ml_result.get("attack_type") if ml_result else "Suspicious Activity")
        key = self._get_correlation_key(event.source_ip, attack_type)
        existing_id = self._active_correlations.get(key)
        incident = None

        if existing_id:
            incident = await db_repo.get_incident(existing_id)
            # If incident is closed or older than correlation window, start fresh
            if incident and incident.status == IncidentStatus.CLOSED:
                incident = None

        now = datetime.utcnow()
        timeline_entry = IncidentTimelineEntry(
            timestamp=event.timestamp or now,
            event_id=event.event_id,
            event_type=event.event_type,
            description=event.message,
            source_ip=event.source_ip
        )

        if incident:
            # Update existing correlated incident
            incident.event_count += 1
            if event.event_id not in incident.related_event_ids:
                incident.related_event_ids.append(event.event_id)
            if event.username and event.username not in incident.affected_accounts:
                incident.affected_accounts.append(event.username)
            incident.timeline.append(timeline_entry)
            incident.updated_at = now

            # Merge evidence
            if detection.get("evidence"):
                for ev in detection["evidence"]:
                    if ev not in incident.evidence.get("rule_evidence", []):
                        incident.evidence.setdefault("rule_evidence", []).append(ev)
            if ml_result and ml_result.get("evidence"):
                for ev in ml_result["evidence"]:
                    if ev not in incident.evidence.get("ml_evidence", []):
                        incident.evidence.setdefault("ml_evidence", []).append(ev)

            await db_repo.save_incident(incident)
            logger.info(f"Updated correlated incident {incident.incident_id} (count: {incident.event_count})")
            return incident

        # Create new incident
        mitre_tech = detection.get("mitre_technique", "T1110")
        title = f"{attack_type} from {event.source_ip}"
        description = (
            f"Autonomous SOC detection triggered {attack_type} originating from source IP {event.source_ip}. "
            f"Initial rule trigger: {detection.get('rule_name', 'RULE_DETECTED')}."
        )

        affected_accounts = [event.username] if event.username else []
        evidence_dict = {
            "rule_evidence": detection.get("evidence", []),
            "detection_confidence": detection.get("confidence", 0.8),
            "source_ip": event.source_ip,
            "failed_attempts": detection.get("failed_attempts", 1)
        }
        if ml_result and ml_result.get("evidence"):
            evidence_dict["ml_evidence"] = ml_result["evidence"]
            evidence_dict["ml_anomaly_score"] = ml_result.get("anomaly_score", 0.0)

        new_incident = Incident(
            title=title,
            description=description,
            attack_type=attack_type,
            severity=IncidentSeverity.MEDIUM,
            risk_score=50,
            mitre_technique=mitre_tech,
            status=IncidentStatus.OPEN,
            source_ip=event.source_ip,
            username=event.username,
            affected_accounts=affected_accounts,
            event_count=1,
            related_event_ids=[event.event_id],
            evidence=evidence_dict,
            recommended_responses=["Block IP", "Lock account", "Increase monitoring"],
            timeline=[timeline_entry],
            created_at=now,
            updated_at=now
        )

        self._active_correlations[key] = new_incident.incident_id
        await db_repo.save_incident(new_incident)
        logger.info(f"Created new correlated incident {new_incident.incident_id} for {event.source_ip}")
        return new_incident


correlation_engine = CorrelationEngine()

