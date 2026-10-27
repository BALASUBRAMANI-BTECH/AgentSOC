import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.investigation import InvestigationReport
from app.models.response import ResponseAction, ResponseAuditRecord

logger = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB_NAME", "agentsoc")


class MongoRepository:
    """
    Dual-mode persistence engine for AgentSOC.
    Connects to MongoDB with indexes when available,
    with an automatic zero-overhead memory fallback when running standalone.
    """

    def __init__(self):
        self.is_connected = False
        self.client = None
        self.db = None

        # Resilient In-Memory Fallback Stores
        self._events: List[Dict[str, Any]] = []
        self._incidents: Dict[str, Dict[str, Any]] = {}
        self._investigations: Dict[str, Dict[str, Any]] = {}
        self._responses: List[Dict[str, Any]] = []
        self._audit_logs: List[Dict[str, Any]] = []

    async def connect(self):
        """Initializes MongoDB connection and creates database indexes."""
        try:
            import motor.motor_asyncio
            self.client = motor.motor_asyncio.AsyncIOMotorClient(
                MONGO_URI,
                serverSelectionTimeoutMS=1500
            )
            # Test connection
            await self.client.admin.command('ping')
            self.db = self.client[DB_NAME]
            self.is_connected = True
            logger.info(f"Connected to MongoDB at {MONGO_URI}, database '{DB_NAME}'")

            # Create Indexes
            await self.db.events.create_index("event_id", unique=True)
            await self.db.events.create_index("timestamp")
            await self.db.events.create_index("source_ip")
            await self.db.events.create_index("event_type")

            await self.db.incidents.create_index("incident_id", unique=True)
            await self.db.incidents.create_index("status")
            await self.db.incidents.create_index("severity")
            await self.db.incidents.create_index("source_ip")
            await self.db.incidents.create_index("created_at")

            await self.db.investigations.create_index("incident_id", unique=True)
            await self.db.responses.create_index("action_id", unique=True)
            await self.db.responses.create_index("incident_id")
            await self.db.audit_logs.create_index("audit_id", unique=True)
        except Exception as e:
            self.is_connected = False
            logger.info(f"MongoDB not reachable ({e}). Resilient in-memory persistence active.")

    # Events
    async def save_event(self, event: SecurityEvent):
        doc = event.model_dump(mode="json")
        self._events.insert(0, doc)
        if len(self._events) > 1000:
            self._events = self._events[:1000]
        if self.is_connected and self.db is not None:
            try:
                await self.db.events.insert_one(doc)
            except Exception as e:
                logger.debug(f"Mongo save_event error: {e}")

    async def get_events(self, limit: int = 50) -> List[SecurityEvent]:
        if self.is_connected and self.db is not None:
            try:
                cursor = self.db.events.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
                results = await cursor.to_list(length=limit)
                return [SecurityEvent(**r) for r in results]
            except Exception:
                pass
        return [SecurityEvent(**r) for r in self._events[:limit]]

    # Incidents
    async def save_incident(self, incident: Incident):
        doc = incident.model_dump(mode="json")
        self._incidents[incident.incident_id] = doc
        if self.is_connected and self.db is not None:
            try:
                await self.db.incidents.replace_one(
                    {"incident_id": incident.incident_id},
                    doc,
                    upsert=True
                )
            except Exception as e:
                logger.debug(f"Mongo save_incident error: {e}")

    async def get_incident(self, incident_id: str) -> Optional[Incident]:
        if self.is_connected and self.db is not None:
            try:
                doc = await self.db.incidents.find_one({"incident_id": incident_id}, {"_id": 0})
                if doc:
                    return Incident(**doc)
            except Exception:
                pass
        doc = self._incidents.get(incident_id)
        return Incident(**doc) if doc else None

    async def get_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50
    ) -> List[Incident]:
        if self.is_connected and self.db is not None:
            try:
                query = {}
                if status and status != "ALL":
                    query["status"] = status
                if severity and severity != "ALL":
                    query["severity"] = severity
                cursor = self.db.incidents.find(query, {"_id": 0}).sort("created_at", -1).limit(limit)
                results = await cursor.to_list(length=limit)
                return [Incident(**r) for r in results]
            except Exception:
                pass

        results = list(self._incidents.values())
        if status and status != "ALL":
            results = [r for r in results if r.get("status") == status]
        if severity and severity != "ALL":
            results = [r for r in results if r.get("severity") == severity]
        results.sort(key=lambda x: str(x.get("created_at", "")), reverse=True)
        return [Incident(**r) for r in results[:limit]]

    # Investigations
    async def save_investigation(self, report: InvestigationReport):
        doc = report.model_dump(mode="json")
        self._investigations[report.incident_id] = doc
        if self.is_connected and self.db is not None:
            try:
                await self.db.investigations.replace_one(
                    {"incident_id": report.incident_id},
                    doc,
                    upsert=True
                )
            except Exception as e:
                logger.debug(f"Mongo save_investigation error: {e}")

    async def get_investigation(self, incident_id: str) -> Optional[InvestigationReport]:
        if self.is_connected and self.db is not None:
            try:
                doc = await self.db.investigations.find_one({"incident_id": incident_id}, {"_id": 0})
                if doc:
                    return InvestigationReport(**doc)
            except Exception:
                pass
        doc = self._investigations.get(incident_id)
        return InvestigationReport(**doc) if doc else None

    # Responses & Audits
    async def save_response(self, action: ResponseAction):
        doc = action.model_dump(mode="json")
        self._responses.insert(0, doc)
        if self.is_connected and self.db is not None:
            try:
                await self.db.responses.insert_one(doc)
            except Exception as e:
                logger.debug(f"Mongo save_response error: {e}")

    async def get_responses(self, incident_id: Optional[str] = None) -> List[ResponseAction]:
        query = {"incident_id": incident_id} if incident_id else {}
        if self.is_connected and self.db is not None:
            try:
                cursor = self.db.responses.find(query, {"_id": 0}).sort("executed_at", -1)
                results = await cursor.to_list(length=100)
                return [ResponseAction(**r) for r in results]
            except Exception:
                pass
        if incident_id:
            return [ResponseAction(**r) for r in self._responses if r.get("incident_id") == incident_id]
        return [ResponseAction(**r) for r in self._responses]

    async def save_audit_record(self, record: ResponseAuditRecord):
        doc = record.model_dump(mode="json")
        self._audit_logs.insert(0, doc)
        if self.is_connected and self.db is not None:
            try:
                await self.db.audit_logs.insert_one(doc)
            except Exception as e:
                logger.debug(f"Mongo save_audit_record error: {e}")

    async def get_audit_records(self) -> List[ResponseAuditRecord]:
        if self.is_connected and self.db is not None:
            try:
                cursor = self.db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1)
                results = await cursor.to_list(length=100)
                return [ResponseAuditRecord(**r) for r in results]
            except Exception:
                pass
        return [ResponseAuditRecord(**r) for r in self._audit_logs]

    # Stats
    async def get_stats(self) -> Dict[str, Any]:
        all_incs = await self.get_incidents(limit=200)
        open_incs = [i for i in all_incs if i.status != IncidentStatus.CLOSED]
        return {
            "total_events": len(self._events),
            "active_incidents": len(open_incs),
            "critical_incidents": len([i for i in open_incs if i.severity == IncidentSeverity.CRITICAL]),
            "high_risk_incidents": len([i for i in open_incs if i.severity == IncidentSeverity.HIGH]),
            "resolved_incidents": len([i for i in all_incs if i.status in [IncidentStatus.CONTAINED, IncidentStatus.CLOSED]]),
            "total_responses": len(self._responses)
        }


db_repo = MongoRepository()

