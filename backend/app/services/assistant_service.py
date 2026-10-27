import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from app.models.auth import AssistantChatResponse
from app.database.mongodb import db_repo
from app.services.threat_intel_service import threat_intel_service
from app.agents.llm import llm_client

logger = logging.getLogger(__name__)


class AssistantService:
    """
    Intelligent AI Security Assistant (SOC Copilot).
    Combines live platform telemetry, incident intelligence, and LLM reasoning.
    """

    DEFAULT_SUGGESTIONS = [
        "Audit active critical threats",
        "Explain mitigation playbook for Brute Force (T1110)",
        "Audit IP 192.168.1.50 reputation",
        "Recommend containment playbooks"
    ]

    async def chat(self, message: str, incident_id: Optional[str] = None) -> AssistantChatResponse:
        """Processes user query and returns contextual cyber guidance."""
        stats = await db_repo.get_stats()
        msg_lower = message.lower().strip()

        # Check if Ollama is available
        if llm_client.is_available():
            try:
                system_prompt = (
                    "You are AgentSOC Copilot, an autonomous Tier-3 cybersecurity analyst and AI assistant. "
                    "You assist SOC operators with threat triage, MITRE ATT&CK guidance, and containment playbooks. "
                    "Be concise, technical, and use markdown formatting."
                )
                user_prompt = f"Live SOC State: {stats}\nIncident Focus: {incident_id or 'General'}\nQuery: {message}"
                llm_res = llm_client.generate(user_prompt, system=system_prompt)
                if not llm_res.get("is_fallback"):
                    return AssistantChatResponse(
                        reply=llm_res["content"],
                        suggestions=self.DEFAULT_SUGGESTIONS,
                        context_summary=stats,
                        provider=llm_res["provider"]
                    )
            except Exception as e:
                logger.warning(f"Ollama chat error: {e}")

        # Deterministic Cyber Engine
        reply, suggestions = await self._generate_response(msg_lower, stats, incident_id)
        return AssistantChatResponse(
            reply=reply,
            suggestions=suggestions,
            context_summary=stats,
            provider="AgentSOC Copilot (Deterministic Engine)"
        )

    async def _generate_response(self, msg: str, stats: Dict[str, Any], incident_id: Optional[str]) -> tuple:
        # If focusing on specific incident
        if incident_id:
            inc = await db_repo.get_incident(incident_id)
            if inc:
                return (
                    f"### 🔍 Focused Incident Analysis: `{inc.incident_id}`\n\n"
                    f"• **Attack Classification**: `{inc.attack_type}`\n"
                    f"• **Assessed Risk Score**: **{inc.risk_score}/100 ({inc.severity.value})**\n"
                    f"• **Attacker Source IP**: `{inc.source_ip}`\n"
                    f"• **Targeted User Account**: `{inc.username or 'Multiple'}`\n"
                    f"• **Telemetry Frequency**: {inc.event_count} correlated events\n"
                    f"• **MITRE ATT&CK**: `{inc.mitre_technique}`\n"
                    f"• **Current Lifecycle Status**: `{inc.status.value}`\n\n"
                    f"**AI Recommendation**: Authorize immediate perimeter containment action `BLOCK_IP` on `{inc.source_ip}` "
                    f"and verify credentials for `{inc.username or 'admin'}`.",
                    [f"Audit IP {inc.source_ip} reputation", "Explain MITRE T1110", "Show active threats"]
                )

        # Status / active threats query
        if any(w in msg for w in ["status", "active", "threat", "critical", "incident", "summary", "overview"]):
            open_incs = await db_repo.get_incidents(status="OPEN", limit=5)
            if not open_incs:
                return (
                    "### 🛡️ SOC Situational Report: Normal\n\n"
                    "There are currently **0 active uncontained incidents** in the queue. "
                    "Telemetry pipelines and Redis streams are healthy.\n\n"
                    "You can inject an attack scenario using the **Attack Simulator** on the dashboard.",
                    ["Simulate 347 Brute-Force Logins", "How does event correlation work?", "Check SOC health"]
                )

            inc_lines = [
                f"- **[{inc.incident_id}] {inc.attack_type}** | Severity: `{inc.severity.value}` | "
                f"Risk: `{inc.risk_score}/100` | Source: `{inc.source_ip}` | Target: `{inc.username}`"
                for inc in open_incs[:3]
            ]
            reply = (
                f"### 🚨 Active SOC Threat Summary\n\n"
                f"The platform is currently tracking **{stats['active_incidents']} active incidents**, "
                f"including **{stats['critical_incidents']} Critical** threats.\n\n"
                f"**Prioritized Incidents:**\n" + "\n".join(inc_lines) +
                f"\n\n**Recommended Next Steps:** Run AI Investigation or authorize Block IP containment."
            )
            return reply, [f"Investigate {open_incs[0].incident_id}", "Explain MITRE T1110", "Audit 192.168.1.50"]

        # IP reputation query
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
        if ip_match or "reputation" in msg or "intel" in msg:
            target_ip = ip_match.group(0) if ip_match else "192.168.1.50"
            intel = threat_intel_service.check_ip_reputation(target_ip)
            return (
                f"### 🔍 Threat Intelligence Dossier: `{target_ip}`\n\n"
                f"• **Reputation**: `{intel.get('reputation')}`\n"
                f"• **Abuse Score**: **{intel.get('abuse_score')}/100**\n"
                f"• **Threat Actor**: `{intel.get('threat_actor')}`\n"
                f"• **Category**: `{intel.get('category')}`\n"
                f"• **Tor Exit Node**: `{'YES (High Risk)' if intel.get('is_tor_exit_node') else 'No'}`\n"
                f"• **ASN**: `{intel.get('asn')}`\n\n"
                f"**Recommendation**: Apply firewall drop on inbound traffic from this host.",
                [f"Block IP {target_ip}", "Explain MITRE T1110", "Audit active threats"]
            )

        # MITRE guidance
        if any(w in msg for w in ["mitre", "t1110", "brute", "password"]):
            return (
                "### 📘 MITRE ATT&CK Technique: T1110 (Brute Force)\n\n"
                "**Tactic**: Credential Access (`TA0006`)\n"
                "**Description**: Adversaries repeatedly submit guesses of passwords or credentials to gain access to valid accounts.\n\n"
                "#### Defense Playbook:\n"
                "1. **Detection**: Velocity threshold $\\ge 5$ attempts in 300s window triggers dynamic risk escalation.\n"
                "2. **Containment**: Execute simulated perimeter rule `BLOCK_IP`.\n"
                "3. **Remediation**: Execute `LOCK_ACCOUNT` and enforce MFA.",
                ["What response actions are available?", "Audit active threats", "Show SOC stats"]
            )

        # Default fallback
        return (
            "### 🤖 AgentSOC AI Copilot Ready\n\n"
            "I am your autonomous cybersecurity assistant connected live to AgentSOC telemetry and LangGraph investigation agents.\n\n"
            "• **Threat Triage**: Summarizing open incidents, risk scores, and affected accounts.\n"
            "• **Threat Intelligence**: Auditing IP reputations, abuse scores, and Tor exit nodes.\n"
            "• **MITRE ATT&CK**: Providing in-depth technique breakdowns and detection logic.\n"
            "• **Incident Remediation**: Formulating containment and firewall playbooks.",
            self.DEFAULT_SUGGESTIONS
        )


assistant_service = AssistantService()

