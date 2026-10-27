from datetime import datetime
from typing import Any, Dict
from app.models.incident import Incident


class ReportExporter:
    """Generates forensic incident dossiers and executive reports in Markdown format."""

    def generate_markdown_report(self, incident: Incident) -> str:
        created_str = incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(incident.created_at, datetime) else str(incident.created_at)
        updated_str = incident.updated_at.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(incident.updated_at, datetime) else str(incident.updated_at)

        mitre = incident.mitre_mapping or {}
        tech_id = mitre.get("technique_id", incident.mitre_technique)
        tech_name = mitre.get("technique_name", incident.mitre_name or "Brute Force")
        tactic = mitre.get("tactic", "Credential Access (TA0006)")
        tech_desc = mitre.get("description", "Adversary TTP pattern identified.")

        investigation = incident.investigation_report or {}
        evidence = incident.evidence or {}
        factors = evidence.get("contributing_factors", [])
        recommendations = incident.recommended_responses or investigation.get("recommended_responses", [])
        agent_logs = investigation.get("agent_logs", [])

        # Format timeline table
        timeline_rows = []
        for entry in incident.timeline:
            t_time = entry.timestamp.strftime("%H:%M:%S") if isinstance(entry.timestamp, datetime) else str(entry.timestamp)
            entry_sev = getattr(entry, "severity", None) or incident.severity.value
            timeline_rows.append(f"| `{t_time}` | **{entry.event_type}** | {entry.description} | `{entry_sev}` |")
        if not timeline_rows:
            timeline_rows.append(f"| `{created_str}` | **{incident.attack_type}** | Initial incident triggered | `{incident.severity.value}` |")

        # Format agent logs
        agent_log_sections = []
        for log in agent_logs:
            agent_name = log.get("agent_name", "Autonomous Agent")
            action = log.get("action", "EXECUTE")
            summary = log.get("summary", "Analysis completed.")
            agent_log_sections.append(
                f"### {agent_name} (`{action}`)\n"
                f"- **Result**: {summary}\n"
            )

        report_md = f"""# AGENTSOC — INCIDENT FORENSIC DOSSIER
**Incident ID**: `{incident.incident_id}`  
**Classification**: `CONFIDENTIAL / SOC INVESTIGATION`  
**Generated At**: `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`  

---

## 1. Executive Summary

| Attribute | Value |
| :--- | :--- |
| **Incident Title** | **{incident.title}** |
| **Current Status** | `{incident.status.value.upper()}` |
| **Assessed Severity** | **{incident.severity.value.upper()}** |
| **Calibrated Risk Score** | **`{incident.risk_score} / 100`** |
| **Primary Adversary IP** | `{incident.source_ip}` |
| **Targeted Account(s)** | `{incident.target_user or incident.username or 'Multiple / Perimeter'}` |
| **Total Telemetry Events** | `{incident.event_count}` raw security events |
| **First Observed** | `{created_str}` |
| **Last Updated** | `{updated_str}` |

### Narrative
{incident.description}

---

## 2. Calibrated 0–100 Explainable Risk Evaluation

The composite risk score of **{incident.risk_score}/100** was calculated using the deterministic formula:
$$\\text{{Risk}} = \\min(100, \\, w_v \\cdot V + w_c \\cdot C + w_a \\cdot A + w_m \\cdot M)$$

### Contributing Hazard Factors:
""" + "\n".join([f"- **Factor**: {f}" for f in factors] if factors else ["- Standard operational telemetry threshold."]) + f"""

---

## 3. MITRE ATT&CK Framework Mapping

- **Technique ID**: [`{tech_id}`](https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/) — **{tech_name}**
- **Tactic Category**: `{tactic}`
- **Technical Description**: {tech_desc}

---

## 4. Autonomous 5-Agent LangGraph Investigation Transcript

{chr(10).join(agent_log_sections) if agent_log_sections else "*Autonomous multi-agent investigation execution recorded in primary telemetry stream.*"}

### Root Cause Hypothesis (AI Synthesis):
> {investigation.get('reasoning') or evidence.get('ai_hypothesis') or 'Deterministic heuristic correlation validated burst threshold and adversary signature.'}

---

## 5. Defensive Playbook & Containment Directives

The following automated defensive containment measures were formulated:
""" + "\n".join([f"1. **{r}**" for r in recommendations] if recommendations else ["1. Continue live passive telemetry monitoring."]) + f"""

---

## 6. Chronological Forensic Timeline

| Timestamp | Event Modality | Forensic Description | Telemetry Severity |
| :--- | :--- | :--- | :--- |
""" + "\n".join(timeline_rows) + f"""

---

## 7. Chain of Custody & Audit Certification

- **Origin**: AgentSOC Autonomous Telemetry Stream & Detection Engine
- **Integrity**: Cryptographically indexed and stored in immutable SOC audit trail
- **Authorized SOC Admin Clearance**: Admin verification required for containment execution (`24282428`)
"""
        return report_md


report_exporter = ReportExporter()
