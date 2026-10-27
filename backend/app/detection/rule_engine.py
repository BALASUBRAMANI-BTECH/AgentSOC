import logging
from typing import Any, Dict
from app.models.event import SecurityEvent
from app.services.redis_stream import redis_service
from app.services.threat_intel_service import threat_intel_service

logger = logging.getLogger(__name__)

FAILED_LOGIN_THRESHOLD = 5
WINDOW_SECONDS = 300


class RuleEngine:
    """
    Signature and threshold-based threat detection engine.
    Detects excessive failed logins, suspicious IP access, and frequency spikes.
    """

    def evaluate_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Evaluates an incoming event against deterministic security rules."""
        evidence = []
        threat_detected = False
        threat_type = "Normal Activity"
        rule_name = "RULE_BENIGN"
        confidence = 0.0
        mitre_technique = None

        # Rule 1: Excessive Failed Logins (Brute Force / Credential Guessing)
        if event.event_type == "login_failed":
            current_attempts = redis_service.increment_failed_login(
                event.source_ip,
                window_seconds=WINDOW_SECONDS
            )

            if current_attempts >= FAILED_LOGIN_THRESHOLD:
                threat_detected = True
                threat_type = "Brute Force Attack"
                rule_name = "RULE_EXCESSIVE_FAILED_LOGINS"
                confidence = min(0.99, 0.70 + (current_attempts * 0.001))
                mitre_technique = "T1110"
                evidence.append(
                    f"Threshold exceeded: {current_attempts} failed login attempts from source IP {event.source_ip} "
                    f"within {WINDOW_SECONDS}s sliding window."
                )

        # Rule 2: Access from Known Malicious / Suspicious IP
        intel = threat_intel_service.check_ip_reputation(event.source_ip)
        if intel.get("abuse_score", 0) >= 80:
            if not threat_detected:
                threat_detected = True
                threat_type = "Suspicious IP Activity"
                rule_name = "RULE_HIGH_ABUSE_IP"
                confidence = 0.85
                mitre_technique = "T1078"
            evidence.append(
                f"Threat Intelligence alert: Source IP {event.source_ip} has an abuse confidence score of "
                f"{intel.get('abuse_score')}/100 ({intel.get('reputation')})."
            )

        # Rule 3: Port Scanning / Reconnaissance
        if event.event_type == "port_scan":
            threat_detected = True
            threat_type = "Network Port Scan"
            rule_name = "RULE_PORT_SCAN_RECON"
            confidence = 0.90
            mitre_technique = "T1046"
            evidence.append(f"Network scanner signature detected on port range from {event.source_ip}.")

        # Rule 4: Credential Stuffing / Password Spray
        elif event.event_type in ["credential_stuffing", "password_spray"]:
            threat_detected = True
            threat_type = "Credential Stuffing Attack"
            rule_name = "RULE_CREDENTIAL_STUFFING"
            confidence = 0.92
            mitre_technique = "T1110"
            evidence.append(f"Distributed credential spray pattern detected against multiple accounts from {event.source_ip}.")

        # Rule 5: Privilege Escalation / Unauthorized Admin Access
        elif event.event_type in ["privilege_escalation", "unauthorized_access", "privilege_abuse"]:
            threat_detected = True
            threat_type = "Privilege Escalation Attempt"
            rule_name = "RULE_PRIVILEGE_ABUSE"
            confidence = 0.94
            mitre_technique = "T1078"
            evidence.append(f"Unauthorized security context elevation attempted by user '{event.username}' from {event.source_ip}.")

        # Rule 6: Data Exfiltration / Anomalous Outbound Transfer
        elif event.event_type in ["data_exfiltration", "anomalous_transfer"]:
            threat_detected = True
            threat_type = "Data Exfiltration Attempt"
            rule_name = "RULE_DATA_EXFILTRATION"
            confidence = 0.95
            mitre_technique = "T1048"
            evidence.append(f"High-volume anomalous outbound network transfer detected from {event.source_ip} to {event.destination_ip}.")

        # Rule 7: Web Application Exploit Attempt
        elif event.event_type in ["exploit_attempt", "web_attack", "rce_attempt"]:
            threat_detected = True
            threat_type = "Web Application Exploit Attempt"
            rule_name = "RULE_WEB_EXPLOIT"
            confidence = 0.93
            mitre_technique = "T1190"
            evidence.append(f"Malicious exploit payload identified in request telemetry from {event.source_ip}.")

        failed_attempts = redis_service.get_failed_logins(event.source_ip)

        return {
            "threat_detected": threat_detected,
            "threat_type": threat_type,
            "rule_name": rule_name,
            "confidence": confidence,
            "failed_attempts": failed_attempts,
            "mitre_technique": mitre_technique or "T1110",
            "evidence": evidence
        }


rule_engine = RuleEngine()

