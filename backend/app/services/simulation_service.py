import logging
from typing import Any, Dict, List
from app.models.event import SecurityEvent

logger = logging.getLogger(__name__)


SCENARIOS = {
    "brute_force": {
        "id": "brute_force",
        "name": "High-Velocity SSH Brute-Force",
        "description": "Adversary repeatedly attempts SSH authentication against admin user from internal pivot IP.",
        "mitre_technique": "T1110",
        "attacker_ip": "192.168.1.50",
        "target_user": "admin",
        "event_count": 25,
        "category": "Credential Access"
    },
    "port_scan": {
        "id": "port_scan",
        "name": "Internal Network Service Discovery",
        "description": "Host conducts fast TCP SYN discovery sweep across enterprise services and database ports.",
        "mitre_technique": "T1046",
        "attacker_ip": "10.0.1.99",
        "target_user": "network_probe",
        "event_count": 15,
        "category": "Discovery"
    },
    "credential_stuffing": {
        "id": "credential_stuffing",
        "name": "Distributed Tor Credential Stuffing",
        "description": "State-sponsored actor relays automated password spraying across multiple valid accounts via Tor exit node.",
        "mitre_technique": "T1110.004",
        "attacker_ip": "185.220.101.5",
        "target_user": "sarah.connor, john.doe, finance_lead, dba_service",
        "event_count": 20,
        "category": "Initial Access & Credential Access"
    },
    "privilege_abuse": {
        "id": "privilege_abuse",
        "name": "Unauthorized Privilege Escalation",
        "description": "Restricted account attempts unauthorized elevation to domain admin and security context tampering.",
        "mitre_technique": "T1078",
        "attacker_ip": "10.0.0.75",
        "target_user": "guest_user",
        "event_count": 10,
        "category": "Defense Evasion & Persistence"
    },
    "data_exfiltration": {
        "id": "data_exfiltration",
        "name": "Encrypted Non-C2 Data Exfiltration",
        "description": "Compromised internal endpoint stages and transmits anomalous high-volume outbound data stream.",
        "mitre_technique": "T1048",
        "attacker_ip": "10.0.0.120",
        "target_user": "backup_agent",
        "event_count": 12,
        "category": "Exfiltration"
    }
}


class SimulationService:
    """Generates synthetic security events matching realistic adversary attack scenarios."""

    def get_available_scenarios(self) -> List[Dict[str, Any]]:
        return list(SCENARIOS.values())

    def generate_events(self, scenario_id: str, count_override: int = None) -> List[SecurityEvent]:
        scenario = SCENARIOS.get(scenario_id, SCENARIOS["brute_force"])
        count = count_override or scenario["event_count"]
        events: List[SecurityEvent] = []

        if scenario_id == "brute_force":
            for i in range(1, count + 1):
                events.append(SecurityEvent(
                    source_ip=scenario["attacker_ip"],
                    destination_ip="10.0.0.5",
                    username=scenario["target_user"],
                    event_type="login_failed",
                    severity="HIGH",
                    message=f"SSH authentication failure attempt #{i} - targeted brute-force password guess",
                    metadata={
                        "attempt": i,
                        "protocol": "ssh",
                        "port": 22,
                        "service": "sshd",
                        "scenario": "brute_force"
                    }
                ))

        elif scenario_id == "port_scan":
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9200, 27017]
            for i in range(1, count + 1):
                port = common_ports[(i - 1) % len(common_ports)]
                events.append(SecurityEvent(
                    source_ip=scenario["attacker_ip"],
                    destination_ip="10.0.0.1",
                    username=scenario["target_user"],
                    event_type="port_scan",
                    severity="MEDIUM",
                    message=f"TCP SYN reconnaissance probe against port {port}/tcp",
                    metadata={
                        "target_port": port,
                        "scan_type": "SYN_STEALTH",
                        "flags": "SYN",
                        "scenario": "port_scan"
                    }
                ))

        elif scenario_id == "credential_stuffing":
            target_users = ["sarah.connor", "john.doe", "finance_lead", "dba_service", "alex.dev", "secops", "billing_admin"]
            for i in range(1, count + 1):
                user = target_users[(i - 1) % len(target_users)]
                events.append(SecurityEvent(
                    source_ip=scenario["attacker_ip"],
                    destination_ip="10.0.0.10",
                    username=user,
                    event_type="credential_stuffing",
                    severity="HIGH",
                    message=f"Distributed password spray attempt against account '{user}' from Tor exit node",
                    metadata={
                        "target_user": user,
                        "relay": "Tor",
                        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Bot/1.0",
                        "scenario": "credential_stuffing"
                    }
                ))

        elif scenario_id == "privilege_abuse":
            for i in range(1, count + 1):
                events.append(SecurityEvent(
                    source_ip=scenario["attacker_ip"],
                    destination_ip="10.0.0.2",
                    username=scenario["target_user"],
                    event_type="privilege_abuse",
                    severity="CRITICAL",
                    message=f"Unauthorized access token duplication attempt #{i} targeting SeDebugPrivilege",
                    metadata={
                        "target_privilege": "SeDebugPrivilege",
                        "process": "cmd.exe",
                        "attempt": i,
                        "scenario": "privilege_abuse"
                    }
                ))

        elif scenario_id == "data_exfiltration":
            for i in range(1, count + 1):
                chunk_mb = 128 * i
                events.append(SecurityEvent(
                    source_ip=scenario["attacker_ip"],
                    destination_ip="198.51.100.23",
                    username=scenario["target_user"],
                    event_type="data_exfiltration",
                    severity="CRITICAL",
                    message=f"Anomalous encrypted outbound payload stream ({chunk_mb} MB) transmitted to external C2",
                    metadata={
                        "bytes_sent": chunk_mb * 1024 * 1024,
                        "destination_port": 443,
                        "cipher": "AES-256-GCM",
                        "scenario": "data_exfiltration"
                    }
                ))

        return events


simulation_service = SimulationService()
