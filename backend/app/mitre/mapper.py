import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


class MitreMapper:
    """
    Knowledge base mapping detected security threats to MITRE ATT&CK framework techniques.
    """

    TECHNIQUES: Dict[str, Dict[str, Any]] = {
        "T1110": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access (TA0006)",
            "description": "Adversaries repeatedly submit guesses of passwords or credentials to gain access to valid user accounts.",
            "sub_techniques": [
                {"id": "T1110.001", "name": "Password Guessing"},
                {"id": "T1110.003", "name": "Password Spraying"},
                {"id": "T1110.004", "name": "Credential Stuffing"}
            ],
            "default_confidence": 0.95
        },
        "T1078": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Defense Evasion / Initial Access (TA0001/TA0005)",
            "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access or Persistence.",
            "sub_techniques": [
                {"id": "T1078.001", "name": "Default Accounts"},
                {"id": "T1078.002", "name": "Domain Accounts"}
            ],
            "default_confidence": 0.85
        },
        "T1046": {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactic": "Discovery (TA0007)",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable targets.",
            "sub_techniques": [],
            "default_confidence": 0.90
        },
        "T1087": {
            "technique_id": "T1087",
            "technique_name": "Account Discovery",
            "tactic": "Discovery (TA0007)",
            "description": "Adversaries may attempt to get a listing of local or domain accounts to inform subsequent lateral movement.",
            "sub_techniques": [],
            "default_confidence": 0.80
        },
        "T1048": {
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration (TA0010)",
            "description": "Adversaries may steal data by transferring it through an alternative protocol rather than the primary command channel.",
            "sub_techniques": [
                {"id": "T1048.002", "name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"},
                {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2 Protocol"}
            ],
            "default_confidence": 0.92
        },
        "T1190": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access (TA0001)",
            "description": "Adversaries may attempt to exploit vulnerabilities or software bugs in internet-facing applications or web services.",
            "sub_techniques": [],
            "default_confidence": 0.88
        },
        "T1003": {
            "technique_id": "T1003",
            "technique_name": "OS Credential Dumping",
            "tactic": "Credential Access (TA0006)",
            "description": "Adversaries may attempt to dump credentials from the operating system security subsystems, LSASS, or memory.",
            "sub_techniques": [
                {"id": "T1003.001", "name": "LSASS Memory"},
                {"id": "T1003.002", "name": "Security Account Manager"}
            ],
            "default_confidence": 0.94
        },
        "T1562": {
            "technique_id": "T1562",
            "technique_name": "Impair Defenses",
            "tactic": "Defense Evasion (TA0005)",
            "description": "Adversaries may maliciously modify or disable defensive components such as firewalls, security agents, or audit tools.",
            "sub_techniques": [
                {"id": "T1562.001", "name": "Disable or Modify Tools"}
            ],
            "default_confidence": 0.91
        },
        "T1021": {
            "technique_id": "T1021",
            "technique_name": "Remote Services",
            "tactic": "Lateral Movement (TA0008)",
            "description": "Adversaries may log into remote services such as SSH, RDP, or SMB to conduct unauthorized lateral movement.",
            "sub_techniques": [
                {"id": "T1021.001", "name": "Remote Desktop Protocol"},
                {"id": "T1021.004", "name": "SSH"}
            ],
            "default_confidence": 0.89
        }
    }

    def map_attack(self, attack_type: str, explicit_technique: str = None) -> Dict[str, Any]:
        """Maps an attack type string to structured MITRE technique details."""
        tech_id = explicit_technique or "T1110"
        atk_lower = attack_type.lower()

        if "brute" in atk_lower or "password" in atk_lower or "login" in atk_lower:
            tech_id = "T1110"
        elif "exfiltrat" in atk_lower or "outbound transfer" in atk_lower or "data leak" in atk_lower:
            tech_id = "T1048"
        elif "exploit" in atk_lower or "vulnerability" in atk_lower or "remote code" in atk_lower:
            tech_id = "T1190"
        elif "dump" in atk_lower or "lsass" in atk_lower or "sam" in atk_lower:
            tech_id = "T1003"
        elif "impair" in atk_lower or "disable firewall" in atk_lower or "tamper" in atk_lower:
            tech_id = "T1562"
        elif "lateral" in atk_lower or "remote service" in atk_lower:
            tech_id = "T1021"
        elif "port" in atk_lower or "scan" in atk_lower:
            tech_id = "T1046"
        elif "account" in atk_lower or "discovery" in atk_lower:
            tech_id = "T1087"
        elif "privilege" in atk_lower or "suspicious" in atk_lower or "unauthorized" in atk_lower:
            tech_id = "T1078"

        tech = self.TECHNIQUES.get(tech_id, self.TECHNIQUES["T1110"])
        return {
            "technique_id": tech["technique_id"],
            "technique_name": tech["technique_name"],
            "tactic": tech["tactic"],
            "description": tech["description"],
            "mapping_confidence": tech["default_confidence"],
            "sub_techniques": tech.get("sub_techniques", [])
        }

    def map_incident(self, incident) -> Dict[str, Any]:
        """Maps an Incident object to structured MITRE technique details."""
        attack_type = getattr(incident, "attack_type", "") or ""
        technique = getattr(incident, "mitre_technique", None)
        return self.map_attack(attack_type, technique)


mitre_mapper = MitreMapper()

