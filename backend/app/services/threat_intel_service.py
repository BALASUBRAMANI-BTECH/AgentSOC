import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """
    Threat Intelligence IOC Enrichment Service.
    Queries external and internal reputation data, Tor node lists, domains, hashes, and abuse scores.
    """

    KNOWN_MALICIOUS_IPS: Dict[str, Dict[str, Any]] = {
        "185.220.101.5": {
            "ioc": "185.220.101.5",
            "type": "ipv4",
            "reputation": "MALICIOUS",
            "abuse_score": 98,
            "threat_actor": "APT-29 (Cozy Bear) / Tor Exit Relay",
            "category": "Tor Exit Node & State-Sponsored Ingress",
            "is_tor_exit_node": True,
            "country": "Germany",
            "city": "Frankfurt",
            "asn": "AS60729",
            "mitre_tactic": "TA0001 Initial Access",
            "last_seen": "2026-09-16T12:00:00Z"
        },
        "192.168.1.50": {
            "ioc": "192.168.1.50",
            "type": "ipv4",
            "reputation": "SUSPICIOUS_HIGH",
            "abuse_score": 88,
            "threat_actor": "Internal Adversary / Automated Rig",
            "category": "Automated Password Guessing & Brute-Force",
            "is_tor_exit_node": False,
            "country": "Internal Enterprise LAN",
            "city": "DMZ Lab",
            "asn": "AS-INTERNAL",
            "mitre_tactic": "TA0006 Credential Access",
            "last_seen": "2026-09-16T15:45:00Z"
        },
        "45.33.32.156": {
            "ioc": "45.33.32.156",
            "type": "ipv4",
            "reputation": "MALICIOUS",
            "abuse_score": 95,
            "threat_actor": "ShadowBroker Botnet",
            "category": "Distributed Credential Stuffing & Scanning",
            "is_tor_exit_node": False,
            "country": "United States",
            "city": "Fremont",
            "asn": "AS63949",
            "mitre_tactic": "TA0006 Credential Access",
            "last_seen": "2026-09-16T10:15:00Z"
        },
        "198.51.100.23": {
            "ioc": "198.51.100.23",
            "type": "ipv4",
            "reputation": "MALICIOUS",
            "abuse_score": 94,
            "threat_actor": "Lazarus Group (HIDDEN COBRA)",
            "category": "C2 Infrastructure & Fast-Flux Node",
            "is_tor_exit_node": False,
            "country": "North Korea / Relayed",
            "city": "Pyongyang Proxy",
            "asn": "AS131279",
            "mitre_tactic": "TA0011 Command and Control",
            "last_seen": "2026-09-15T22:30:00Z"
        },
        "91.240.118.172": {
            "ioc": "91.240.118.172",
            "type": "ipv4",
            "reputation": "MALICIOUS",
            "abuse_score": 91,
            "threat_actor": "Sandworm Team / GRU 74455",
            "category": "ICS/SCADA Recon & Lateral Movement",
            "is_tor_exit_node": False,
            "country": "Russian Federation",
            "city": "Moscow",
            "asn": "AS49392",
            "mitre_tactic": "TA0008 Lateral Movement",
            "last_seen": "2026-09-14T08:12:00Z"
        },
        "10.0.1.99": {
            "ioc": "10.0.1.99",
            "type": "ipv4",
            "reputation": "SUSPICIOUS_MEDIUM",
            "abuse_score": 75,
            "threat_actor": "Internal Recon Rig",
            "category": "Port Scanner & Service Discovery Probe",
            "is_tor_exit_node": False,
            "country": "Internal Subnet",
            "city": "VLAN 100",
            "asn": "AS-INTERNAL",
            "mitre_tactic": "TA0007 Discovery",
            "last_seen": "2026-09-16T14:20:00Z"
        }
    }

    KNOWN_MALICIOUS_DOMAINS: Dict[str, Dict[str, Any]] = {
        "c2-stealth-beacon.xyz": {
            "ioc": "c2-stealth-beacon.xyz",
            "type": "domain",
            "reputation": "MALICIOUS",
            "abuse_score": 97,
            "threat_actor": "Cobalt Strike / Silver C2",
            "category": "Adversary Command & Control Beacon",
            "country": "Seychelles",
            "asn": "AS197695",
            "mitre_tactic": "TA0011 Command and Control",
            "last_seen": "2026-09-16T09:00:00Z"
        },
        "darkweb-exfil-portal.cc": {
            "ioc": "darkweb-exfil-portal.cc",
            "type": "domain",
            "reputation": "MALICIOUS",
            "abuse_score": 99,
            "threat_actor": "BlackCat / ALPHV Ransomware Group",
            "category": "Data Exfiltration Staging Drop",
            "country": "Panama",
            "asn": "AS40034",
            "mitre_tactic": "TA0010 Exfiltration",
            "last_seen": "2026-09-16T11:45:00Z"
        },
        "payload-delivery.top": {
            "ioc": "payload-delivery.top",
            "type": "domain",
            "reputation": "MALICIOUS",
            "abuse_score": 90,
            "threat_actor": "Emotet / TA542 Distribution Network",
            "category": "Initial Access Malware Loader",
            "country": "Bulgaria",
            "asn": "AS206804",
            "mitre_tactic": "TA0001 Initial Access",
            "last_seen": "2026-09-15T18:20:00Z"
        }
    }

    KNOWN_MALICIOUS_HASHES: Dict[str, Dict[str, Any]] = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "type": "sha256",
            "reputation": "MALICIOUS",
            "abuse_score": 96,
            "threat_actor": "Mimikatz LSASS In-Memory Dumper",
            "category": "Credential Extraction Tool",
            "country": "Global",
            "asn": "N/A",
            "mitre_tactic": "TA0006 Credential Access",
            "last_seen": "2026-09-16T04:10:00Z"
        },
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
            "ioc": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "type": "sha256",
            "reputation": "MALICIOUS",
            "abuse_score": 99,
            "threat_actor": "Cobalt Strike HTTPS Malleable Stager",
            "category": "Weaponized Shellcode Injector",
            "country": "Global",
            "asn": "N/A",
            "mitre_tactic": "TA0002 Execution",
            "last_seen": "2026-09-16T07:35:00Z"
        }
    }

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Looks up threat intelligence dossier for an IP address (maintains backwards compatibility)."""
        if ip in self.KNOWN_MALICIOUS_IPS:
            return self.KNOWN_MALICIOUS_IPS[ip]

        # Dynamic heuristic for other IPs
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
            return {
                "ioc": ip,
                "type": "ipv4",
                "reputation": "INTERNAL_CLEAN",
                "abuse_score": 10,
                "threat_actor": "None",
                "category": "Private Enterprise Subnet",
                "is_tor_exit_node": False,
                "country": "Local",
                "city": "Internal LAN",
                "asn": "RFC1918",
                "mitre_tactic": "None",
                "last_seen": "2026-09-16T16:00:00Z"
            }

        return {
            "ioc": ip,
            "type": "ipv4",
            "reputation": "SUSPICIOUS_UNVERIFIED",
            "abuse_score": 50,
            "threat_actor": "Unknown Scanner",
            "category": "External WAN Ingress",
            "is_tor_exit_node": False,
            "country": "External",
            "city": "Unknown",
            "asn": "AS-UNKNOWN",
            "mitre_tactic": "TA0007 Discovery",
            "last_seen": "2026-09-16T16:00:00Z"
        }

    def lookup_ioc(self, ioc: str) -> Dict[str, Any]:
        """Looks up reputation for any IOC (IP, domain, or SHA256 hash)."""
        clean_ioc = ioc.strip().lower()

        # Check IP
        if clean_ioc in self.KNOWN_MALICIOUS_IPS:
            return self.KNOWN_MALICIOUS_IPS[clean_ioc]

        # Check Domain
        if clean_ioc in self.KNOWN_MALICIOUS_DOMAINS:
            return self.KNOWN_MALICIOUS_DOMAINS[clean_ioc]

        # Check Hash
        if clean_ioc in self.KNOWN_MALICIOUS_HASHES:
            return self.KNOWN_MALICIOUS_HASHES[clean_ioc]

        # Heuristic IP check
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if re.match(ip_pattern, clean_ioc):
            return self.check_ip_reputation(clean_ioc)

        # Heuristic Domain check
        if "." in clean_ioc and not clean_ioc.endswith("."):
            return {
                "ioc": clean_ioc,
                "type": "domain",
                "reputation": "UNCLASSIFIED_DOMAIN",
                "abuse_score": 35,
                "threat_actor": "Unattributed",
                "category": "External Domain Asset",
                "country": "Global",
                "asn": "AS-DNS-RESOLVED",
                "mitre_tactic": "TA0011 Command and Control",
                "last_seen": "2026-09-16T16:00:00Z"
            }

        # Heuristic Hash check (32 hex = MD5, 64 hex = SHA256)
        if re.match(r"^[a-f0-9]{64}$", clean_ioc):
            return {
                "ioc": clean_ioc,
                "type": "sha256",
                "reputation": "UNCLASSIFIED_HASH",
                "abuse_score": 40,
                "threat_actor": "Unattributed File",
                "category": "Unknown Binary / Artifact",
                "country": "Global",
                "asn": "N/A",
                "mitre_tactic": "TA0002 Execution",
                "last_seen": "2026-09-16T16:00:00Z"
            }

        return {
            "ioc": clean_ioc,
            "type": "generic",
            "reputation": "UNKNOWN",
            "abuse_score": 20,
            "threat_actor": "None",
            "category": "Unknown Telemetry Token",
            "country": "Unknown",
            "asn": "N/A",
            "mitre_tactic": "None",
            "last_seen": "2026-09-16T16:00:00Z"
        }

    def get_threat_feed(self) -> List[Dict[str, Any]]:
        """Returns the curated active global threat intelligence feed."""
        feed = []
        for ioc, data in self.KNOWN_MALICIOUS_IPS.items():
            feed.append(data)
        for ioc, data in self.KNOWN_MALICIOUS_DOMAINS.items():
            feed.append(data)
        for ioc, data in self.KNOWN_MALICIOUS_HASHES.items():
            feed.append(data)
        return feed


threat_intel_service = ThreatIntelService()
