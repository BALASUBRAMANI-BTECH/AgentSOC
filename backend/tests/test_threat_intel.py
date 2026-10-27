import pytest
from app.services.threat_intel_service import threat_intel_service


def test_ip_reputation_lookup():
    intel = threat_intel_service.lookup_ioc("185.220.101.5")
    assert intel["reputation"] == "MALICIOUS"
    assert intel["abuse_score"] >= 90
    assert intel["is_tor_exit_node"] is True
    assert "APT-29" in intel["threat_actor"]


def test_domain_reputation_lookup():
    intel = threat_intel_service.lookup_ioc("c2-stealth-beacon.xyz")
    assert intel["reputation"] == "MALICIOUS"
    assert intel["type"] == "domain"
    assert "Cobalt Strike" in intel["threat_actor"]


def test_hash_reputation_lookup():
    intel = threat_intel_service.lookup_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert intel["reputation"] == "MALICIOUS"
    assert intel["type"] == "sha256"
    assert "Mimikatz" in intel["threat_actor"]


def test_threat_feed_listing():
    feed = threat_intel_service.get_threat_feed()
    assert len(feed) >= 5
    types = [item["type"] for item in feed]
    assert "ipv4" in types
    assert "domain" in types
    assert "sha256" in types
