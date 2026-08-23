"""Unit tests for SentinelMemory state management and SQLite persistence."""

import os
import pytest

from app.memory import SentinelMemory
from app.models import (
    AgentEvaluation,
    ParsedEmail,
    ScanStatus,
    ScanTarget,
    ThreatLevel,
    UrlscanResult,
    VTResult,
)


@pytest.fixture
def temp_memory_db(tmp_path):
    db_file = str(tmp_path / "test_memory.db")
    memory = SentinelMemory(db_path=db_file)
    return memory


class TestSentinelMemory:
    def test_init_and_default_trusted_baselines(self, temp_memory_db):
        assert temp_memory_db.is_domain_trusted("microsoft.com") == "Microsoft 365 / Azure"
        assert temp_memory_db.is_domain_trusted("login.microsoftonline.com") == "Microsoft 365 / Azure"
        assert temp_memory_db.is_domain_trusted("gmail.com") == "Google Workspace"
        assert temp_memory_db.is_domain_trusted("unknown-evil-site.top") is None

    def test_record_and_lookup_investigation(self, temp_memory_db):
        target = ScanTarget(raw_url="https://phishing-site.xyz/login")
        vt = VTResult(status=ScanStatus.COMPLETED, malicious_count=8)
        urlscan = UrlscanResult(status=ScanStatus.COMPLETED, verdict_score=85)
        evaluation = AgentEvaluation(
            threat_level=ThreatLevel.MALICIOUS,
            confidence_score=95,
            reasoning_summary="Credential harvester impersonating Microsoft.",
            recommended_actions=["Block domain"],
            indicators_of_compromise=["phishing-site[.]xyz"],
            impersonated_brand="Microsoft",
        )

        inv_id = temp_memory_db.record_investigation(
            target=target,
            vt_result=vt,
            urlscan_result=urlscan,
            evaluation=evaluation,
        )
        assert inv_id > 0

        # Lookup by domain
        history = temp_memory_db.lookup_target_history("phishing-site.xyz")
        assert history is not None
        assert history["threat_level"] == "MALICIOUS"
        assert history["confidence_score"] == 95
        assert history["impersonated_brand"] == "Microsoft"

    def test_threat_campaign_correlation(self, temp_memory_db):
        # 1st incident for Microsoft brand
        camp_1 = temp_memory_db.correlate_or_create_campaign(
            targeted_brand="Microsoft",
            domain="phish-domain-1.top",
            threat_level=ThreatLevel.MALICIOUS,
        )
        assert camp_1 is not None
        assert camp_1["attack_count"] == 1
        assert camp_1["is_recurring"] is False

        # 2nd repeat incident for same brand with new domain
        camp_2 = temp_memory_db.correlate_or_create_campaign(
            targeted_brand="Microsoft",
            domain="phish-domain-2.top",
            threat_level=ThreatLevel.MALICIOUS,
        )
        assert camp_2 is not None
        assert camp_2["attack_count"] == 2
        assert camp_2["is_recurring"] is True
        assert "phish-domain-2.top" in camp_2["associated_domains"]

    def test_agent_execution_traces(self, temp_memory_db):
        inv_id = 1
        temp_memory_db.record_step_trace(
            investigation_id=inv_id,
            step_number=1,
            step_name="MEMORY_CHECK",
            action_taken="Queried memory for evil.com",
            observation="Found 0 past scans",
        )
        temp_memory_db.record_step_trace(
            investigation_id=inv_id,
            step_number=2,
            step_name="SCAN_VT",
            action_taken="Queried VirusTotal",
            observation="Positives: 10",
        )

        traces = temp_memory_db.get_execution_traces(inv_id)
        assert len(traces) == 2
        assert traces[0]["step_name"] == "MEMORY_CHECK"
        assert traces[1]["step_name"] == "SCAN_VT"
