"""Unit tests for the InvestigationPlanner multi-step reasoning workflow."""

import pytest
from unittest.mock import AsyncMock, patch

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
from app.planner import InvestigationPlanner


@pytest.fixture
def planner_memory(tmp_path):
    db_file = str(tmp_path / "planner_test_memory.db")
    return SentinelMemory(db_path=db_file)


@pytest.mark.asyncio
class TestInvestigationPlanner:
    async def test_planner_executes_5_step_investigation(
        self,
        mock_settings,
        planner_memory,
        sample_malicious_target,
    ):
        planner = InvestigationPlanner(settings=mock_settings, memory=planner_memory)

        mock_vt = VTResult(
            status=ScanStatus.COMPLETED,
            malicious_count=10,
            suspicious_count=2,
            permalink="https://virustotal.com/gui/url/123",
        )
        mock_urlscan = UrlscanResult(
            status=ScanStatus.COMPLETED,
            verdict_score=90,
            malicious=True,
            tags=["phishing"],
            report_link="https://urlscan.io/result/123",
        )
        mock_eval = AgentEvaluation(
            threat_level=ThreatLevel.MALICIOUS,
            confidence_score=98,
            reasoning_summary="Target domain impersonates Bank of America with credential theft forms.",
            recommended_actions=["Block domain at firewall", "Purge emails"],
            indicators_of_compromise=["bankofamerica.update-auth-now[.]top"],
            impersonated_brand="Bank of America",
        )

        with patch.object(planner.vt_scanner, "scan_url", new_callable=AsyncMock) as mock_vt_scan, \
             patch.object(planner.urlscan_scanner, "scan_url", new_callable=AsyncMock) as mock_url_scan, \
             patch.object(planner.agent, "evaluate_target", new_callable=AsyncMock) as mock_agent_eval, \
             patch.object(planner.notifier, "send_alert", new_callable=AsyncMock) as mock_notify:

            mock_vt_scan.return_value = mock_vt
            mock_url_scan.return_value = mock_urlscan
            mock_agent_eval.return_value = mock_eval
            mock_notify.return_value = True

            report = await planner.execute_investigation(
                target=sample_malicious_target,
                send_alert=True,
            )

            assert report.target == sample_malicious_target
            assert report.evaluation.threat_level == ThreatLevel.MALICIOUS
            assert report.evaluation.impersonated_brand == "Bank of America"
            assert mock_notify.called

            # Verify memory was persisted
            history = planner_memory.lookup_target_history(sample_malicious_target.domain)
            assert history is not None
            assert history["threat_level"] == "MALICIOUS"
            assert history["confidence_score"] == 98

            # Verify all 5 execution step traces were recorded in SQLite
            traces = planner_memory.get_execution_traces(history["id"])
            assert len(traces) == 5
            step_names = [t["step_name"] for t in traces]
            assert "MEMORY_RECALL_AND_BASELINE_CHECK" in step_names
            assert "GATHER_THREAT_INTELLIGENCE" in step_names
            assert "REASON_AND_EVALUATE" in step_names
            assert "PERSIST_AND_CORRELATE_CAMPAIGN" in step_names
            assert "DISPATCH_REMEDIATION_ALERT" in step_names
