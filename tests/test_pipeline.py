"""Unit tests for the end-to-end PhishingSentinelPipeline."""

import pytest
from unittest.mock import AsyncMock, patch

from app.models import (
    AgentEvaluation,
    ScanStatus,
    ScanTarget,
    ThreatLevel,
    UrlscanResult,
    VTResult,
)
from app.pipeline import PhishingSentinelPipeline


@pytest.mark.asyncio
class TestPhishingSentinelPipeline:
    async def test_pipeline_scan_single_target(self, mock_settings, sample_malicious_target):
        pipeline = PhishingSentinelPipeline(mock_settings)

        mock_vt = VTResult(
            status=ScanStatus.COMPLETED,
            malicious_count=15,
            suspicious_count=2,
            permalink="https://virustotal.com/gui/url/123",
        )
        mock_urlscan = UrlscanResult(
            status=ScanStatus.COMPLETED,
            verdict_score=95,
            malicious=True,
            tags=["phishing"],
            report_link="https://urlscan.io/result/123",
        )
        mock_eval = AgentEvaluation(
            threat_level=ThreatLevel.MALICIOUS,
            confidence_score=99,
            reasoning_summary="Confirmed credential harvesting page.",
            recommended_actions=["Block domain"],
            indicators_of_compromise=["malicious-site[.]top"],
        )

        with patch.object(pipeline.vt_scanner, "scan_url", new_callable=AsyncMock) as mock_vt_scan, \
             patch.object(pipeline.urlscan_scanner, "scan_url", new_callable=AsyncMock) as mock_url_scan, \
             patch.object(pipeline.agent, "evaluate_target", new_callable=AsyncMock) as mock_agent_eval, \
             patch.object(pipeline.notifier, "send_alert", new_callable=AsyncMock) as mock_notify:

            mock_vt_scan.return_value = mock_vt
            mock_url_scan.return_value = mock_urlscan
            mock_agent_eval.return_value = mock_eval
            mock_notify.return_value = True

            report = await pipeline.scan_single_target(sample_malicious_target, send_alert=True)

            assert report.target == sample_malicious_target
            assert report.virustotal.malicious_count == 15
            assert report.urlscan.verdict_score == 95
            assert report.evaluation.threat_level == ThreatLevel.MALICIOUS
            assert mock_notify.called

    async def test_pipeline_analyze_email_content(self, mock_settings):
        pipeline = PhishingSentinelPipeline(mock_settings)

        email_content = """
        Urgent security alert:
        Please review your account at https://verify-identity.suspicious-portal.com/auth
        """

        mock_vt = VTResult(status=ScanStatus.COMPLETED, malicious_count=0)
        mock_urlscan = UrlscanResult(status=ScanStatus.COMPLETED, verdict_score=0)
        mock_eval = AgentEvaluation(
            threat_level=ThreatLevel.SAFE,
            confidence_score=90,
            reasoning_summary="No malicious signals.",
        )

        with patch.object(pipeline.vt_scanner, "scan_url", new_callable=AsyncMock) as mock_vt_scan, \
             patch.object(pipeline.urlscan_scanner, "scan_url", new_callable=AsyncMock) as mock_url_scan, \
             patch.object(pipeline.agent, "evaluate_target", new_callable=AsyncMock) as mock_agent_eval:

            mock_vt_scan.return_value = mock_vt
            mock_url_scan.return_value = mock_urlscan
            mock_agent_eval.return_value = mock_eval

            reports = await pipeline.analyze_email_content(email_content, send_alerts=False)

            assert len(reports) == 1
            assert reports[0].target.domain == "verify-identity.suspicious-portal.com"
            assert reports[0].evaluation.threat_level == ThreatLevel.SAFE
