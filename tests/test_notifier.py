"""Unit tests for DiscordNotifier embed formatting and dispatching."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch

from app.models import (
    AgentEvaluation,
    ScanStatus,
    ThreatLevel,
    UrlscanResult,
    VTResult,
)
from app.notifier import (
    COLOR_MALICIOUS,
    COLOR_SAFE,
    COLOR_SUSPICIOUS,
    DiscordNotifier,
)


class TestDiscordNotifier:
    def test_embed_colors_and_defanging(self, mock_settings, sample_malicious_target):
        notifier = DiscordNotifier(mock_settings)

        vt_res = VTResult(
            status=ScanStatus.COMPLETED,
            malicious_count=10,
            suspicious_count=2,
            harmless_count=50,
            undetected_count=10,
            permalink="https://virustotal.com/gui/url/123",
        )
        urlscan_res = UrlscanResult(
            status=ScanStatus.COMPLETED,
            verdict_score=90,
            malicious=True,
            tags=["phishing"],
            screenshot_url="https://urlscan.io/screenshots/123.png",
            report_link="https://urlscan.io/result/123",
        )

        # 1. Test Malicious Embed
        eval_malicious = AgentEvaluation(
            threat_level=ThreatLevel.MALICIOUS,
            confidence_score=95,
            reasoning_summary="Credential harvester impersonating financial institution.",
            recommended_actions=["Block domain", "Revoke tokens"],
            indicators_of_compromise=["malicious-site[.]top"],
            impersonated_brand="Bank of America",
        )
        embed = notifier.build_embed(sample_malicious_target, vt_res, urlscan_res, eval_malicious)

        assert embed["color"] == COLOR_MALICIOUS
        assert "MALICIOUS" in embed["title"]
        assert sample_malicious_target.defanged_url in str(embed["fields"])
        assert embed.get("image", {}).get("url") == "https://urlscan.io/screenshots/123.png"

        # 2. Test Suspicious Embed
        eval_suspicious = AgentEvaluation(
            threat_level=ThreatLevel.SUSPICIOUS,
            confidence_score=70,
            reasoning_summary="Newly registered domain with unverified SSL certificate.",
        )
        embed_susp = notifier.build_embed(sample_malicious_target, vt_res, urlscan_res, eval_suspicious)
        assert embed_susp["color"] == COLOR_SUSPICIOUS

        # 3. Test Safe Embed
        eval_safe = AgentEvaluation(
            threat_level=ThreatLevel.SAFE,
            confidence_score=90,
            reasoning_summary="Legitimate domain with zero malicious hits across all engines.",
        )
        embed_safe = notifier.build_embed(sample_malicious_target, vt_res, urlscan_res, eval_safe)
        assert embed_safe["color"] == COLOR_SAFE

    @pytest.mark.asyncio
    async def test_send_alert_http_dispatch(self, mock_settings, sample_malicious_target):
        notifier = DiscordNotifier(mock_settings)

        vt_res = VTResult(status=ScanStatus.COMPLETED)
        urlscan_res = UrlscanResult(status=ScanStatus.COMPLETED)
        evaluation = AgentEvaluation(
            threat_level=ThreatLevel.MALICIOUS,
            confidence_score=90,
            reasoning_summary="Test alert dispatch.",
        )

        mock_response = httpx.Response(
            status_code=204,
            request=httpx.Request("POST", notifier.webhook_url),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            success = await notifier.send_alert(
                sample_malicious_target, vt_res, urlscan_res, evaluation
            )

            assert success is True
            assert mock_post.called
            payload = mock_post.call_args[1]["json"]
            assert len(payload["embeds"]) == 1
            assert payload["embeds"][0]["color"] == COLOR_MALICIOUS
