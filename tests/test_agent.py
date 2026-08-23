"""Unit tests for PhishingAnalystAgent with mocked LLM responses."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch

from app.agent import PhishingAnalystAgent
from app.models import ScanStatus, ThreatLevel, UrlscanResult, VTResult


@pytest.fixture
def sample_vt_result():
    return VTResult(
        status=ScanStatus.COMPLETED,
        malicious_count=12,
        suspicious_count=2,
        harmless_count=45,
        undetected_count=10,
        permalink="https://virustotal.com/gui/url/123",
    )


@pytest.fixture
def sample_urlscan_result():
    return UrlscanResult(
        status=ScanStatus.COMPLETED,
        verdict_score=90,
        malicious=True,
        tags=["phishing", "credential-harvesting"],
        screenshot_url="https://urlscan.io/screenshots/123.png",
        report_link="https://urlscan.io/result/123",
    )


@pytest.mark.asyncio
class TestPhishingAnalystAgent:
    async def test_agent_evaluates_malicious_target_successfully(
        self,
        mock_settings,
        sample_malicious_target,
        sample_vt_result,
        sample_urlscan_result,
    ):
        agent = PhishingAnalystAgent(mock_settings)

        llm_response_json = {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{\n'
                            '  "threat_level": "MALICIOUS",\n'
                            '  "confidence_score": 98,\n'
                            '  "reasoning_summary": "Domain impersonates Bank of America with credential harvesting inputs.",\n'
                            '  "recommended_actions": ["Block domain", "Revoke user sessions", "Purge emails"],\n'
                            '  "indicators_of_compromise": ["secure-login.bankofamerica.update-auth-now[.]top"],\n'
                            '  "impersonated_brand": "Bank of America"\n'
                            '}'
                        )
                    }
                }
            ]
        }

        mock_http_response = httpx.Response(
            status_code=200,
            json=llm_response_json,
            request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_http_response

            evaluation = await agent.evaluate_target(
                target=sample_malicious_target,
                vt_result=sample_vt_result,
                urlscan_result=sample_urlscan_result,
                email_context="Urgent notice: Verify your bank account immediately.",
            )

            assert evaluation.threat_level == ThreatLevel.MALICIOUS
            assert evaluation.confidence_score == 98
            assert evaluation.impersonated_brand == "Bank of America"
            assert len(evaluation.recommended_actions) == 3

    async def test_agent_fallback_on_llm_failure(
        self,
        mock_settings,
        sample_malicious_target,
        sample_vt_result,
        sample_urlscan_result,
    ):
        agent = PhishingAnalystAgent(mock_settings)

        mock_error_response = httpx.Response(
            status_code=500,
            text="Internal Server Error",
            request=httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_error_response

            evaluation = await agent.evaluate_target(
                target=sample_malicious_target,
                vt_result=sample_vt_result,
                urlscan_result=sample_urlscan_result,
            )

            # Fallback should activate deterministically and classify as MALICIOUS due to VT count
            assert evaluation.threat_level == ThreatLevel.MALICIOUS
            assert evaluation.confidence_score == 85
            assert "fallback" in evaluation.reasoning_summary.lower()
