"""Unit tests with mocked HTTP for VirusTotal and urlscan.io scanners."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch

from app.models import ScanStatus
from app.scanners.virustotal import VirusTotalScanner
from app.scanners.urlscan import UrlscanScanner


@pytest.mark.asyncio
class TestVirusTotalScanner:
    async def test_virustotal_clean_url(self, mock_settings, sample_safe_target, vt_clean_payload):
        scanner = VirusTotalScanner(mock_settings)

        mock_response = httpx.Response(
            status_code=200,
            json=vt_clean_payload,
            request=httpx.Request("GET", "https://test.com"),
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            result = await scanner.scan_url(sample_safe_target)

            assert result.status == ScanStatus.COMPLETED
            assert result.malicious_count == 0
            assert result.harmless_count == 75
            assert result.is_malicious is False
            assert result.permalink is not None

    async def test_virustotal_malicious_url(self, mock_settings, sample_malicious_target, vt_malicious_payload):
        scanner = VirusTotalScanner(mock_settings)

        mock_response = httpx.Response(
            status_code=200,
            json=vt_malicious_payload,
            request=httpx.Request("GET", "https://test.com"),
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            result = await scanner.scan_url(sample_malicious_target)

            assert result.status == ScanStatus.COMPLETED
            assert result.malicious_count == 14
            assert result.suspicious_count == 3
            assert result.is_malicious is True
            assert "Kaspersky" in result.engine_scan_summary

    async def test_virustotal_rate_limit_429_backoff(self, mock_settings, sample_safe_target, vt_clean_payload):
        scanner = VirusTotalScanner(mock_settings)

        response_429 = httpx.Response(
            status_code=429,
            json={"error": "Rate limit exceeded"},
            request=httpx.Request("GET", "https://test.com"),
        )
        response_200 = httpx.Response(
            status_code=200,
            json=vt_clean_payload,
            request=httpx.Request("GET", "https://test.com"),
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            # First call returns 429, second succeeds with 200
            mock_get.side_effect = [response_429, response_200]
            result = await scanner.scan_url(sample_safe_target)

            assert result.status == ScanStatus.COMPLETED
            assert result.malicious_count == 0
            assert mock_get.call_count == 2


@pytest.mark.asyncio
class TestUrlscanScanner:
    async def test_urlscan_successful_submission_and_polling(
        self,
        mock_settings,
        sample_malicious_target,
        urlscan_submit_payload,
        urlscan_result_completed_payload,
    ):
        scanner = UrlscanScanner(mock_settings)

        submit_response = httpx.Response(
            status_code=200,
            json=urlscan_submit_payload,
            request=httpx.Request("POST", "https://urlscan.io/api/v1/scan/"),
        )
        poll_404_response = httpx.Response(
            status_code=404,
            request=httpx.Request("GET", "https://urlscan.io/api/v1/result/"),
        )
        poll_200_response = httpx.Response(
            status_code=200,
            json=urlscan_result_completed_payload,
            request=httpx.Request("GET", "https://urlscan.io/api/v1/result/"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post, \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            
            mock_post.return_value = submit_response
            # First poll returns 404 (processing), second returns 200 (done)
            mock_get.side_effect = [poll_404_response, poll_200_response]

            result = await scanner.scan_url(sample_malicious_target)

            assert result.status == ScanStatus.COMPLETED
            assert result.verdict_score == 85
            assert result.malicious is True
            assert "phishing" in result.tags
            assert result.scan_uuid == "01234567-89ab-cdef-0123-456789abcdef"

    async def test_urlscan_timeout_handling(
        self,
        mock_settings,
        sample_safe_target,
        urlscan_submit_payload,
    ):
        # Settings with short timeout
        mock_settings.URLSCAN_TIMEOUT = 0.15
        mock_settings.URLSCAN_POLL_INTERVAL = 0.05
        scanner = UrlscanScanner(mock_settings)

        submit_response = httpx.Response(
            status_code=200,
            json=urlscan_submit_payload,
            request=httpx.Request("POST", "https://urlscan.io/api/v1/scan/"),
        )
        poll_404_response = httpx.Response(
            status_code=404,
            request=httpx.Request("GET", "https://urlscan.io/api/v1/result/"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post, \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            
            mock_post.return_value = submit_response
            mock_get.return_value = poll_404_response

            result = await scanner.scan_url(sample_safe_target)

            assert result.status == ScanStatus.INCONCLUSIVE
            assert "timed out" in result.error_message.lower()
