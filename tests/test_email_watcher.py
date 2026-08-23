"""Unit tests for IMAPEmailWatcher with mocked IMAP socket operations."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.config import Settings
from app.email_watcher import IMAPEmailWatcher
from app.models import ComprehensiveScanReport, ScanStatus, ScanTarget, ThreatLevel, UrlscanResult, VTResult


@pytest.fixture
def mock_imap_settings():
    return Settings(
        VIRUSTOTAL_API_KEY="test_vt_key",
        URLSCAN_API_KEY="test_urlscan_key",
        DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/123/token",
        LLM_API_KEY="gsk_test_key",
        IMAP_HOST="imap.example.com",
        IMAP_USER="analyst@example.com",
        IMAP_PASSWORD="secret_password",
        IMAP_FOLDER="INBOX",
        IMAP_POLL_INTERVAL=0.1,
    )


@pytest.mark.asyncio
class TestIMAPEmailWatcher:
    async def test_check_mailbox_once_with_mock_message(self, mock_imap_settings):
        sample_eml = (
            b'From: "Security" <alerts@phish.xyz>\n'
            b'To: user@company.com\n'
            b'Subject: Reset Password\n'
            b'Content-Type: text/plain\n\n'
            b'Click here: https://phishing-portal.com/login\n'
        )

        mock_imap_client = MagicMock()
        mock_imap_client.search.return_value = ("OK", [b"1"])
        mock_imap_client.fetch.return_value = ("OK", [(b"1 (RFC822 {100}", sample_eml), b")"])

        mock_pipeline = MagicMock()
        mock_report = ComprehensiveScanReport(
            target=ScanTarget(raw_url="https://phishing-portal.com/login"),
            virustotal=VTResult(status=ScanStatus.COMPLETED, malicious_count=5),
            urlscan=UrlscanResult(status=ScanStatus.COMPLETED, verdict_score=80),
        )
        mock_pipeline.scan_single_target = AsyncMock(return_value=mock_report)

        watcher = IMAPEmailWatcher(mock_imap_settings, pipeline=mock_pipeline)

        with patch("imaplib.IMAP4_SSL", return_value=mock_imap_client):
            reports = await watcher.check_mailbox_once()

            assert len(reports) == 1
            assert reports[0].target.domain == "phishing-portal.com"
            assert reports[0].email_metadata.subject == "Reset Password"
            assert mock_pipeline.scan_single_target.called
            assert mock_imap_client.store.called  # Marked as seen
