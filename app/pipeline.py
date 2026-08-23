"""End-to-End Orchestrator Pipeline for the Phishing Sentinel AI Agent."""

from app.models import ParsedEmail
import asyncio
import logging
from typing import List, Optional

from app.agent import PhishingAnalystAgent
from app.config import Settings, get_settings
from app.extractor import LinkExtractor
from app.models import (
    ComprehensiveScanReport,
    ScanStatus,
    ScanTarget,
    ThreatLevel,
    UrlscanResult,
    VTResult,
)
from app.notifier import DiscordNotifier
from app.scanners.urlscan import UrlscanScanner
from app.scanners.virustotal import VirusTotalScanner

from app.memory import SentinelMemory
from app.planner import InvestigationPlanner

logger = logging.getLogger(__name__)


class PhishingSentinelPipeline:
    """
    Coordinates link extraction, multi-source threat scanning, AI analysis, and alerting.
    """

    def __init__(self, settings: Optional[Settings] = None, memory: Optional[SentinelMemory] = None):
        self.settings = settings or get_settings()
        self.memory = memory or SentinelMemory(settings=self.settings)
        self.planner = InvestigationPlanner(settings=self.settings, memory=self.memory)

        # Scanner & notifier references preserved for backwards compatibility
        self.vt_scanner = self.planner.vt_scanner
        self.urlscan_scanner = self.planner.urlscan_scanner
        self.agent = self.planner.agent
        self.notifier = self.planner.notifier

    async def scan_single_target(
        self,
        target: ScanTarget,
        email_context: Optional[str] = None,
        email_metadata: Optional[ParsedEmail] = None,
        send_alert: bool = True,
        alert_on_safe: bool = False,
    ) -> ComprehensiveScanReport:
        """
        Executes the autonomous 5-step investigation plan with memory recall, multi-source telemetry,
        AI synthesis, campaign clustering, and SQLite persistence.
        """
        return await self.planner.execute_investigation(
            target=target,
            email_context=email_context,
            email_metadata=email_metadata,
            send_alert=send_alert,
            alert_on_safe=alert_on_safe,
        )

    async def analyze_email_content(
        self,
        content: str,
        send_alerts: bool = True,
        alert_on_safe: bool = False,
    ) -> List[ComprehensiveScanReport]:
        """
        Extracts all embedded links from email text/HTML and conducts threat investigations.
        """
        targets = LinkExtractor.extract_urls(content)
        if not targets:
            logger.info("[Pipeline] No extractable URL targets found in content.")
            return []

        logger.info(f"[Pipeline] Extracted {len(targets)} target(s) for investigation.")
        reports: List[ComprehensiveScanReport] = []

        for target in targets:
            report = await self.scan_single_target(
                target=target,
                email_context=content[:500],
                send_alert=send_alerts,
                alert_on_safe=alert_on_safe,
            )
            reports.append(report)

        return reports

    async def analyze_eml(
        self,
        raw_eml: bytes | str,
        send_alerts: bool = True,
        alert_on_safe: bool = False,
    ) -> List[ComprehensiveScanReport]:
        """
        Parses a full MIME .eml message, extracts forensic headers (SPF, DKIM, DMARC),
        detects display name spoofing, and analyzes all embedded links.
        """
        from app.email_parser import EmailParser

        parsed_email = EmailParser.parse_eml(raw_eml)
        if not parsed_email.targets:
            logger.info(f"[Pipeline] Email '{parsed_email.subject}' contains no extractable URLs.")
            return []

        email_summary = (
            f"Subject: {parsed_email.subject}\n"
            f"From: {parsed_email.sender}\n"
            f"SPF: {parsed_email.spf_status}, DKIM: {parsed_email.dkim_status}, DMARC: {parsed_email.dmarc_status}\n"
            f"Spoofed Display Name Detected: {parsed_email.is_spoofed_display_name}\n"
            f"Attachments: {', '.join(parsed_email.attachments) or 'None'}\n\n"
            f"Body Snippet:\n{parsed_email.body_plain[:500]}"
        )

        reports: List[ComprehensiveScanReport] = []
        for target in parsed_email.targets:
            report = await self.scan_single_target(
                target=target,
                email_context=email_summary,
                email_metadata=parsed_email,
                send_alert=send_alerts,
                alert_on_safe=alert_on_safe,
            )
            reports.append(report)

        return reports
