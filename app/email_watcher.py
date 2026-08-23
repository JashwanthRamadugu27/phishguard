"""Autonomous IMAP Mailbox Watcher for real-time unread email monitoring."""

import asyncio
import email
import imaplib
import logging
from typing import List, Optional

from app.config import Settings, get_settings
from app.email_parser import EmailParser
from app.models import ComprehensiveScanReport, ParsedEmail, ScanTarget
from app.pipeline import PhishingSentinelPipeline

logger = logging.getLogger(__name__)


class IMAPEmailWatcher:
    """
    Monitors an IMAP mailbox for unread messages, extracts forensic email headers and links,
    and dispatches investigations to the Phishing Sentinel pipeline.
    """

    def __init__(self, settings: Optional[Settings] = None, pipeline: Optional[PhishingSentinelPipeline] = None):
        self.settings = settings or get_settings()
        self.pipeline = pipeline or PhishingSentinelPipeline(self.settings)
        self._running = False

    def _connect(self) -> imaplib.IMAP4:
        """Establishes an authenticated connection to the IMAP server."""
        if not self.settings.IMAP_HOST or not self.settings.IMAP_USER or not self.settings.IMAP_PASSWORD:
            raise ValueError(
                "IMAP credentials missing. Please configure IMAP_HOST, IMAP_USER, and IMAP_PASSWORD in .env."
            )

        if self.settings.IMAP_USE_SSL:
            client = imaplib.IMAP4_SSL(self.settings.IMAP_HOST, self.settings.IMAP_PORT)
        else:
            client = imaplib.IMAP4(self.settings.IMAP_HOST, self.settings.IMAP_PORT)

        client.login(self.settings.IMAP_USER, self.settings.IMAP_PASSWORD)
        return client

    async def check_mailbox_once(self) -> List[ComprehensiveScanReport]:
        """
        Performs a single polling cycle: fetches unread messages, analyzes them, and returns reports.
        """
        reports: List[ComprehensiveScanReport] = []

        try:
            # Run blocking IMAP socket operations in executor to preserve async loop
            loop = asyncio.get_running_loop()
            raw_emails = await loop.run_in_executor(None, self._fetch_unread_emails_sync)

            if not raw_emails:
                logger.info("[IMAP Watcher] Polled mailbox — 0 unread (UNSEEN) messages found.")
                return []

            logger.info(f"[IMAP Watcher] 📬 Found {len(raw_emails)} unread email(s) for investigation!")

            for msg_id, raw_bytes in raw_emails:
                try:
                    parsed_email = EmailParser.parse_eml(raw_bytes)
                    logger.info(
                        f"[IMAP Watcher] Analyzing email: '{parsed_email.subject}' from '{parsed_email.sender_address}'"
                    )

                    if not parsed_email.targets:
                        sender_domain = parsed_email.sender_address.split('@')[-1] if '@' in parsed_email.sender_address else "unknown-domain.com"
                        logger.info(f"[IMAP Watcher] Email '{parsed_email.subject}' contains no extractable URLs. Creating fallback target for domain '{sender_domain}'.")
                        parsed_email.targets = [ScanTarget(raw_url=f"https://{sender_domain}")]

                    # Context summary for the AI analyst
                    email_summary = (
                        f"Subject: {parsed_email.subject}\n"
                        f"From: {parsed_email.sender}\n"
                        f"SPF: {parsed_email.spf_status}, DKIM: {parsed_email.dkim_status}, DMARC: {parsed_email.dmarc_status}\n"
                        f"Spoofed Display Name Detected: {parsed_email.is_spoofed_display_name}\n"
                        f"Attachments: {', '.join(parsed_email.attachments) or 'None'}\n\n"
                        f"Body Snippet:\n{parsed_email.body_plain[:500]}"
                    )

                    for target in parsed_email.targets:
                        report = await self.pipeline.scan_single_target(
                            target=target,
                            email_context=email_summary,
                            email_metadata=parsed_email,
                            send_alert=True,
                        )
                        report.email_metadata = parsed_email
                        reports.append(report)

                    # Mark email as read if configured
                    if self.settings.IMAP_MARK_AS_SEEN:
                        await loop.run_in_executor(None, self._mark_as_seen_sync, msg_id)
                except Exception as exc:
                    logger.error(f"[IMAP Watcher] Failed to process email {msg_id}: {exc}", exc_info=True)
                    continue

        except Exception as exc:
            logger.error(f"[IMAP Watcher] Error checking mailbox: {exc}")

        return reports

    def _fetch_unread_emails_sync(self) -> List[tuple]:
        """Synchronous fetch for executor (UNSEEN only)."""
        client = self._connect()
        results = []
        try:
            client.select(self.settings.IMAP_FOLDER)
            status, response = client.search(None, "UNSEEN")

            if status != "OK" or not response or not response[0]:
                return []

            msg_ids = response[0].split()
            for msg_id in msg_ids:
                status, msg_data = client.fetch(msg_id, "(RFC822)")
                if status == "OK" and msg_data:
                    for part in msg_data:
                        if isinstance(part, tuple):
                            results.append((msg_id, part[1]))
            return results
        finally:
            try:
                client.close()
                client.logout()
            except Exception:
                pass

    def _fetch_latest_emails_sync(self, limit: int = 3) -> List[tuple]:
        """Synchronous fetch for executor of the most recent N messages (ALL/SEEN/UNSEEN)."""
        client = self._connect()
        results = []
        try:
            client.select(self.settings.IMAP_FOLDER)
            status, response = client.search(None, "ALL")

            if status != "OK" or not response or not response[0]:
                return []

            all_ids = response[0].split()
            # Pick latest 'limit' messages
            target_ids = all_ids[-limit:] if len(all_ids) > limit else all_ids

            for msg_id in reversed(target_ids):
                status, msg_data = client.fetch(msg_id, "(RFC822)")
                if status == "OK" and msg_data:
                    for part in msg_data:
                        if isinstance(part, tuple):
                            results.append((msg_id, part[1]))
            return results
        finally:
            try:
                client.close()
                client.logout()
            except Exception:
                pass

    async def check_latest_mailbox(self, limit: int = 3) -> List[ComprehensiveScanReport]:
        """Fetches and analyzes the latest N emails from inbox regardless of seen status."""
        reports: List[ComprehensiveScanReport] = []
        try:
            loop = asyncio.get_running_loop()
            raw_emails = await loop.run_in_executor(None, self._fetch_latest_emails_sync, limit)

            if not raw_emails:
                return []

            logger.info(f"[IMAP Watcher] 📬 On-demand scanning {len(raw_emails)} latest email(s)...")

            for msg_id, raw_bytes in raw_emails:
                try:
                    parsed_email = EmailParser.parse_eml(raw_bytes)
                    if not parsed_email.targets:
                        sender_domain = parsed_email.sender_address.split('@')[-1] if '@' in parsed_email.sender_address else "unknown-domain.com"
                        parsed_email.targets = [ScanTarget(raw_url=f"https://{sender_domain}")]

                    email_summary = (
                        f"Subject: {parsed_email.subject}\n"
                        f"From: {parsed_email.sender}\n"
                        f"SPF: {parsed_email.spf_status}, DKIM: {parsed_email.dkim_status}, DMARC: {parsed_email.dmarc_status}\n"
                        f"Spoofed Display Name Detected: {parsed_email.is_spoofed_display_name}\n"
                        f"Attachments: {', '.join(parsed_email.attachments) or 'None'}\n\n"
                        f"Body Snippet:\n{parsed_email.body_plain[:500]}"
                    )

                    for target in parsed_email.targets:
                        report = await self.pipeline.scan_single_target(
                            target=target,
                            email_context=email_summary,
                            email_metadata=parsed_email,
                            send_alert=True,
                        )
                        report.email_metadata = parsed_email
                        reports.append(report)
                except Exception as exc:
                    logger.error(f"[IMAP Watcher] Failed processing latest email {msg_id}: {exc}")
                    continue
        except Exception as exc:
            logger.error(f"[IMAP Watcher] Error in check_latest_mailbox: {exc}")

        return reports

    def _mark_as_seen_sync(self, msg_id: bytes):
        r"""Marks a message as \Seen."""
        client = self._connect()
        try:
            client.select(self.settings.IMAP_FOLDER)
            client.store(msg_id, "+FLAGS", "\\Seen")
        finally:
            try:
                client.close()
                client.logout()
            except Exception:
                pass

    async def start_watching(self):
        """
        Starts the continuous polling background loop.
        """
        self._running = True
        logger.info(
            f"[IMAP Watcher] Monitoring mailbox '{self.settings.IMAP_FOLDER}' on '{self.settings.IMAP_HOST}' "
            f"every {self.settings.IMAP_POLL_INTERVAL}s..."
        )

        while self._running:
            await self.check_mailbox_once()
            await asyncio.sleep(self.settings.IMAP_POLL_INTERVAL)

    def stop_watching(self):
        """Stops the watcher loop."""
        self._running = False
        logger.info("[IMAP Watcher] Watcher loop stopped.")
