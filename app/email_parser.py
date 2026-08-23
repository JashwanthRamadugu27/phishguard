"""Forensic Email (MIME / .eml) Parser for Phishing Sentinel."""

import email
import email.policy
import logging
import re
from email.utils import parseaddr
from typing import List, Optional, Tuple, Union

from app.extractor import LinkExtractor
from app.models import ParsedEmail, ScanTarget

logger = logging.getLogger(__name__)

PROMINENT_BRAND_DOMAINS = {
    "paypal": ["paypal.com", "paypal-communication.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "azure.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com", "itunes.com"],
    "google": ["google.com", "youtube.com", "gmail.com"],
    "amazon": ["amazon.com", "amazonses.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "wellsfargo": ["wellsfargo.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "dropbox": ["dropbox.com", "dropboxmail.com"],
    "docusign": ["docusign.com", "docusign.net"],
}


class EmailParser:
    """
    Parses raw MIME / .eml payloads, extracts forensic headers (SPF, DKIM, DMARC),
    strips body content, detects attachment indicators, and extracts embedded URLs.
    """

    @classmethod
    def parse_eml(cls, raw_content: Union[bytes, str]) -> ParsedEmail:
        """
        Parses raw bytes or string of an RFC-822 / .eml message into a structured ParsedEmail.
        """
        if isinstance(raw_content, str):
            raw_bytes = raw_content.encode("utf-8", errors="replace")
        else:
            raw_bytes = raw_content

        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

        # 1. Extract standard headers
        subject = msg.get("Subject", "[No Subject]")
        sender_raw = msg.get("From", "")
        recipient_raw = msg.get("To", "")
        date_str = msg.get("Date", None)
        message_id = msg.get("Message-ID", None)

        # Parse display name and sender address
        display_name, sender_addr = parseaddr(sender_raw)
        sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

        # 2. Extract Authentication Headers (SPF / DKIM / DMARC)
        spf_status, dkim_status, dmarc_status = cls._extract_auth_results(msg)

        # 3. Detect Display Name Spoofing
        is_spoofed_display_name = cls._check_display_name_spoofing(display_name, sender_domain)

        # 4. Extract Body Parts & Attachments
        body_plain, body_html, attachments = cls._extract_parts(msg)

        # 5. Extract all candidate links
        combined_content = f"{body_plain}\n\n{body_html}"
        targets = LinkExtractor.extract_urls(combined_content)

        return ParsedEmail(
            subject=subject,
            sender=sender_raw,
            sender_address=sender_addr,
            sender_domain=sender_domain,
            recipient=recipient_raw,
            date=str(date_str) if date_str else None,
            message_id=str(message_id) if message_id else None,
            spf_status=spf_status,
            dkim_status=dkim_status,
            dmarc_status=dmarc_status,
            body_plain=body_plain.strip(),
            body_html=body_html.strip(),
            attachments=attachments,
            targets=targets,
            is_spoofed_display_name=is_spoofed_display_name,
        )

    @classmethod
    def _extract_auth_results(cls, msg: email.message.EmailMessage) -> Tuple[str, str, str]:
        """Extracts SPF, DKIM, and DMARC verdicts from Authentication-Results / Received-SPF headers."""
        spf_status = "none"
        dkim_status = "none"
        dmarc_status = "none"

        auth_headers = msg.get_all("Authentication-Results", [])
        received_spf = msg.get_all("Received-SPF", [])

        # Check Authentication-Results
        for header in auth_headers:
            header_lower = str(header).lower()
            if "spf=" in header_lower:
                match = re.search(r"spf=([a-z]+)", header_lower)
                if match:
                    spf_status = match.group(1)
            if "dkim=" in header_lower:
                match = re.search(r"dkim=([a-z]+)", header_lower)
                if match:
                    dkim_status = match.group(1)
            if "dmarc=" in header_lower:
                match = re.search(r"dmarc=([a-z]+)", header_lower)
                if match:
                    dmarc_status = match.group(1)

        # Fallback to Received-SPF if not found
        if spf_status == "none" and received_spf:
            spf_header = str(received_spf[0]).lower()
            first_word = spf_header.split()[0] if spf_header.split() else "none"
            if first_word in ("pass", "fail", "softfail", "neutral", "none"):
                spf_status = first_word

        return spf_status, dkim_status, dmarc_status

    @classmethod
    def _check_display_name_spoofing(cls, display_name: str, sender_domain: str) -> bool:
        """
        Detects if display name claims to be a brand while sender domain does not belong to that brand.
        Example: 'PayPal Security Support' coming from 'support@free-mail-provider.com'
        """
        if not display_name or not sender_domain:
            return False

        name_lower = display_name.lower()
        domain_lower = sender_domain.lower()

        # If display name contains an embedded email address different from sender domain
        if "@" in name_lower:
            match = re.search(r"[\w\.-]+@([\w\.-]+)", name_lower)
            if match and match.group(1).lower() not in domain_lower:
                return True

        # Check for brand mismatch
        for brand, valid_domains in PROMINENT_BRAND_DOMAINS.items():
            if brand in name_lower:
                is_legit = any(
                    domain_lower == vd or domain_lower.endswith(f".{vd}") for vd in valid_domains
                )
                if not is_legit:
                    return True

        return False

    @classmethod
    def _extract_parts(cls, msg: email.message.EmailMessage) -> Tuple[str, str, List[str]]:
        """Walks multipart MIME structure to extract plain text, HTML, and attachment names."""
        body_plain_parts: List[str] = []
        body_html_parts: List[str] = []
        attachments: List[str] = []

        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Check if this part is an attachment
            filename = part.get_filename()
            if filename or "attachment" in content_disposition.lower():
                att_name = filename or "unnamed_attachment"
                attachments.append(att_name)
                continue

            # Extract body
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")

                if content_type == "text/plain":
                    body_plain_parts.append(text)
                elif content_type == "text/html":
                    body_html_parts.append(text)
            except Exception as e:
                logger.debug(f"[EmailParser] Error decoding part {content_type}: {e}")

        return "\n".join(body_plain_parts), "\n".join(body_html_parts), attachments
