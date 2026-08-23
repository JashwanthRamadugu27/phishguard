"""Discord Webhook & Windows OS Toast Alert Notifier."""

import logging
import subprocess
import sys
from typing import Any, Dict, Optional
import httpx

from app.config import Settings, get_settings
from app.models import (
    AgentEvaluation,
    ScanTarget,
    ThreatLevel,
    UrlscanResult,
    VTResult,
)

logger = logging.getLogger(__name__)

# Discord embed color constants
COLOR_MALICIOUS = 0xFF0033  # Red (#FF0033)
COLOR_SUSPICIOUS = 0xFFA500  # Orange (#FFA500)
COLOR_SAFE = 0x00FF66        # Green (#00FF66)
COLOR_UNKNOWN = 0x808080     # Gray (#808080)


def send_windows_toast(title: str, message: str) -> None:
    """Dispatches a native Windows OS desktop toast notification popup."""
    if sys.platform != "win32":
        return

    # Clean special characters for PowerShell XML syntax
    clean_title = title.replace("'", "").replace('"', "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    clean_msg = message.replace("'", "").replace('"', "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    ps_script = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; "
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null; "
        "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument; "
        f"$xml.LoadXml('<toast><visual><binding template=\"ToastGeneric\"><text>{clean_title}</text><text>{clean_msg}</text></binding></visual></toast>'); "
        "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml); "
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('PhishGuard AI').Show($toast);"
    )

    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info(f"[Windows Toast] Dispatched Windows notification: '{clean_title}'")
    except Exception as exc:
        logger.error(f"[Windows Toast] Failed to dispatch Windows notification: {exc}")


class DiscordNotifier:
    """
    Formats and dispatches structured security threat alert embeds to Discord and Windows desktop.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.webhook_url = self.settings.DISCORD_WEBHOOK_URL

    @staticmethod
    def get_color_for_threat(threat_level: ThreatLevel) -> int:
        """Returns Discord integer color corresponding to threat severity."""
        if threat_level == ThreatLevel.MALICIOUS:
            return COLOR_MALICIOUS
        elif threat_level == ThreatLevel.SUSPICIOUS:
            return COLOR_SUSPICIOUS
        elif threat_level == ThreatLevel.SAFE:
            return COLOR_SAFE
        return COLOR_UNKNOWN

    @staticmethod
    def get_emoji_for_threat(threat_level: ThreatLevel) -> str:
        """Returns visual indicator icon for threat level."""
        if threat_level == ThreatLevel.MALICIOUS:
            return "🚨 [MALICIOUS DETECTED]"
        elif threat_level == ThreatLevel.SUSPICIOUS:
            return "⚠️ [SUSPICIOUS ACTIVITY]"
        elif threat_level == ThreatLevel.SAFE:
            return "✅ [BENIGN / SAFE]"
        return "❓ [UNKNOWN STATUS]"

    def build_embed(
        self,
        target: ScanTarget,
        vt_result: VTResult,
        urlscan_result: UrlscanResult,
        evaluation: AgentEvaluation,
        email_metadata: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Builds a comprehensive, defanged Discord embed payload.
        """
        color = self.get_color_for_threat(evaluation.threat_level)
        title = f"{self.get_emoji_for_threat(evaluation.threat_level)} — {target.domain}"

        # Fields list
        fields = [
            {
                "name": "🎯 Target (Defanged)",
                "value": f"`{target.defanged_url}`",
                "inline": False,
            },
        ]

        # Add email metadata if available
        if email_metadata:
            spoof_warning = " ⚠️ (Spoofed Display Name!)" if getattr(email_metadata, "is_spoofed_display_name", False) else ""
            fields.append({
                "name": "📧 Email Forensic Metadata",
                "value": (
                    f"**Subject:** {getattr(email_metadata, 'subject', 'N/A')}\n"
                    f"**From:** `{getattr(email_metadata, 'sender', 'N/A')}`{spoof_warning}\n"
                    f"**SPF:** `{getattr(email_metadata, 'spf_status', 'none').upper()}` | **DKIM:** `{getattr(email_metadata, 'dkim_status', 'none').upper()}`\n"
                    + (f"**Attachments:** `{', '.join(email_metadata.attachments)}`" if getattr(email_metadata, "attachments", None) else "")
                ),
                "inline": False,
            })

        fields.extend([
            {
                "name": "🤖 AI Analyst Verdict",
                "value": (
                    f"**Level:** `{evaluation.threat_level.value}`\n"
                    f"**Confidence:** `{evaluation.confidence_score}%`\n"
                    f"**Brand Impersonated:** `{evaluation.impersonated_brand or 'None'}`"
                ),
                "inline": True,
            },
            {
                "name": "🛡️ VirusTotal Telemetry",
                "value": (
                    f"**Malicious:** `{vt_result.malicious_count}`\n"
                    f"**Suspicious:** `{vt_result.suspicious_count}`\n"
                    f"**Total Engines:** `{vt_result.total_engines}`\n"
                    + (f"[VT Full Report]({vt_result.permalink})" if vt_result.permalink else "No VT link")
                ),
                "inline": True,
            },
            {
                "name": "🔍 urlscan.io Telemetry",
                "value": (
                    f"**Verdict Score:** `{urlscan_result.verdict_score}/100`\n"
                    f"**Tags:** `{', '.join(urlscan_result.tags) or 'None'}`\n"
                    + (f"[urlscan Result]({urlscan_result.report_link})" if urlscan_result.report_link else "No report link")
                ),
                "inline": True,
            },
            {
                "name": "🧠 AI Analysis & Evidence",
                "value": evaluation.reasoning_summary[:1024],
                "inline": False,
            },
        ])

        # Recommended Actions field
        if evaluation.recommended_actions:
            actions_text = "\n".join([f"• {act}" for act in evaluation.recommended_actions[:5]])
            fields.append({
                "name": "⚡ Recommended Remediation",
                "value": actions_text[:1024],
                "inline": False,
            })

        # IOCs field
        if evaluation.indicators_of_compromise:
            iocs_text = "\n".join([f"`{ioc}`" for ioc in evaluation.indicators_of_compromise[:6]])
            fields.append({
                "name": "📌 Indicators of Compromise (IOCs)",
                "value": iocs_text[:1024],
                "inline": False,
            })

        embed: Dict[str, Any] = {
            "title": title,
            "color": color,
            "fields": fields,
            "footer": {
                "text": f"Phishing Sentinel AI Agent • {self.settings.APP_ENV.upper()}",
            },
            "timestamp": evaluation.evaluated_at.isoformat(),
        }

        # Attach urlscan screenshot if available and relevant
        if urlscan_result.screenshot_url and evaluation.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS):
            embed["image"] = {"url": urlscan_result.screenshot_url}

        return embed

    async def send_alert(
        self,
        target: ScanTarget,
        vt_result: VTResult,
        urlscan_result: UrlscanResult,
        evaluation: AgentEvaluation,
        email_metadata: Optional[Any] = None,
    ) -> bool:
        """
        Dispatches alert embed to Discord Webhook and pops native Windows desktop Toast.
        """
        # Always trigger Windows OS Toast popup on Malicious / Suspicious verdict
        if evaluation.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS):
            brand_info = f"Impersonating: {evaluation.impersonated_brand}" if evaluation.impersonated_brand else f"Domain: {target.domain}"
            send_windows_toast(
                title=f"🚨 PhishGuard Alert: {evaluation.threat_level.value}",
                message=f"{brand_info}\nTarget: {target.defanged_url[:60]}"
            )

        embed = self.build_embed(target, vt_result, urlscan_result, evaluation, email_metadata)
        payload = {
            "username": "Phishing Sentinel AI",
            "avatar_url": "https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.svg",
            "embeds": [embed],
        }

        async with httpx.AsyncClient(timeout=self.settings.HTTP_REQUEST_TIMEOUT) as client:
            try:
                response = await client.post(self.webhook_url, json=payload)
                if response.status_code in (200, 204):
                    logger.info(f"[Discord] Alert successfully dispatched for {target.defanged_url}")
                    return True
                else:
                    logger.error(
                        f"[Discord] Webhook returned status {response.status_code}: {response.text}"
                    )
                    return False
            except Exception as exc:
                logger.error(f"[Discord] Failed to send alert: {exc}")
                return False
