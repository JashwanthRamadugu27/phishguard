import asyncio
import sys
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.config import get_settings
from app.models import (
    AgentEvaluation,
    ScanStatus,
    ScanTarget,
    ThreatLevel,
    UrlscanResult,
    VTResult,
)
from app.notifier import DiscordNotifier


async def main():
    print("🚀 Initializing live Discord Webhook test...")
    settings = get_settings()
    notifier = DiscordNotifier(settings)

    test_target = ScanTarget(
        raw_url="https://secure-auth.microsoft-verify.support-portal.top/login",
        defanged_url="hxxps://secure-auth[.]microsoft-verify[.]support-portal[.]top/login",
        domain="secure-auth.microsoft-verify.support-portal.top",
    )

    test_vt = VTResult(
        status=ScanStatus.COMPLETED,
        malicious_count=18,
        suspicious_count=4,
        harmless_count=40,
        undetected_count=12,
        engine_scan_summary={"Kaspersky": "malicious", "Sophos": "phishing", "BitDefender": "malware"},
        permalink="https://www.virustotal.com/gui/url/sample_test",
    )

    test_urlscan = UrlscanResult(
        status=ScanStatus.COMPLETED,
        verdict_score=92,
        malicious=True,
        tags=["phishing", "brand-impersonation", "credential-harvester"],
        categories=["phishing"],
        screenshot_url="https://urlscan.io/static/og/urlscan-og.png",
        report_link="https://urlscan.io/result/sample_test/",
        scan_uuid="sample-uuid-1234",
    )

    test_eval = AgentEvaluation(
        threat_level=ThreatLevel.MALICIOUS,
        confidence_score=98,
        reasoning_summary=(
            "Target domain explicitly mimics the Microsoft 365 login portal with credential interception forms. "
            "High confidence malicious classification supported by 18 positive VirusTotal detections and urlscan.io score of 92."
        ),
        recommended_actions=[
            "Block domain `microsoft-verify[.]support-portal[.]top` on DNS firewall",
            "Purge suspicious inbound messages matching this link across mailboxes",
            "Reset credentials for any employee who visited the defanged link",
        ],
        indicators_of_compromise=[
            "microsoft-verify[.]support-portal[.]top",
            "hxxps://secure-auth[.]microsoft-verify[.]support-portal[.]top/login",
        ],
        impersonated_brand="Microsoft 365",
        evaluated_at=datetime.now(timezone.utc),
    )

    print(f"📡 Sending test alert to webhook: {settings.DISCORD_WEBHOOK_URL[:40]}...")
    success = await notifier.send_alert(
        target=test_target,
        vt_result=test_vt,
        urlscan_result=test_urlscan,
        evaluation=test_eval,
    )

    if success:
        print("✅ Success! Check your Discord channel for the Phishing Sentinel alert embed.")
    else:
        print("❌ Failed to send Discord alert. Please check your webhook URL in .env.")


if __name__ == "__main__":
    asyncio.run(main())
