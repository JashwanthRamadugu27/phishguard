"""Phishing Sentinel AI Agent - CLI & Execution Entry Point."""

import argparse
import asyncio
import logging
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from app.config import get_settings
from app.defang import defang_url
from app.models import ThreatLevel
from app.pipeline import PhishingSentinelPipeline

# Configure logging format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phishing-sentinel")


async def run_pipeline(content: str | bytes, is_url_only: bool = False, is_eml: bool = False, force_alert: bool = False):
    settings = get_settings()
    pipeline = PhishingSentinelPipeline(settings)

    print("\n" + "=" * 70)
    print("🛡️  PHISHING SENTINEL AI AGENT - INVESTIGATION START")
    print("=" * 70)

    if is_url_only:
        from app.models import ScanTarget
        target = ScanTarget(raw_url=str(content).strip())
        report = await pipeline.scan_single_target(
            target=target,
            send_alert=True,
            alert_on_safe=force_alert,
        )
        reports = [report]
    elif is_eml:
        reports = await pipeline.analyze_eml(
            raw_eml=content,
            send_alerts=True,
            alert_on_safe=force_alert,
        )
    else:
        reports = await pipeline.analyze_email_content(
            content=str(content),
            send_alerts=True,
            alert_on_safe=force_alert,
        )

    if not reports:
        print("⚠️  No extractable URL targets found in provided input.")
        return

    for idx, r in enumerate(reports, 1):
        eval_res = r.evaluation
        print(f"\n[{idx}/{len(reports)}] Target: {r.target.defanged_url}")
        print(f"     Domain:      {r.target.domain}")
        if r.email_metadata:
            print(f"     Subject:     {r.email_metadata.subject}")
            print(f"     Sender:      {r.email_metadata.sender}")
            print(f"     SPF/DKIM:    SPF={r.email_metadata.spf_status.upper()}, DKIM={r.email_metadata.dkim_status.upper()}")
            if r.email_metadata.is_spoofed_display_name:
                print("     Spoof Alert: ⚠️ Display Name Spoofing Detected!")
        print(f"     VirusTotal:  Malicious={r.virustotal.malicious_count}, Suspicious={r.virustotal.suspicious_count} (Total={r.virustotal.total_engines})")
        print(f"     urlscan.io:  Score={r.urlscan.verdict_score}/100, Malicious={r.urlscan.malicious}, Tags={r.urlscan.tags}")
        if eval_res:
            icon = "🚨" if eval_res.threat_level == ThreatLevel.MALICIOUS else ("⚠️" if eval_res.threat_level == ThreatLevel.SUSPICIOUS else "✅")
            print(f"     AI Verdict:  {icon} {eval_res.threat_level.value} (Confidence: {eval_res.confidence_score}%)")
            print(f"     Brand:       {eval_res.impersonated_brand or 'None'}")
            print(f"     Reasoning:   {eval_res.reasoning_summary}")
            if eval_res.recommended_actions:
                print("     Actions:")
                for act in eval_res.recommended_actions:
                    print(f"       • {act}")

    print("\n" + "=" * 70)
    print("✅  INVESTIGATION COMPLETE")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Autonomous Phishing Sentinel AI Agent")
    parser.add_argument("--url", type=str, help="Single URL to scan and evaluate")
    parser.add_argument("--email", type=str, help="Email text or body content containing links to analyze")
    parser.add_argument("--file", type=str, help="Path to email (.eml / .txt) file to analyze")
    parser.add_argument("--watch", action="store_true", help="Start continuous IMAP mailbox watcher loop")
    parser.add_argument("--alert-all", action="store_true", help="Send Discord alert even if evaluated as SAFE")

    args = parser.parse_args()

    if args.watch:
        from app.email_watcher import IMAPEmailWatcher
        watcher = IMAPEmailWatcher()
        try:
            asyncio.run(watcher.start_watching())
        except KeyboardInterrupt:
            watcher.stop_watching()
            print("\n👋 IMAP watcher stopped by user.")
    elif args.url:
        asyncio.run(run_pipeline(args.url, is_url_only=True, force_alert=args.alert_all))
    elif args.email:
        asyncio.run(run_pipeline(args.email, is_url_only=False, force_alert=args.alert_all))
    elif args.file:
        try:
            is_eml = args.file.lower().endswith(".eml")
            with open(args.file, "rb") as f:
                content = f.read()
            asyncio.run(run_pipeline(content, is_url_only=False, is_eml=is_eml, force_alert=args.alert_all))
        except Exception as e:
            print(f"❌ Failed to read file: {e}")
            sys.exit(1)
    else:
        # Default interactive demo run
        sample_email = """
        Subject: Urgent Notice: Your Microsoft 365 Account is Suspended
        From: security-notice@msft-update-auth.com
        
        Dear User,
        Your account access has expired. Please verify your credentials immediately:
        https://login.microsoftonline.msft-update-auth.top/auth/verify?session=928347
        
        Thank you,
        Microsoft Security Team
        """
        print("💡 No arguments provided. Running demonstration scan with sample phishing email...\n")
        asyncio.run(run_pipeline(sample_email, is_url_only=False, force_alert=True))


if __name__ == "__main__":
    main()
