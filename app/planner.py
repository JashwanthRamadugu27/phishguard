"""Autonomous Multi-Step Investigation Planner & Reasoning Engine."""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from app.agent import PhishingAnalystAgent
from app.config import Settings, get_settings
from app.memory import SentinelMemory
from app.models import (
    AgentEvaluation,
    ComprehensiveScanReport,
    ParsedEmail,
    ScanStatus,
    ScanTarget,
    ThreatLevel,
    UrlscanResult,
    VTResult,
)
from app.notifier import DiscordNotifier
from app.scanners.urlscan import UrlscanScanner
from app.scanners.virustotal import VirusTotalScanner

logger = logging.getLogger(__name__)


class InvestigationPlanner:
    """
    Autonomous multi-step agent that plans and executes deep security investigations.
    
    Phases executed:
    1. RECALL: Memory check & organizational baseline verification.
    2. GATHER: Multi-source external threat intelligence scanning (VirusTotal, urlscan).
    3. REASON: LLM threat synthesis incorporating memory and forensic context.
    4. CORRELATE: Threat campaign clustering and memory persistence.
    5. DISPATCH: Actionable alert execution and Discord notification.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        memory: Optional[SentinelMemory] = None,
    ):
        self.settings = settings or get_settings()
        self.memory = memory or SentinelMemory(settings=self.settings)
        self.vt_scanner = VirusTotalScanner(self.settings)
        self.urlscan_scanner = UrlscanScanner(self.settings)
        self.agent = PhishingAnalystAgent(self.settings)
        self.notifier = DiscordNotifier(self.settings)

    async def execute_investigation(
        self,
        target: ScanTarget,
        email_metadata: Optional[ParsedEmail] = None,
        email_context: Optional[str] = None,
        send_alert: bool = True,
        alert_on_safe: bool = False,
    ) -> ComprehensiveScanReport:
        """
        Executes a planned 5-step autonomous investigation workflow.
        """
        logger.info(f"[Planner] 🎯 Initiating 5-step investigation plan for: {target.defanged_url}")
        step_traces: List[Dict[str, Any]] = []

        # ====================================================================
        # Step 1: Memory Recall & Organizational Trust Profile Check
        # ====================================================================
        trusted_entity = self.memory.is_domain_trusted(target.domain)
        past_scan = self.memory.lookup_target_history(target.domain)

        step_1_obs = (
            f"Trusted Baseline: {'Verified (' + trusted_entity + ')' if trusted_entity else 'Untrusted / Unknown'}. "
            f"Memory Recall: {'Found previous investigation (Threat=' + past_scan.get('threat_level', 'N/A') + ')' if past_scan else 'No prior history in memory'}."
        )
        logger.info(f"[Planner Step 1/5] Memory Check: {step_1_obs}")
        step_traces.append({
            "step_num": 1,
            "name": "MEMORY_RECALL_AND_BASELINE_CHECK",
            "action": f"Queried sentinel_memory.db for domain '{target.domain}'",
            "observation": step_1_obs,
        })

        # ====================================================================
        # Step 2: Multi-Source Threat Intelligence Gathering
        # ====================================================================
        logger.info(f"[Planner Step 2/5] Gathering external threat telemetry (VirusTotal & urlscan)...")
        vt_task = asyncio.create_task(self.vt_scanner.scan_url(target))
        urlscan_task = asyncio.create_task(self.urlscan_scanner.scan_url(target))

        vt_res_raw, urlscan_res_raw = await asyncio.gather(vt_task, urlscan_task, return_exceptions=True)

        vt_result = (
            VTResult(status=ScanStatus.FAILED, error_message=str(vt_res_raw))
            if isinstance(vt_res_raw, Exception)
            else vt_res_raw
        )
        urlscan_result = (
            UrlscanResult(status=ScanStatus.FAILED, error_message=str(urlscan_res_raw))
            if isinstance(urlscan_res_raw, Exception)
            else urlscan_res_raw
        )

        step_2_obs = (
            f"VirusTotal: {vt_result.malicious_count} malicious detections across {vt_result.total_engines} engines. "
            f"urlscan.io: Score {urlscan_result.verdict_score}/100, Malicious={urlscan_result.malicious}, Tags={urlscan_result.tags}."
        )
        logger.info(f"[Planner Step 2/5] Telemetry Collected: {step_2_obs}")
        step_traces.append({
            "step_num": 2,
            "name": "GATHER_THREAT_INTELLIGENCE",
            "action": "Queried VirusTotal v3 and urlscan.io APIs concurrently",
            "observation": step_2_obs,
        })

        # ====================================================================
        # Step 3: AI Threat Synthesis with Memory & Forensics
        # ====================================================================
        logger.info(f"[Planner Step 3/5] Synthesizing verdict with AI Analyst...")
        
        # Build enriched context for LLM
        if email_context is not None:
            enriched_context = email_context
        else:
            enriched_context = ""
            if email_metadata:
                enriched_context += (
                    f"Email Subject: {email_metadata.subject}\n"
                    f"Sender: {email_metadata.sender}\n"
                    f"SPF: {email_metadata.spf_status}, DKIM: {email_metadata.dkim_status}\n"
                    f"Spoofed Display Name: {email_metadata.is_spoofed_display_name}\n"
                    f"Attachments: {', '.join(email_metadata.attachments) or 'None'}\n"
                )
            if trusted_entity:
                enriched_context += f"Organizational Baseline: Domain belongs to verified entity '{trusted_entity}'.\n"
            if past_scan:
                enriched_context += f"Historical Memory: Previously scanned on {past_scan.get('created_at')} and judged {past_scan.get('threat_level')}.\n"

        evaluation = await self.agent.evaluate_target(
            target=target,
            vt_result=vt_result,
            urlscan_result=urlscan_result,
            email_context=enriched_context or None,
        )

        step_3_obs = (
            f"Verdict: {evaluation.threat_level.value} (Confidence: {evaluation.confidence_score}%). "
            f"Brand: {evaluation.impersonated_brand or 'None'}. Rationale: {evaluation.reasoning_summary[:120]}..."
        )
        logger.info(f"[Planner Step 3/5] AI Evaluation Complete: {step_3_obs}")
        step_traces.append({
            "step_num": 3,
            "name": "REASON_AND_EVALUATE",
            "action": f"Executed Groq LLM threat analysis ({self.settings.LLM_MODEL})",
            "observation": step_3_obs,
        })

        # ====================================================================
        # Step 4: Threat Campaign Correlation & Memory Persistence
        # ====================================================================
        logger.info(f"[Planner Step 4/5] Correlating threat campaign & persisting memory...")
        campaign_info = self.memory.correlate_or_create_campaign(
            targeted_brand=evaluation.impersonated_brand,
            domain=target.domain,
            threat_level=evaluation.threat_level,
        )

        campaign_id = campaign_info["campaign_id"] if campaign_info else None
        investigation_id = self.memory.record_investigation(
            target=target,
            vt_result=vt_result,
            urlscan_result=urlscan_result,
            evaluation=evaluation,
            email_metadata=email_metadata,
            campaign_id=campaign_id,
        )

        # Persist step execution traces into memory
        step_4_obs = (
            f"Investigation #{investigation_id} saved to sentinel_memory.db. "
            + (f"Correlated to {campaign_info['campaign_name']} (Attack #{campaign_info['attack_count']})." if campaign_info else "No campaign correlation needed.")
        )
        step_traces.append({
            "step_num": 4,
            "name": "PERSIST_AND_CORRELATE_CAMPAIGN",
            "action": "Saved investigation record and updated threat campaign cluster in memory",
            "observation": step_4_obs,
        })

        for trace in step_traces:
            self.memory.record_step_trace(
                investigation_id=investigation_id,
                step_number=trace["step_num"],
                step_name=trace["name"],
                action_taken=trace["action"],
                observation=trace["observation"],
            )

        # ====================================================================
        # Step 5: Action Dispatch & Notification
        # ====================================================================
        should_alert = send_alert and (
            alert_on_safe or evaluation.threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS)
        )

        if should_alert:
            logger.info(f"[Planner Step 5/5] Dispatching rich Discord alert embed...")
            await self.notifier.send_alert(
                target=target,
                vt_result=vt_result,
                urlscan_result=urlscan_result,
                evaluation=evaluation,
                email_metadata=email_metadata,
            )
            step_5_obs = "Discord webhook alert dispatched successfully."
        else:
            step_5_obs = "Alert suppressed (Target evaluated as SAFE and alert_on_safe=False)."

        self.memory.record_step_trace(
            investigation_id=investigation_id,
            step_number=5,
            step_name="DISPATCH_REMEDIATION_ALERT",
            action_taken="Executed automated response and Discord alert policy",
            observation=step_5_obs,
        )

        logger.info(f"[Planner] ✅ 5-step investigation finished for {target.defanged_url} (ID: {investigation_id})")

        return ComprehensiveScanReport(
            target=target,
            virustotal=vt_result,
            urlscan=urlscan_result,
            evaluation=evaluation,
            email_metadata=email_metadata,
        )
