"""Autonomous AI Phishing Threat Analyst powered by Groq / LLM."""

import json
import logging
from typing import Any, Dict, Optional
import httpx
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.models import (
    AgentEvaluation,
    ScanStatus,
    ScanTarget,
    ThreatLevel,
    UrlscanResult,
    VTResult,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an elite Tier-3 Cyber Threat Intelligence & Phishing Analysis AI Agent.
Your role is to rigorously evaluate extracted URLs, domain intelligence, VirusTotal v3 engine results, and urlscan.io artifacts to determine whether a target represents a phishing, malware, credential harvesting, or social engineering threat.

EVALUATION GUIDELINES:
1. Examine Domain & URL Structure:
   - Check for brand impersonation, typosquatting, homoglyph / IDN attacks, excessive subdomains, or deceptive login/auth paths.
   - Look for known malicious TLDs or suspicious URL shorteners.
2. Evaluate VirusTotal Intelligence:
   - High positive count (>3) is a strong MALICIOUS indicator.
   - 1-2 detections should be assessed in context with suspicious subdomains/tags.
3. Evaluate urlscan.io Artifacts:
   - Review verdict score, tags (e.g., 'phishing', 'brand-impersonation'), and categorization.
4. Synthesize Threat Level:
   - 'MALICIOUS': Clear evidence of phishing, malware distribution, or credential harvesting.
   - 'SUSPICIOUS': High risk indicators, unindexed freshly registered domains imitating sensitive services, or inconclusive/conflicting scanner signals.
   - 'SAFE': Reputable, verified domains with clean scanner reputations and normal structure.
   - 'UNKNOWN': Completely inaccessible target with no scanner data.

OUTPUT REQUIREMENT:
You MUST respond with a single, valid JSON object matching this exact schema:
{
  "threat_level": "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN",
  "confidence_score": <integer from 0 to 100>,
  "reasoning_summary": "<Concise technical analysis explaining the verdict and evidence>",
  "recommended_actions": ["<Action 1>", "<Action 2>"],
  "indicators_of_compromise": ["<IOC 1 (defanged)>", "<IOC 2>"],
  "impersonated_brand": "<Brand Name or null>"
}
"""


class PhishingAnalystAgent:
    """
    AI Security Analyst that synthesizes multi-source scan telemetry into a structured threat verdict.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.base_url = (self.settings.LLM_BASE_URL or "https://api.groq.com/openai/v1").rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {self.settings.LLM_API_KEY}",
            "Content-Type": "application/json",
        }

    async def evaluate_target(
        self,
        target: ScanTarget,
        vt_result: VTResult,
        urlscan_result: UrlscanResult,
        email_context: Optional[str] = None,
    ) -> AgentEvaluation:
        """
        Synthesizes scanner data and URL context into an AgentEvaluation.
        """
        user_prompt = self._build_user_prompt(target, vt_result, urlscan_result, email_context)

        payload = {
            "model": self.settings.LLM_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
            "max_tokens": 1536,
        }

        endpoint = f"{self.base_url}/chat/completions"

        async with httpx.AsyncClient(timeout=self.settings.HTTP_REQUEST_TIMEOUT) as client:
            try:
                response = await client.post(endpoint, headers=self.headers, json=payload)
                if response.status_code == 200:
                    raw_json = response.json()
                    content = raw_json["choices"][0]["message"]["content"]
                    return self._parse_llm_response(content, target, vt_result, urlscan_result)
                else:
                    logger.error(
                        f"[Agent] LLM API error {response.status_code}: {response.text}"
                    )
                    return self._fallback_evaluation(
                        target, vt_result, urlscan_result, f"LLM API returned HTTP {response.status_code}"
                    )
            except Exception as exc:
                logger.error(f"[Agent] Exception calling LLM API: {exc}")
                return self._fallback_evaluation(
                    target, vt_result, urlscan_result, f"LLM communication error: {str(exc)}"
                )

    def _build_user_prompt(
        self,
        target: ScanTarget,
        vt: VTResult,
        urlscan: UrlscanResult,
        email_context: Optional[str],
    ) -> str:
        """Constructs rich contextual prompt for the LLM."""
        data: Dict[str, Any] = {
            "target": {
                "defanged_url": target.defanged_url,
                "domain": target.domain,
            },
            "virustotal": {
                "status": vt.status.value,
                "malicious_count": vt.malicious_count,
                "suspicious_count": vt.suspicious_count,
                "harmless_count": vt.harmless_count,
                "undetected_count": vt.undetected_count,
                "engine_detections": vt.engine_scan_summary,
                "permalink": vt.permalink,
                "error": vt.error_message,
            },
            "urlscan": {
                "status": urlscan.status.value,
                "verdict_score": urlscan.verdict_score,
                "malicious": urlscan.malicious,
                "tags": urlscan.tags,
                "categories": urlscan.categories,
                "report_link": urlscan.report_link,
                "error": urlscan.error_message,
            },
        }

        if email_context:
            data["email_context"] = email_context

        return (
            "Analyze the following security scan results for the target URL and provide a comprehensive threat evaluation in JSON:\n\n"
            f"```json\n{json.dumps(data, indent=2)}\n```"
        )

    def _parse_llm_response(
        self,
        raw_text: str,
        target: ScanTarget,
        vt: VTResult,
        urlscan: UrlscanResult,
    ) -> AgentEvaluation:
        """Parses and validates LLM JSON response into AgentEvaluation schema."""
        try:
            cleaned_text = raw_text.strip()
            if cleaned_text.startswith("```json"):
                cleaned_text = cleaned_text[7:]
            if cleaned_text.endswith("```"):
                cleaned_text = cleaned_text[:-3]

            parsed = json.loads(cleaned_text.strip())
            return AgentEvaluation.model_validate(parsed)
        except (json.JSONDecodeError, ValidationError) as exc:
            logger.warning(f"[Agent] Failed to parse LLM response into AgentEvaluation: {exc}")
            return self._fallback_evaluation(
                target, vt, urlscan, f"JSON parse error from LLM output: {str(exc)}"
            )

    def _fallback_evaluation(
        self,
        target: ScanTarget,
        vt: VTResult,
        urlscan: UrlscanResult,
        reason: str,
    ) -> AgentEvaluation:
        """
        Deterministic rule-based fallback if LLM inference fails.
        """
        if vt.malicious_count > 0 or urlscan.malicious or urlscan.verdict_score >= 60:
            threat_level = ThreatLevel.MALICIOUS
            confidence = 85
            actions = ["Block domain at gateway", "Purge received emails containing this URL", "Check user access logs"]
        elif vt.suspicious_count > 0 or urlscan.verdict_score >= 30:
            threat_level = ThreatLevel.SUSPICIOUS
            confidence = 60
            actions = ["Monitor outbound connections", "Warn user regarding suspicious domain"]
        elif vt.status == ScanStatus.COMPLETED and vt.harmless_count > 10 and not urlscan.malicious:
            threat_level = ThreatLevel.SAFE
            confidence = 80
            actions = ["No immediate action required"]
        else:
            threat_level = ThreatLevel.UNKNOWN
            confidence = 40
            actions = ["Perform manual triage and sandbox review"]

        return AgentEvaluation(
            threat_level=threat_level,
            confidence_score=confidence,
            reasoning_summary=(
                f"Automated fallback assessment triggered ({reason}). "
                f"VirusTotal positives: {vt.malicious_count}, urlscan score: {urlscan.verdict_score}."
            ),
            recommended_actions=actions,
            indicators_of_compromise=[target.defanged_url, target.domain],
        )
