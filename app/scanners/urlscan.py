"""urlscan.io API scanner client with polling and fail-safe timeout handling."""

import asyncio
import logging
import time
from typing import Any, Dict, Optional
import httpx

from app.config import Settings, get_settings
from app.models import ScanStatus, ScanTarget, UrlscanResult

logger = logging.getLogger(__name__)


class UrlscanScanner:
    """
    Asynchronous client for urlscan.io automated submission and result retrieval.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.base_url = "https://urlscan.io/api/v1"
        self.headers = {
            "API-Key": self.settings.URLSCAN_API_KEY,
            "Content-Type": "application/json",
        }

    async def scan_url(self, target: ScanTarget) -> UrlscanResult:
        """
        Submits target URL to urlscan.io and polls for completed verdict and screenshots.
        """
        async with httpx.AsyncClient(timeout=self.settings.HTTP_REQUEST_TIMEOUT) as client:
            # 1. Submit scan request
            submission_data = await self._submit_url(client, target)
            if not submission_data:
                return UrlscanResult(
                    status=ScanStatus.FAILED,
                    error_message="Failed to submit URL to urlscan.io.",
                )

            uuid = submission_data.get("uuid")
            if not uuid:
                return UrlscanResult(
                    status=ScanStatus.FAILED,
                    error_message=submission_data.get("message", "Missing scan UUID from urlscan submission."),
                )

            report_link = submission_data.get("result", f"https://urlscan.io/result/{uuid}/")

            # 2. Poll for results
            return await self._poll_result(client, uuid, report_link, target)

    async def _submit_url(self, client: httpx.AsyncClient, target: ScanTarget) -> Optional[Dict[str, Any]]:
        """Submits target URL to urlscan.io scan endpoint."""
        submit_endpoint = f"{self.base_url}/scan/"
        payload = {
            "url": target.raw_url,
            "visibility": "unlisted",
            "tags": ["phishing-sentinel", "automated-scan"],
        }

        try:
            response = await client.post(submit_endpoint, headers=self.headers, json=payload)
            if response.status_code in (200, 201):
                return response.json()
            elif response.status_code == 429:
                logger.warning(f"[urlscan] Rate limit exceeded on submission for {target.defanged_url}")
                return {"message": "urlscan rate limit exceeded"}
            else:
                logger.warning(f"[urlscan] Submission failed ({response.status_code}): {response.text}")
                return {"message": f"HTTP {response.status_code}: {response.text}"}
        except Exception as exc:
            logger.error(f"[urlscan] Error submitting {target.defanged_url}: {exc}")
            return None

    async def _poll_result(
        self,
        client: httpx.AsyncClient,
        uuid: str,
        report_link: str,
        target: ScanTarget,
    ) -> UrlscanResult:
        """
        Polls urlscan.io result API until completed or maximum timeout reached.
        """
        result_endpoint = f"{self.base_url}/result/{uuid}/"
        start_time = time.monotonic()
        poll_interval = self.settings.URLSCAN_POLL_INTERVAL
        timeout = self.settings.URLSCAN_TIMEOUT

        screenshot_url = f"https://urlscan.io/screenshots/{uuid}.png"

        while time.monotonic() - start_time < timeout:
            await asyncio.sleep(poll_interval)

            try:
                response = await client.get(result_endpoint, headers={"API-Key": self.settings.URLSCAN_API_KEY})
                
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_result(data, uuid, report_link, screenshot_url)

                elif response.status_code in (404, 410):
                    # Scan still in queue or processing
                    logger.debug(f"[urlscan] Polling {uuid} (still processing)...")
                    continue
                elif response.status_code == 429:
                    logger.warning("[urlscan] Polling rate limit encountered, backing off...")
                    await asyncio.sleep(poll_interval * 2)
                else:
                    logger.warning(f"[urlscan] Polling unexpected status {response.status_code} for {uuid}")

            except httpx.RequestError as exc:
                logger.warning(f"[urlscan] Polling network error for {uuid}: {exc}")

        # If timeout reached before result returned
        logger.warning(f"[urlscan] Scan timed out after {timeout}s for {target.defanged_url} (UUID: {uuid})")
        return UrlscanResult(
            status=ScanStatus.INCONCLUSIVE,
            scan_uuid=uuid,
            report_link=report_link,
            screenshot_url=screenshot_url,
            error_message=f"Scan timed out after {timeout}s while waiting for urlscan processing.",
        )

    def _parse_result(
        self,
        data: Dict[str, Any],
        uuid: str,
        report_link: str,
        screenshot_url: str,
    ) -> UrlscanResult:
        """Parses finished urlscan.io JSON payload."""
        try:
            verdicts = data.get("verdicts", {})
            overall = verdicts.get("overall", {})
            urlscan_verdict = verdicts.get("urlscan", {})
            engines = verdicts.get("engines", {})

            score = overall.get("score", urlscan_verdict.get("score", 0))
            is_malicious = overall.get("malicious", urlscan_verdict.get("malicious", False))
            
            # Combine tags and categories
            tags = list(set(overall.get("tags", []) + urlscan_verdict.get("tags", [])))
            categories = list(set(overall.get("categories", []) + urlscan_verdict.get("categories", [])))

            # If score >= 60 or engines detected malice, set malicious flag
            if score >= 60 or engines.get("maliciousTotal", 0) > 0:
                is_malicious = True

            return UrlscanResult(
                status=ScanStatus.COMPLETED,
                verdict_score=min(max(int(score), 0), 100),
                malicious=is_malicious,
                tags=tags,
                categories=categories,
                screenshot_url=screenshot_url,
                report_link=report_link,
                scan_uuid=uuid,
            )
        except Exception as exc:
            logger.error(f"[urlscan] Failed to parse result payload: {exc}")
            return UrlscanResult(
                status=ScanStatus.FAILED,
                scan_uuid=uuid,
                report_link=report_link,
                error_message=f"Parsing error: {str(exc)}",
            )
