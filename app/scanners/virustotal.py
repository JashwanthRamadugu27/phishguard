"""VirusTotal v3 API scanner client with sliding window rate limiting and exponential backoff."""

import asyncio
import base64
import logging
import random
import time
from typing import Any, Dict, List, Optional
import httpx

from app.config import Settings, get_settings
from app.models import ScanStatus, ScanTarget, VTResult

logger = logging.getLogger(__name__)


class VirusTotalRateLimiter:
    """
    Sliding window rate limiter to strictly respect VirusTotal free tier limits (4 requests / 60 seconds).
    """

    def __init__(self, max_requests: int = 4, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.timestamps: List[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Blocks until a request slot in the sliding window is available."""
        async with self._lock:
            now = time.monotonic()
            # Remove timestamps outside the sliding window
            self.timestamps = [t for t in self.timestamps if now - t < self.window_seconds]

            if len(self.timestamps) >= self.max_requests:
                sleep_time = self.window_seconds - (now - self.timestamps[0]) + 0.1
                if sleep_time > 0:
                    logger.debug(f"[VT RateLimiter] Window full. Throttling for {sleep_time:.2f}s")
                    await asyncio.sleep(sleep_time)
                # Re-clean timestamps after sleeping
                now = time.monotonic()
                self.timestamps = [t for t in self.timestamps if now - t < self.window_seconds]

            self.timestamps.append(time.monotonic())


class VirusTotalScanner:
    """
    Asynchronous client for VirusTotal v3 API.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.settings.VIRUSTOTAL_API_KEY,
            "Accept": "application/json",
        }
        self.rate_limiter = VirusTotalRateLimiter(
            max_requests=self.settings.VIRUSTOTAL_RATE_LIMIT,
            window_seconds=self.settings.VIRUSTOTAL_RATE_LIMIT_PERIOD,
        )

    @staticmethod
    def compute_url_id(url: str) -> str:
        """Computes URL identifier for VT v3 (base64url encoded without padding)."""
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")

    async def scan_url(self, target: ScanTarget) -> VTResult:
        """
        Queries VirusTotal for an existing URL analysis, or submits for scanning if unindexed.
        """
        url_id = self.compute_url_id(target.raw_url)
        endpoint = f"{self.base_url}/urls/{url_id}"

        async with httpx.AsyncClient(timeout=self.settings.VIRUSTOTAL_TIMEOUT) as client:
            # 1. Fetch existing URL report
            response_data = await self._request_with_retry(client, "GET", endpoint, target)

            if response_data is None:
                return VTResult(
                    status=ScanStatus.FAILED,
                    error_message="VirusTotal request failed after max retries or timeout.",
                )

            # If 404 / not found, submit for fresh analysis
            if response_data.get("status_code") == 404:
                logger.info(f"[VirusTotal] URL not previously analyzed: {target.defanged_url}. Submitting...")
                submit_endpoint = f"{self.base_url}/urls"
                submit_res = await self._request_with_retry(
                    client, "POST", submit_endpoint, target, data={"url": target.raw_url}
                )

                if submit_res and submit_res.get("data", {}).get("id"):
                    analysis_id = submit_res["data"]["id"]
                    # Poll analysis briefly
                    return await self._poll_analysis(client, analysis_id, target)
                else:
                    return VTResult(
                        status=ScanStatus.INCONCLUSIVE,
                        error_message="Submitted URL to VirusTotal, but could not retrieve immediate verdict.",
                    )

            # Parse existing report
            return self._parse_url_report(response_data, url_id)

    async def _poll_analysis(self, client: httpx.AsyncClient, analysis_id: str, target: ScanTarget) -> VTResult:
        """Polls analysis status up to 3 times before returning intermediate verdict."""
        endpoint = f"{self.base_url}/analyses/{analysis_id}"
        for _ in range(3):
            await asyncio.sleep(4.0)
            res = await self._request_with_retry(client, "GET", endpoint, target)
            if res and res.get("data", {}).get("attributes", {}).get("status") == "completed":
                stats = res["data"]["attributes"].get("stats", {})
                results = res["data"]["attributes"].get("results", {})
                engine_summary = {
                    engine: info.get("category", "undetected")
                    for engine, info in results.items()
                    if info.get("category") in ("malicious", "suspicious")
                }
                return VTResult(
                    status=ScanStatus.COMPLETED,
                    malicious_count=stats.get("malicious", 0),
                    suspicious_count=stats.get("suspicious", 0),
                    harmless_count=stats.get("harmless", 0),
                    undetected_count=stats.get("undetected", 0),
                    engine_scan_summary=engine_summary,
                    scan_id=analysis_id,
                )

        return VTResult(
            status=ScanStatus.INCONCLUSIVE,
            scan_id=analysis_id,
            error_message="VirusTotal analysis still in progress.",
        )

    def _parse_url_report(self, payload: Dict[str, Any], url_id: str) -> VTResult:
        """Extracts stats and engine detections from VT v3 URL report."""
        try:
            attrs = payload.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            # Summarize positive engine detections
            engine_summary = {}
            for engine_name, engine_data in results.items():
                category = engine_data.get("category", "")
                if category in ("malicious", "suspicious"):
                    engine_summary[engine_name] = {
                        "category": category,
                        "result": engine_data.get("result", ""),
                    }

            permalink = f"https://www.virustotal.com/gui/url/{url_id}"

            return VTResult(
                status=ScanStatus.COMPLETED,
                malicious_count=stats.get("malicious", 0),
                suspicious_count=stats.get("suspicious", 0),
                harmless_count=stats.get("harmless", 0),
                undetected_count=stats.get("undetected", 0),
                engine_scan_summary=engine_summary,
                permalink=permalink,
                scan_id=url_id,
            )
        except Exception as e:
            logger.error(f"[VirusTotal] Failed to parse report: {e}")
            return VTResult(
                status=ScanStatus.FAILED,
                error_message=f"Report parsing error: {str(e)}",
            )

    async def _request_with_retry(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        target: ScanTarget,
        data: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Executes HTTP request respecting rate limits and handling 429 with exponential backoff + jitter.
        """
        for attempt in range(self.settings.MAX_RETRIES + 1):
            await self.rate_limiter.acquire()
            try:
                if method.upper() == "GET":
                    response = await client.get(url, headers=self.headers)
                else:
                    response = await client.post(url, headers=self.headers, data=data)

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 404:
                    return {"status_code": 404}

                if response.status_code == 429:
                    jitter = random.uniform(0.5, 1.5)
                    backoff = (self.settings.RETRY_BACKOFF_FACTOR ** attempt) * 5.0 + jitter
                    logger.warning(
                        f"[VirusTotal] Rate limit (429) encountered for {target.defanged_url}. "
                        f"Backing off for {backoff:.2f}s (attempt {attempt + 1}/{self.settings.MAX_RETRIES})"
                    )
                    await asyncio.sleep(backoff)
                    continue

                logger.warning(f"[VirusTotal] Non-200 status ({response.status_code}) for {target.defanged_url}")
                if attempt == self.settings.MAX_RETRIES:
                    return None

            except (httpx.RequestError, httpx.TimeoutException) as exc:
                logger.warning(
                    f"[VirusTotal] Network error ({exc}) on attempt {attempt + 1} for {target.defanged_url}"
                )
                if attempt == self.settings.MAX_RETRIES:
                    return None
                await asyncio.sleep(2.0 ** attempt)

        return None
