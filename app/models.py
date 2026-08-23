"""Core data models and schemas for Phishing Sentinel AI Agent."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.defang import defang_url, extract_domain


class ScanStatus(str, Enum):
    """Execution status for security scanning and analysis tasks."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ThreatLevel(str, Enum):
    """Standard threat assessment classification levels."""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class ScanTarget(BaseModel):
    """
    Represents a scanned URL target with defanged representation and normalized domain.
    """
    model_config = ConfigDict(frozen=True, str_strip_whitespace=True)

    raw_url: str = Field(
        ...,
        min_length=1,
        description="Raw URL or target string extracted from source email/message",
    )
    defanged_url: str = Field(
        default="",
        description="Defanged, non-clickable safe representation (e.g. hxxps://evil[.]com/login)",
    )
    domain: str = Field(
        default="",
        description="Extracted and normalized domain / hostname",
    )
    extracted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when target was parsed",
    )

    @model_validator(mode="before")
    @classmethod
    def populate_defanged_and_domain(cls, data: Any) -> Any:
        """Automatically computes defanged_url and domain if not provided."""
        if isinstance(data, dict):
            raw = (data.get("raw_url") or "").strip()
            if raw:
                if not data.get("defanged_url"):
                    data["defanged_url"] = defang_url(raw)
                if not data.get("domain"):
                    data["domain"] = extract_domain(raw)
        return data

    @model_validator(mode="after")
    def validate_target(self) -> "ScanTarget":
        """Ensure raw_url is valid and domain was successfully extracted."""
        if not self.raw_url.strip():
            raise ValueError("raw_url cannot be empty or whitespace.")
        if not self.domain:
            raise ValueError(f"Could not extract a valid domain from target: '{self.raw_url}'")
        return self


class VTResult(BaseModel):
    """
    Structured scan results from the VirusTotal v3 URL analysis endpoint.
    """
    model_config = ConfigDict(extra="ignore")

    status: ScanStatus = Field(
        default=ScanStatus.COMPLETED,
        description="VirusTotal scan status",
    )
    malicious_count: int = Field(
        default=0,
        ge=0,
        description="Number of engines reporting malicious",
    )
    suspicious_count: int = Field(
        default=0,
        ge=0,
        description="Number of engines reporting suspicious",
    )
    harmless_count: int = Field(
        default=0,
        ge=0,
        description="Number of engines reporting harmless",
    )
    undetected_count: int = Field(
        default=0,
        ge=0,
        description="Number of engines with undetected/no-verdict result",
    )
    engine_scan_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Summary of individual engine detections (e.g. {'Kaspersky': 'malicious'})",
    )
    permalink: Optional[str] = Field(
        default=None,
        description="VirusTotal GUI report link",
    )
    scan_id: Optional[str] = Field(
        default=None,
        description="VirusTotal analysis ID",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error details if scan failed or timed out",
    )

    @property
    def total_engines(self) -> int:
        """Total number of participating antivirus/URL engines."""
        return self.malicious_count + self.suspicious_count + self.harmless_count + self.undetected_count

    @property
    def is_malicious(self) -> bool:
        """Quick boolean flag indicating positive threat detection from VT."""
        return self.malicious_count > 0 or self.suspicious_count >= 2


class UrlscanResult(BaseModel):
    """
    Structured submission and analysis results from the urlscan.io API.
    """
    model_config = ConfigDict(extra="ignore")

    status: ScanStatus = Field(
        default=ScanStatus.COMPLETED,
        description="urlscan.io scan status",
    )
    verdict_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="urlscan overall verdict score (0-100)",
    )
    malicious: bool = Field(
        default=False,
        description="Whether urlscan classified the URL as malicious",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags detected by urlscan (e.g. ['phishing', 'brand-impersonation'])",
    )
    categories: List[str] = Field(
        default_factory=list,
        description="Categorization labels assigned to the URL",
    )
    screenshot_url: Optional[str] = Field(
        default=None,
        description="Direct link to page screenshot artifact",
    )
    report_link: Optional[str] = Field(
        default=None,
        description="Direct link to full urlscan.io interactive report",
    )
    scan_uuid: Optional[str] = Field(
        default=None,
        description="Unique scan UUID from urlscan.io submission",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error details if urlscan failed or timed out",
    )


class AgentEvaluation(BaseModel):
    """
    Synthesized threat evaluation produced by the AI Agent Analyst.
    """
    model_config = ConfigDict(extra="ignore")

    threat_level: ThreatLevel = Field(
        ...,
        description="Consolidated threat level classification (SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN)",
    )
    confidence_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="AI confidence percentage in the assessment (0-100)",
    )
    reasoning_summary: str = Field(
        ...,
        min_length=5,
        description="Technical synthesis and evidence-backed rationale for the verdict",
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Prescriptive remediation actions (e.g. Block domain, Purge mailbox, Reset credentials)",
    )
    indicators_of_compromise: List[str] = Field(
        default_factory=list,
        description="List of detected IOCs (IPs, domains, hashes, suspicious header patterns)",
    )
    impersonated_brand: Optional[str] = Field(
        default=None,
        description="Targeted brand or entity if spoofing/phishing detected",
    )
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when evaluation was generated",
    )


class ParsedEmail(BaseModel):
    """
    Structured forensic representation of an extracted email message.
    """
    model_config = ConfigDict(extra="ignore")

    subject: str = Field(default="[No Subject]", description="Email subject line")
    sender: str = Field(default="", description="Raw From header (e.g., 'PayPal Support <support@paypal.com>')")
    sender_address: str = Field(default="", description="Parsed email address from From header")
    sender_domain: str = Field(default="", description="Domain part of the sender email address")
    recipient: str = Field(default="", description="Raw To header")
    date: Optional[str] = Field(default=None, description="Email Date header")
    message_id: Optional[str] = Field(default=None, description="Message-ID header")
    spf_status: str = Field(default="none", description="Extracted SPF authentication result (pass, fail, softfail, neutral, none)")
    dkim_status: str = Field(default="none", description="Extracted DKIM authentication result")
    dmarc_status: str = Field(default="none", description="Extracted DMARC authentication result")
    body_plain: str = Field(default="", description="Plain text body content")
    body_html: str = Field(default="", description="HTML body content")
    attachments: List[str] = Field(default_factory=list, description="List of detected attachment filenames")
    targets: List[ScanTarget] = Field(default_factory=list, description="Extracted URL targets")
    is_spoofed_display_name: bool = Field(default=False, description="Flag indicating display name spoofing detected")


class ComprehensiveScanReport(BaseModel):
    """
    Consolidated investigation payload containing target metadata, raw scan results, and AI evaluation.
    """
    model_config = ConfigDict(extra="ignore")

    target: ScanTarget
    virustotal: VTResult
    urlscan: UrlscanResult
    evaluation: Optional[AgentEvaluation] = None
    email_metadata: Optional[ParsedEmail] = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when investigation started",
    )
