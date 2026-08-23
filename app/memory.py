"""Persistent Memory Management Module for Phishing Sentinel AI Agent.

Adheres strictly to DATABASE_SPEC.md:
- Pure instance logging per link
- Strict binary threat verdict: 'SAFE' or 'MALICIOUS'
- Zero clutter and clean, readable columns
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import Settings, get_settings
from app.models import AgentEvaluation, ParsedEmail, ScanTarget, ThreatLevel, UrlscanResult, VTResult

logger = logging.getLogger(__name__)


class SentinelMemory:
    """
    Persistent state & memory database (SQLite) managing scans and threat campaigns.
    """

    def __init__(self, db_path: Optional[str] = None, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.db_path = db_path or self.settings.MEMORY_DB_PATH
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns SQLite connection with row factory configured."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Creates clean tables and indexes if they do not exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Main Scans Table (Strictly only necessary columns)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    defanged_url TEXT,
                    domain TEXT NOT NULL,
                    verdict TEXT NOT NULL CHECK(verdict IN ('SAFE', 'MALICIOUS')),
                    confidence INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    brand TEXT,
                    email_subject TEXT,
                    email_sender TEXT,
                    email_body_snippet TEXT,
                    spf_status TEXT,
                    dkim_status TEXT,
                    dmarc_status TEXT,
                    is_spoofed_display_name BOOLEAN,
                    attachments TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            # 2. Correlated Threat Campaigns Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    brand TEXT NOT NULL UNIQUE,
                    domains TEXT NOT NULL,
                    attack_count INTEGER DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
            """)

            # 3. Agent Execution Audit Traces
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    step_num INTEGER NOT NULL,
                    step_name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    observation TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)

            # Auto-migrate columns for existing databases
            cursor.execute("PRAGMA table_info(scans)")
            existing_cols = {row["name"] for row in cursor.fetchall()}
            desired_cols = {
                "email_body_snippet": "TEXT",
                "spf_status": "TEXT",
                "dkim_status": "TEXT",
                "dmarc_status": "TEXT",
                "is_spoofed_display_name": "BOOLEAN",
                "attachments": "TEXT",
            }
            for col_name, col_type in desired_cols.items():
                if col_name not in existing_cols:
                    cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")

            # Indexes for fast historical lookups
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans (domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans (verdict)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_url ON scans (url)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_brand ON campaigns (brand)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_traces_scan ON traces (scan_id)")
            conn.commit()

    @staticmethod
    def normalize_verdict(threat_level: ThreatLevel | str) -> str:
        """Normalizes any assessment into strict binary 'SAFE' or 'MALICIOUS'."""
        val = threat_level.value if isinstance(threat_level, ThreatLevel) else str(threat_level).upper()
        if val in ("MALICIOUS", "SUSPICIOUS"):
            return "MALICIOUS"
        return "SAFE"

    def lookup_target_history(self, domain_or_url: str) -> Optional[Dict[str, Any]]:
        """Recalls previous scans for a domain or specific URL from memory."""
        clean_target = domain_or_url.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    id,
                    url,
                    url AS target_url,
                    defanged_url,
                    domain,
                    verdict,
                    verdict AS threat_level,
                    confidence,
                    confidence AS confidence_score,
                    summary,
                    summary AS reasoning_summary,
                    brand,
                    brand AS impersonated_brand,
                    email_subject,
                    email_sender,
                    email_body_snippet,
                    spf_status,
                    dkim_status,
                    dmarc_status,
                    is_spoofed_display_name,
                    attachments,
                    created_at
                FROM scans 
                WHERE domain = ? OR url = ? 
                ORDER BY id DESC LIMIT 1
            """, (clean_target, clean_target))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def is_domain_trusted(self, domain: str) -> Optional[str]:
        """
        Organizational baseline check: verifies if domain is a known legitimate service.
        """
        if not domain:
            return None
        clean_domain = domain.strip().lower()
        
        trusted_map = {
            "Microsoft 365 / Azure": ["microsoft.com", "office.com", "live.com", "outlook.com", "azure.com", "microsoftonline.com"],
            "Google Workspace": ["google.com", "youtube.com", "gmail.com", "googlemail.com"],
            "Apple Services": ["apple.com", "icloud.com", "itunes.com"],
            "PayPal": ["paypal.com", "paypal-communication.com"],
            "GitHub": ["github.com", "githubusercontent.com"],
        }

        for entity, domains in trusted_map.items():
            for d in domains:
                if clean_domain == d or clean_domain.endswith(f".{d}"):
                    return entity
        return None

    def correlate_or_create_campaign(
        self,
        targeted_brand: Optional[str],
        domain: str,
        threat_level: ThreatLevel | str,
    ) -> Optional[Dict[str, Any]]:
        """
        Searches memory for active threat campaigns targeting this brand.
        Increments attack count if recurring, or creates a new campaign entry.
        """
        normalized_verdict = self.normalize_verdict(threat_level)
        if normalized_verdict != "MALICIOUS":
            return None

        brand = targeted_brand or "Generic Credential Harvester"
        now = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM campaigns WHERE brand = ?", (brand,))
            row = cursor.fetchone()

            if row:
                campaign_id = row["id"]
                domains_list: List[str] = json.loads(row["domains"])
                if domain not in domains_list:
                    domains_list.append(domain)

                new_count = row["attack_count"] + 1
                cursor.execute("""
                    UPDATE campaigns
                    SET domains = ?, attack_count = ?, last_seen = ?
                    WHERE id = ?
                """, (json.dumps(domains_list), new_count, now, campaign_id))
                conn.commit()

                return {
                    "campaign_id": campaign_id,
                    "campaign_name": f"Campaign-{brand}",
                    "attack_count": new_count,
                    "is_recurring": True,
                    "associated_domains": domains_list,
                }
            else:
                domains_list = [domain]
                cursor.execute("""
                    INSERT INTO campaigns 
                    (brand, domains, attack_count, first_seen, last_seen)
                    VALUES (?, ?, 1, ?, ?)
                """, (
                    brand,
                    json.dumps(domains_list),
                    now,
                    now,
                ))
                conn.commit()
                campaign_id = cursor.lastrowid

                return {
                    "campaign_id": campaign_id,
                    "campaign_name": f"Campaign-{brand}",
                    "attack_count": 1,
                    "is_recurring": False,
                    "associated_domains": domains_list,
                }

    def record_investigation(
        self,
        target: ScanTarget,
        vt_result: Optional[VTResult] = None,
        urlscan_result: Optional[UrlscanResult] = None,
        evaluation: Optional[AgentEvaluation] = None,
        email_metadata: Optional[ParsedEmail] = None,
        campaign_id: Optional[int] = None,
    ) -> int:
        """
        Saves a single scanned link instance into the 'scans' table.
        """
        now = datetime.now(timezone.utc).isoformat()
        verdict = self.normalize_verdict(evaluation.threat_level if evaluation else ThreatLevel.UNKNOWN)
        confidence = evaluation.confidence_score if evaluation else 50
        summary = evaluation.reasoning_summary if evaluation else "Target analyzed."
        brand = evaluation.impersonated_brand if evaluation else None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scans (
                    url, defanged_url, domain, verdict, confidence, summary, brand,
                    email_subject, email_sender, email_body_snippet, spf_status, dkim_status, dmarc_status, is_spoofed_display_name, attachments, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target.raw_url,
                target.defanged_url,
                target.domain,
                verdict,
                confidence,
                summary,
                brand,
                email_metadata.subject if email_metadata else None,
                email_metadata.sender if email_metadata else None,
                email_metadata.body_plain[:500] if email_metadata else None,
                getattr(email_metadata, 'spf_status', None) if email_metadata else None,
                getattr(email_metadata, 'dkim_status', None) if email_metadata else None,
                getattr(email_metadata, 'dmarc_status', None) if email_metadata else None,
                getattr(email_metadata, 'is_spoofed_display_name', False) if email_metadata else False,
                json.dumps(email_metadata.attachments) if email_metadata and getattr(email_metadata, 'attachments', None) else None,
                now,
            ))
            conn.commit()
            return cursor.lastrowid or 0

    def record_step_trace(
        self,
        investigation_id: int,
        step_number: int,
        step_name: str,
        action_taken: str,
        observation: str,
    ) -> None:
        """Records a step in the agent reasoning execution trace."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO traces (scan_id, step_num, step_name, action, observation, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (investigation_id, step_number, step_name, action_taken, observation, now))
            conn.commit()

    def get_execution_traces(self, investigation_id: int) -> List[Dict[str, Any]]:
        """Retrieves execution traces for a scan instance."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    id,
                    scan_id AS investigation_id,
                    step_num AS step_number,
                    step_name,
                    action AS action_taken,
                    observation,
                    timestamp
                FROM traces 
                WHERE scan_id = ? 
                ORDER BY step_num ASC
            """, (investigation_id,))
            return [dict(r) for r in cursor.fetchall()]

    def get_recent_investigations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves most recent scans for dashboard or audit."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    id,
                    url,
                    url AS target_url,
                    defanged_url,
                    domain,
                    verdict,
                    verdict AS threat_level,
                    confidence,
                    confidence AS confidence_score,
                    summary,
                    summary AS reasoning_summary,
                    brand,
                    brand AS impersonated_brand,
                    email_subject,
                    email_sender,
                    email_body_snippet,
                    spf_status,
                    dkim_status,
                    dmarc_status,
                    is_spoofed_display_name,
                    attachments,
                    created_at
                FROM scans 
                ORDER BY id DESC LIMIT ?
            """, (limit,))
            return [dict(r) for r in cursor.fetchall()]
