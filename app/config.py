"""Configuration management with strict validation for Phishing Sentinel AI Agent."""

import re
from functools import lru_cache
from typing import Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Known placeholder patterns to reject immediately at startup
PLACEHOLDER_PATTERNS = [
    r"^your[-_].*",
    r".*<.+>.*",
    r".*changeme.*",
    r".*placeholder.*",
    r".*api_key_here.*",
    r".*replace_me.*",
    r"^TODO$",
    r"^\.\.\.$",
]


class Settings(BaseSettings):
    """
    Application Settings loaded from environment variables and .env file.
    Enforces strict presence and format validation on credentials and services.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # API Keys & Secrets (Required)
    VIRUSTOTAL_API_KEY: str = Field(
        ...,
        description="API key for VirusTotal v3 API",
    )
    URLSCAN_API_KEY: str = Field(
        ...,
        description="API key for urlscan.io API",
    )
    DISCORD_WEBHOOK_URL: str = Field(
        ...,
        description="Discord Webhook URL for alerting",
    )
    LLM_API_KEY: str = Field(
        ...,
        description="API key for LLM Provider (e.g., Groq API key gsk_...)",
    )
    LLM_MODEL: str = Field(
        default="openai/gpt-oss-20b",
        description="Default LLM model identifier for phishing analysis (e.g. openai/gpt-oss-20b)",
    )
    LLM_BASE_URL: Optional[str] = Field(
        default="https://api.groq.com/openai/v1",
        description="Base URL for LLM provider API (defaults to Groq OpenAI-compatible endpoint)",
    )

    # VirusTotal Free Tier Guardrails
    VIRUSTOTAL_RATE_LIMIT: int = Field(
        default=4,
        ge=1,
        description="Max requests per sliding window for VirusTotal (Free tier is 4/min)",
    )
    VIRUSTOTAL_RATE_LIMIT_PERIOD: float = Field(
        default=60.0,
        gt=0.0,
        description="Sliding window duration in seconds for VirusTotal rate limiter",
    )
    VIRUSTOTAL_TIMEOUT: float = Field(
        default=30.0,
        gt=0.0,
        description="Timeout in seconds for VirusTotal API requests",
    )

    # urlscan.io Guardrails
    URLSCAN_POLL_INTERVAL: float = Field(
        default=5.0,
        gt=0.0,
        description="Polling interval in seconds for urlscan.io submission result checks",
    )
    URLSCAN_TIMEOUT: float = Field(
        default=60.0,
        gt=0.0,
        description="Maximum wait timeout in seconds for urlscan.io scan completion",
    )

    # General HTTP Client & Application Settings
    HTTP_REQUEST_TIMEOUT: float = Field(
        default=15.0,
        gt=0.0,
        description="Default HTTP client timeout in seconds",
    )
    MAX_RETRIES: int = Field(
        default=3,
        ge=0,
        description="Maximum retry attempts on transient network/rate limit failures",
    )
    RETRY_BACKOFF_FACTOR: float = Field(
        default=1.5,
        ge=1.0,
        description="Exponential backoff factor for retries",
    )

    # Optional IMAP Live Mailbox Watcher Configuration
    IMAP_HOST: Optional[str] = Field(
        default=None,
        description="IMAP server hostname (e.g. imap.gmail.com, outlook.office365.com)",
    )
    IMAP_PORT: int = Field(
        default=993,
        description="IMAP port (typically 993 for SSL/TLS)",
    )
    IMAP_USER: Optional[str] = Field(
        default=None,
        description="IMAP username / email address",
    )
    IMAP_PASSWORD: Optional[str] = Field(
        default=None,
        description="IMAP password or App Password",
    )
    IMAP_FOLDER: str = Field(
        default="INBOX",
        description="Mailbox folder to monitor",
    )
    IMAP_POLL_INTERVAL: float = Field(
        default=30.0,
        gt=0.0,
        description="Polling interval in seconds for checking unread emails",
    )
    IMAP_USE_SSL: bool = Field(
        default=True,
        description="Whether to use SSL/TLS for IMAP connection",
    )
    IMAP_MARK_AS_SEEN: bool = Field(
        default=True,
        description="Whether to mark processed emails as read/seen",
    )

    # Memory Management & Persistence
    MEMORY_DB_PATH: str = Field(
        default="sentinel_memory.db",
        description="File path to the SQLite Sentinel Memory database",
    )

    APP_ENV: str = Field(
        default="development",
        description="Execution environment (development, staging, production)",
    )
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging verbosity level",
    )

    @field_validator(
        "VIRUSTOTAL_API_KEY",
        "URLSCAN_API_KEY",
        "LLM_API_KEY",
        "LLM_MODEL",
        mode="after",
    )
    @classmethod
    def validate_non_empty_and_non_placeholder(cls, value: str, info) -> str:
        """Ensure secret credentials are not blank, whitespace-only, or dummy placeholders."""
        trimmed = value.strip()
        if not trimmed:
            raise ValueError(f"'{info.field_name}' must not be empty or blank.")

        for pattern in PLACEHOLDER_PATTERNS:
            if re.match(pattern, trimmed, flags=re.IGNORECASE):
                raise ValueError(
                    f"'{info.field_name}' contains a dummy placeholder value '{trimmed}'. "
                    f"Please provide a valid credential."
                )

        return trimmed

    @field_validator("DISCORD_WEBHOOK_URL", mode="after")
    @classmethod
    def validate_discord_webhook(cls, value: str) -> str:
        """Validate Discord Webhook URL structure and ensure it's not a placeholder."""
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("'DISCORD_WEBHOOK_URL' must not be empty or blank.")

        for pattern in PLACEHOLDER_PATTERNS:
            if re.match(pattern, trimmed, flags=re.IGNORECASE):
                raise ValueError(
                    f"'DISCORD_WEBHOOK_URL' contains a dummy placeholder value '{trimmed}'."
                )

        # Discord webhook URL validation
        if not (trimmed.startswith("https://") or trimmed.startswith("http://")):
            raise ValueError(
                f"'DISCORD_WEBHOOK_URL' must start with http:// or https://, got '{trimmed}'."
            )

        if "discord.com/api/webhooks" not in trimmed and "discordapp.com/api/webhooks" not in trimmed:
            # Allow mock endpoints only in test/dev if explicitly prefixed
            if not (trimmed.startswith("http://localhost") or trimmed.startswith("http://127.0.0.1") or trimmed.startswith("https://mock")):
                raise ValueError(
                    f"'DISCORD_WEBHOOK_URL' must be a valid Discord Webhook URL (https://discord.com/api/webhooks/...)."
                )

        return trimmed


@lru_cache()
def get_settings() -> Settings:
    """Retrieve cached application settings instance."""
    return Settings()
