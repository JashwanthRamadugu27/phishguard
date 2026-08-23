"""Unit tests for Settings configuration and core Pydantic data models."""

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.defang import defang_url, extract_domain
from app.models import (
    AgentEvaluation,
    ScanStatus,
    ScanTarget,
    ThreatLevel,
    UrlscanResult,
    VTResult,
)


# ============================================================================
# Defanging & URL Sanitization Tests
# ============================================================================

class TestDefangingUtilities:
    def test_defang_http_url(self):
        url = "http://malicious-domain.com/login"
        defanged = defang_url(url)
        assert defanged == "hxxp://malicious-domain[.]com/login"

    def test_defang_https_url(self):
        url = "https://secure-update.phish.org/path?token=123"
        defanged = defang_url(url)
        assert defanged == "hxxps://secure-update[.]phish[.]org/path?token=123"

    def test_defang_subdomain_and_port(self):
        url = "https://sub.evil.corp.co.uk:8443/auth/reset"
        defanged = defang_url(url)
        assert defanged == "hxxps://sub[.]evil[.]corp[.]co[.]uk:8443/auth/reset"

    def test_defang_ip_address(self):
        url = "http://192.168.1.100:8080/payload.exe"
        defanged = defang_url(url)
        assert defanged == "hxxp://192[.]168[.]1[.]100:8080/payload.exe"

    def test_defang_raw_domain(self):
        domain = "phishing-bank.com"
        defanged = defang_url(domain)
        assert defanged == "phishing-bank[.]com"

    def test_extract_domain(self):
        assert extract_domain("https://accounts.google.com/signin") == "accounts.google.com"
        assert extract_domain("http://evil-site.xyz:8080/test") == "evil-site.xyz"
        assert extract_domain("somedomain.org/path") == "somedomain.org"
        assert extract_domain("") == ""


# ============================================================================
# Configuration & Settings Tests
# ============================================================================

class TestSettings:
    @pytest.fixture
    def valid_env_dict(self):
        return {
            "VIRUSTOTAL_API_KEY": "vt_valid_api_key_secret_1234567890",
            "URLSCAN_API_KEY": "urlscan_valid_api_key_secret_1234567890",
            "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/1234567890/valid_token_xyz",
            "LLM_API_KEY": "llm_valid_api_key_secret_1234567890",
            "LLM_MODEL": "gemini-2.0-flash",
        }

    def test_settings_loads_successfully(self, valid_env_dict):
        settings = Settings(**valid_env_dict)
        assert settings.VIRUSTOTAL_API_KEY == "vt_valid_api_key_secret_1234567890"
        assert settings.URLSCAN_API_KEY == "urlscan_valid_api_key_secret_1234567890"
        assert settings.DISCORD_WEBHOOK_URL == "https://discord.com/api/webhooks/1234567890/valid_token_xyz"
        assert settings.LLM_API_KEY == "llm_valid_api_key_secret_1234567890"
        assert settings.LLM_MODEL == "gemini-2.0-flash"
        
        # Verify guardrail defaults
        assert settings.VIRUSTOTAL_RATE_LIMIT == 4
        assert settings.VIRUSTOTAL_RATE_LIMIT_PERIOD == 60.0
        assert settings.VIRUSTOTAL_TIMEOUT == 30.0
        assert settings.URLSCAN_POLL_INTERVAL == 5.0
        assert settings.URLSCAN_TIMEOUT == 60.0

    def test_settings_missing_keys_raises_validation_error(self):
        with pytest.raises(ValidationError):
            Settings(
                _env_file=None,
                VIRUSTOTAL_API_KEY="valid_key",
                # missing URLSCAN_API_KEY, DISCORD_WEBHOOK_URL, LLM_API_KEY
            )

    @pytest.mark.parametrize(
        "placeholder",
        [
            "your_api_key_here",
            "<your_vt_api_key>",
            "changeme",
            "placeholder",
            "TODO",
            "...",
            "   ",
            "",
        ],
    )
    def test_settings_rejects_placeholder_credentials(self, valid_env_dict, placeholder):
        valid_env_dict["VIRUSTOTAL_API_KEY"] = placeholder
        with pytest.raises(ValidationError):
            Settings(**valid_env_dict)

    def test_settings_rejects_invalid_discord_webhook_url(self, valid_env_dict):
        # Non-http url
        valid_env_dict["DISCORD_WEBHOOK_URL"] = "ftp://invalid-url.com"
        with pytest.raises(ValidationError):
            Settings(**valid_env_dict)

        # Non-discord domain
        valid_env_dict["DISCORD_WEBHOOK_URL"] = "https://evil.com/webhook"
        with pytest.raises(ValidationError):
            Settings(**valid_env_dict)


# ============================================================================
# Model Validation Tests
# ============================================================================

class TestScanTarget:
    def test_scan_target_auto_populates_defanged_and_domain(self):
        target = ScanTarget(raw_url="https://secure-login.phishingsite.com/auth")
        assert target.raw_url == "https://secure-login.phishingsite.com/auth"
        assert target.defanged_url == "hxxps://secure-login[.]phishingsite[.]com/auth"
        assert target.domain == "secure-login.phishingsite.com"
        assert target.extracted_at is not None

    def test_scan_target_preserves_explicit_fields_if_given(self):
        target = ScanTarget(
            raw_url="http://custom.com",
            defanged_url="hxxp://custom[.]com",
            domain="custom.com",
        )
        assert target.defanged_url == "hxxp://custom[.]com"
        assert target.domain == "custom.com"

    def test_scan_target_rejects_empty_url(self):
        with pytest.raises(ValidationError):
            ScanTarget(raw_url="   ")


class TestVTResult:
    def test_vt_result_defaults_and_properties(self):
        result = VTResult(
            status=ScanStatus.COMPLETED,
            malicious_count=5,
            suspicious_count=2,
            harmless_count=60,
            undetected_count=10,
            engine_scan_summary={"Kaspersky": "malicious", "Sophos": "malicious"},
            permalink="https://www.virustotal.com/gui/url/123",
        )
        assert result.total_engines == 77
        assert result.is_malicious is True
        assert result.status == ScanStatus.COMPLETED

    def test_vt_result_safe_detection(self):
        result = VTResult(
            malicious_count=0,
            suspicious_count=0,
            harmless_count=75,
            undetected_count=5,
        )
        assert result.is_malicious is False
        assert result.total_engines == 80

    def test_vt_result_rejects_negative_counts(self):
        with pytest.raises(ValidationError):
            VTResult(malicious_count=-1)


class TestUrlscanResult:
    def test_urlscan_result_valid(self):
        result = UrlscanResult(
            status=ScanStatus.COMPLETED,
            verdict_score=85,
            malicious=True,
            tags=["phishing", "brand-impersonation"],
            screenshot_url="https://urlscan.io/screenshots/123.png",
            report_link="https://urlscan.io/result/123",
        )
        assert result.verdict_score == 85
        assert result.malicious is True
        assert "phishing" in result.tags

    def test_urlscan_result_rejects_invalid_score(self):
        with pytest.raises(ValidationError):
            UrlscanResult(verdict_score=150)

        with pytest.raises(ValidationError):
            UrlscanResult(verdict_score=-5)


class TestAgentEvaluation:
    def test_agent_evaluation_valid(self):
        eval_result = AgentEvaluation(
            threat_level=ThreatLevel.MALICIOUS,
            confidence_score=95,
            reasoning_summary="Target domain mimics Office365 login portal with credential harvesting forms.",
            recommended_actions=["Block domain at gateway", "Purge delivered emails", "Revoke user tokens"],
            indicators_of_compromise=["phish-office365-login[.]com", "192.168.1.5"],
            impersonated_brand="Microsoft Office 365",
        )
        assert eval_result.threat_level == ThreatLevel.MALICIOUS
        assert eval_result.confidence_score == 95
        assert len(eval_result.recommended_actions) == 3
        assert eval_result.impersonated_brand == "Microsoft Office 365"

    def test_agent_evaluation_rejects_out_of_bounds_confidence(self):
        with pytest.raises(ValidationError):
            AgentEvaluation(
                threat_level=ThreatLevel.SUSPICIOUS,
                confidence_score=101,
                reasoning_summary="Suspicious URL pattern.",
            )

    def test_agent_evaluation_rejects_invalid_threat_level(self):
        with pytest.raises(ValidationError):
            AgentEvaluation(
                threat_level="EXTREME_DANGER",  # type: ignore
                confidence_score=80,
                reasoning_summary="Test summary.",
            )
