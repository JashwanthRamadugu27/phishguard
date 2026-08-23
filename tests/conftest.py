"""Pytest configuration, shared test fixtures, and mock payloads."""

import pytest
from app.config import Settings
from app.models import ScanTarget


@pytest.fixture
def mock_settings():
    return Settings(
        VIRUSTOTAL_API_KEY="test_virustotal_key_1234567890",
        URLSCAN_API_KEY="test_urlscan_key_1234567890",
        DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/123456789/test_token_abc",
        LLM_API_KEY="gsk_test_groq_key_1234567890",
        LLM_MODEL="llama-3.3-70b-versatile",
        VIRUSTOTAL_RATE_LIMIT=4,
        VIRUSTOTAL_RATE_LIMIT_PERIOD=1.0,  # Fast period for testing
        VIRUSTOTAL_TIMEOUT=5.0,
        URLSCAN_POLL_INTERVAL=0.1,         # Fast polling for testing
        URLSCAN_TIMEOUT=0.5,
        HTTP_REQUEST_TIMEOUT=5.0,
    )


@pytest.fixture
def sample_malicious_target():
    return ScanTarget(
        raw_url="https://secure-login.bankofamerica.update-auth-now.top/signin",
        defanged_url="hxxps://secure-login[.]bankofamerica[.]update-auth-now[.]top/signin",
        domain="secure-login.bankofamerica.update-auth-now.top",
    )


@pytest.fixture
def sample_safe_target():
    return ScanTarget(
        raw_url="https://www.google.com/search?q=cybersecurity",
        defanged_url="hxxps://www[.]google[.]com/search?q=cybersecurity",
        domain="www.google.com",
    )


@pytest.fixture
def vt_clean_payload():
    return {
        "data": {
            "id": "url-id-clean",
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 75,
                    "undetected": 5,
                },
                "last_analysis_results": {},
            },
        }
    }


@pytest.fixture
def vt_malicious_payload():
    return {
        "data": {
            "id": "url-id-malicious",
            "type": "url",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 14,
                    "suspicious": 3,
                    "harmless": 50,
                    "undetected": 10,
                },
                "last_analysis_results": {
                    "Kaspersky": {"category": "malicious", "result": "phishing"},
                    "Sophos": {"category": "malicious", "result": "trojan-dropper"},
                    "BitDefender": {"category": "malicious", "result": "credential-stealer"},
                },
            },
        }
    }


@pytest.fixture
def urlscan_submit_payload():
    return {
        "message": "Submission successful",
        "uuid": "01234567-89ab-cdef-0123-456789abcdef",
        "result": "https://urlscan.io/result/01234567-89ab-cdef-0123-456789abcdef/",
        "api": "https://urlscan.io/api/v1/result/01234567-89ab-cdef-0123-456789abcdef/",
    }


@pytest.fixture
def urlscan_result_completed_payload():
    return {
        "verdicts": {
            "overall": {
                "score": 85,
                "malicious": True,
                "tags": ["phishing", "brand-impersonation"],
                "categories": ["phishing"],
            },
            "urlscan": {
                "score": 85,
                "malicious": True,
                "tags": ["phishing"],
            },
            "engines": {
                "maliciousTotal": 2,
            },
        },
        "page": {
            "url": "https://phishing-site.com",
            "domain": "phishing-site.com",
        },
    }
