"""URL extraction and normalization module for email and text bodies."""

import re
from typing import List, Set
from urllib.parse import unquote
from bs4 import BeautifulSoup

from app.defang import defang_url, extract_domain
from app.models import ScanTarget


# Regex for extracting raw HTTP/HTTPS URLs
URL_REGEX = re.compile(
    r"""(?i)\b((?:https?|hxxps?|ftp|fxp)://[^\s<>'"()]+)""",
    re.IGNORECASE,
)

# Regex for detecting URL-encoded URLs (e.g., http%3A%2F%2F or https%3A%2F%2F)
ENCODED_URL_REGEX = re.compile(
    r"""(?i)(https?%3A%2F%2F[^\s<>'"()&]+)""",
    re.IGNORECASE,
)

# Regex for defanged domains with [.] or (.) notation (e.g. evil[.]com or evil(.)com)
DEFANGED_DOMAIN_REGEX = re.compile(
    r"""(?i)\b([a-zA-Z0-9-]+(?:\[\.\]|\(\.\)|\.\[\])[a-zA-Z0-9-.]+(?:/[^\s<>'"()]*)?)\b""",
    re.IGNORECASE,
)


def refang_url(url: str) -> str:
    """
    Restores a defanged or obfuscated URL into a standard routable URL.
    
    Examples:
        hxxps://evil[.]com/login -> https://evil.com/login
        hxxp://phish(.)org -> http://phish.org
    """
    if not url:
        return ""
    
    cleaned = url.strip()
    # Decode URL-encoded components
    if "%3A" in cleaned or "%2F" in cleaned:
        cleaned = unquote(cleaned)
    
    # Replace defanged schemes
    cleaned = re.sub(r"^hxxps://", "https://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^hxxp://", "http://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^fxp://", "ftp://", cleaned, flags=re.IGNORECASE)
    
    # Replace defanged dots
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace(".[]", ".")
    
    # Add default scheme if missing and looks like a domain
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned):
        cleaned = f"http://{cleaned}"
        
    return cleaned


class LinkExtractor:
    """
    Extracts, decodes, and standardizes URLs from email headers, text bodies, and HTML content.
    """

    @classmethod
    def extract_urls(cls, content: str) -> List[ScanTarget]:
        """
        Extracts all unique, valid URL scan targets from a given text or HTML content.
        """
        if not content or not content.strip():
            return []

        raw_candidates: List[str] = []
        seen_refanged: Set[str] = set()
        targets: List[ScanTarget] = []

        # 1. Parse HTML anchor tags and attributes if HTML is detected
        if "<html" in content.lower() or "<body" in content.lower() or "<a " in content.lower():
            try:
                soup = BeautifulSoup(content, "html.parser")
                for tag in soup.find_all("a", href=True):
                    href = tag["href"].strip()
                    if href and not href.startswith(("mailto:", "tel:", "javascript:", "#")):
                        raw_candidates.append(href)
                for tag in soup.find_all(["img", "script", "iframe", "form"], src=True):
                    src = tag.get("src", "").strip()
                    if src and not src.startswith("data:"):
                        raw_candidates.append(src)
                for tag in soup.find_all("form", action=True):
                    action = tag.get("action", "").strip()
                    if action:
                        raw_candidates.append(action)
            except Exception:
                # Fallback to pure regex if BeautifulSoup fails
                pass

        # 2. Extract standard URLs via regex
        for match in URL_REGEX.findall(content):
            raw_candidates.append(match.rstrip(".,;!?)>]}"))

        # 3. Extract URL-encoded URLs
        for match in ENCODED_URL_REGEX.findall(content):
            decoded = unquote(match).rstrip(".,;!?)>]} ")
            raw_candidates.append(decoded)

        # 4. Extract defanged domain expressions (e.g., evil[.]com)
        for match in DEFANGED_DOMAIN_REGEX.findall(content):
            raw_candidates.append(match.rstrip(".,;!?)>]}"))

        # 5. Normalize, refang, deduplicate and convert to ScanTarget
        for candidate in raw_candidates:
            candidate_clean = candidate.strip().strip("'\"<>`")
            if not candidate_clean:
                continue

            refanged = refang_url(candidate_clean)
            domain = extract_domain(refanged)

            # Skip invalid domains or internal-only non-domain tokens
            if not domain or "." not in domain or len(domain) < 3:
                continue

            # Case-insensitive deduplication based on refanged normalized URL
            normalized_key = refanged.rstrip("/").lower()
            if normalized_key in seen_refanged:
                continue

            seen_refanged.add(normalized_key)

            try:
                target = ScanTarget(
                    raw_url=refanged,
                    defanged_url=defang_url(refanged),
                    domain=domain,
                )
                targets.append(target)
            except Exception:
                # Ignore invalid URLs that fail schema validation
                continue

        return targets
