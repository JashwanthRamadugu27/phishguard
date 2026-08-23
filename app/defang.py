"""URL defanging and sanitization utilities for safe logging and reporting."""

import re
from urllib.parse import urlparse


def defang_url(url: str) -> str:
    """
    Defangs a URL for safe logging and display.
    
    Rules enforced:
    - 'http://' -> 'hxxp://'
    - 'https://' -> 'hxxps://'
    - 'ftp://' -> 'fxp://'
    - Dots in the domain/host are converted to '[.]' (e.g., example[.]com)
    
    Examples:
        http://malicious.evil.com/login -> hxxp://malicious[.]evil[.]com/login
        https://192.168.1.1/phish -> hxxps://192[.]168[.]1[.]1/phish
    """
    if not url:
        return ""

    raw = url.strip()

    # Determine scheme prefix
    scheme_prefix = ""
    rest = raw
    if re.match(r"^https://", raw, flags=re.IGNORECASE):
        scheme_prefix = "hxxps://"
        rest = raw[8:]
    elif re.match(r"^http://", raw, flags=re.IGNORECASE):
        scheme_prefix = "hxxp://"
        rest = raw[7:]
    elif re.match(r"^ftp://", raw, flags=re.IGNORECASE):
        scheme_prefix = "fxp://"
        rest = raw[6:]

    # Parse host/netloc vs path/query
    if scheme_prefix:
        # Separate authority (host:port) from path/query/fragment
        path_start_indices = [pos for pos in [rest.find("/"), rest.find("?"), rest.find("#")] if pos != -1]
        if path_start_indices:
            split_pos = min(path_start_indices)
            authority = rest[:split_pos]
            path_rest = rest[split_pos:]
        else:
            authority = rest
            path_rest = ""
        
        defanged_authority = authority.replace(".", "[.]")
        return f"{scheme_prefix}{defanged_authority}{path_rest}"
    else:
        # If no explicit scheme, defang all domain dots
        return raw.replace(".", "[.]")


def extract_domain(url: str) -> str:
    """
    Extracts the normalized domain/hostname from a raw URL.
    """
    if not url:
        return ""
    
    candidate = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", candidate):
        candidate = f"http://{candidate}"
    
    parsed = urlparse(candidate)
    host = parsed.hostname or parsed.netloc or ""
    return host.lower()
