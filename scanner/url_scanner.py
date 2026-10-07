"""
scanner/url_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~
URL analysis module.

Performs DEFENSIVE, read-only analysis of a URL:
  - Parses structure (scheme, host, path, query, fragment)
  - Checks HTTPS vs HTTP
  - Detects suspicious patterns (keywords, encoding, subdomains, etc.)
  - Resolves DNS safely
  - Does NOT visit the URL, execute scripts, or follow redirects automatically.
"""

from __future__ import annotations

import re
import socket
import hashlib
import urllib.parse
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Suspicious keyword list (defensive – detects phishing/social eng)
# ------------------------------------------------------------------ #
SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "secure", "update", "confirm", "banking",
    "paypal", "amazon", "apple", "microsoft", "google",
    "password", "credential", "wallet", "crypto", "invoice",
    "free", "winner", "prize", "lucky", "claim", "urgent",
    "suspended", "limited", "alert", "unusual", "activity",
    "support", "helpdesk",
]

# Suspicious TLDs commonly abused in phishing
SUSPICIOUS_TLDS: set = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # free Freenom TLDs
    ".xyz", ".top", ".club", ".online",
    ".site", ".icu", ".cam", ".work",
}

# Redirect-indicator query parameter names
REDIRECT_PARAMS: set = {
    "redirect", "redirect_uri", "redirect_url",
    "url", "next", "return", "returnto", "goto",
    "destination", "dest", "target", "link",
}


def scan_url(url: str) -> Dict[str, Any]:
    """
    Analyse a URL and return a structured result dict.

    Parameters
    ----------
    url : str  – a valid URL (already validated by validators.py)

    Returns
    -------
    dict with keys:
        parsed      – parsed URL components
        indicators  – boolean flags for risk_engine
        technical   – extra technical detail
        errors      – list of non-fatal error messages
    """
    errors: List[str] = []

    # ------------------------------------------------------------------ #
    # 1. Parse URL
    # ------------------------------------------------------------------ #
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        logger.warning("URL parse error: %s", exc)
        return _error_result(url, str(exc))

    scheme   = (parsed.scheme or "").lower()
    host     = (parsed.hostname or "").lower()
    path     = parsed.path or ""
    query    = parsed.query or ""
    fragment = parsed.fragment or ""
    port     = parsed.port
    userinfo = parsed.username or ""

    # ------------------------------------------------------------------ #
    # 2. Structural checks
    # ------------------------------------------------------------------ #
    is_https           = scheme == "https"
    is_http            = scheme == "http"
    ftp_scheme         = scheme == "ftp"
    has_credentials    = bool(parsed.username or parsed.password)
    has_at_symbol      = "@" in url.split("?")[0]   # @ before query string
    url_length         = len(url)
    url_long           = url_length > 100
    url_very_long      = url_length > 200

    # ------------------------------------------------------------------ #
    # 3. Host / domain analysis
    # ------------------------------------------------------------------ #
    is_ip_host = _is_ip_host(host)
    subdomains = _count_subdomains(host) if not is_ip_host else 0
    excessive_subdomains = subdomains >= 4
    domain = _extract_domain(host) if not is_ip_host else host
    tld    = ("." + host.rsplit(".", 1)[-1]) if "." in host else ""
    suspicious_tld = tld.lower() in SUSPICIOUS_TLDS
    has_punycode = "xn--" in host.lower()

    # ------------------------------------------------------------------ #
    # 4. Content checks
    # ------------------------------------------------------------------ #
    full_text = url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_text]
    has_suspicious_keyword = bool(matched_keywords)

    # Excessive percent-encoding: more than 5 encoded chars is suspicious
    encoded_chars = re.findall(r"%[0-9A-Fa-f]{2}", url)
    excessive_encoding = len(encoded_chars) > 5

    # Double slashes in path (not counting scheme ://)
    path_double_slash = path.replace("//", "", 1) if path.startswith("//") else path
    has_double_slash = "//" in path_double_slash

    # Redirect indicator in query string
    query_params = urllib.parse.parse_qs(query, keep_blank_values=True)
    has_redirect_indicator = bool(set(k.lower() for k in query_params) & REDIRECT_PARAMS)

    # ------------------------------------------------------------------ #
    # 5. Port check
    # ------------------------------------------------------------------ #
    standard_ports = {80, 443, 21, 8080, 8443}
    non_standard_port = (port is not None) and (port not in standard_ports)

    # ------------------------------------------------------------------ #
    # 6. DNS resolution (safe – no HTTP request made)
    # ------------------------------------------------------------------ #
    ip_address: Optional[str] = None
    reverse_dns: Optional[str] = None
    missing_dns = False

    if host and not is_ip_host:
        try:
            from config import Config
            socket.setdefaulttimeout(Config.DNS_TIMEOUT)
            ip_address = socket.gethostbyname(host)
        except socket.gaierror:
            missing_dns = True
            errors.append(f"DNS resolution failed for '{host}'")
        except Exception as exc:
            errors.append(f"DNS lookup error: {exc}")
        finally:
            socket.setdefaulttimeout(None)
    elif is_ip_host:
        ip_address = host

    if ip_address:
        try:
            socket.setdefaulttimeout(3)
            reverse_dns = socket.gethostbyaddr(ip_address)[0]
        except Exception:
            reverse_dns = None
        finally:
            socket.setdefaulttimeout(None)

    # ------------------------------------------------------------------ #
    # 7. URL fingerprint (for deduplication – not used for security)
    # ------------------------------------------------------------------ #
    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]

    # ------------------------------------------------------------------ #
    # 8. Assemble result
    # ------------------------------------------------------------------ #
    indicators: Dict[str, Any] = {
        "is_https":               is_https,
        "is_http":                is_http,
        "ftp_scheme":             ftp_scheme,
        "has_credentials":        has_credentials,
        "has_at_symbol":          has_at_symbol,
        "url_long":               url_long,
        "url_very_long":          url_very_long,
        "is_ip_host":             is_ip_host,
        "excessive_subdomains":   excessive_subdomains,
        "suspicious_tld":         suspicious_tld,
        "has_punycode":           has_punycode,
        "has_suspicious_keyword": has_suspicious_keyword,
        "excessive_encoding":     excessive_encoding,
        "has_double_slash":       has_double_slash,
        "has_redirect_indicator": has_redirect_indicator,
        "non_standard_port":      non_standard_port,
        "missing_dns":            missing_dns,
    }

    parsed_info: Dict[str, Any] = {
        "scheme":       scheme,
        "host":         host,
        "domain":       domain,
        "port":         port,
        "path":         path,
        "query":        query,
        "fragment":     fragment,
        "tld":          tld,
        "subdomains":   subdomains,
    }

    technical: Dict[str, Any] = {
        "url_length":        url_length,
        "encoded_chars":     len(encoded_chars),
        "query_params":      list(query_params.keys()),
        "matched_keywords":  matched_keywords,
        "ip_address":        ip_address,
        "reverse_dns":       reverse_dns,
        "url_hash":          url_hash,
        "scan_time":         datetime.now(timezone.utc).isoformat(),
    }

    return {
        "url":       url,
        "parsed":    parsed_info,
        "indicators": indicators,
        "technical": technical,
        "errors":    errors,
    }


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _is_ip_host(host: str) -> bool:
    """Return True if host is an IP address rather than a hostname."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _count_subdomains(host: str) -> int:
    """
    Count subdomain levels.
    For 'a.b.c.example.com' this returns 3 (a, b, c are subdomains).
    For 'example.com' this returns 0.
    """
    parts = host.split(".")
    # Subtract 2 for domain + TLD
    return max(0, len(parts) - 2)


def _extract_domain(host: str) -> str:
    """Return the registered domain (last two labels) from a hostname."""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _error_result(url: str, message: str) -> Dict[str, Any]:
    return {
        "url":       url,
        "parsed":    {},
        "indicators": {},
        "technical": {"error": message},
        "errors":    [message],
    }
