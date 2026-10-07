"""
services/reputation_service.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Optional external reputation checking.

Supports:
  - VirusTotal  (URLs and IPs)
  - AbuseIPDB   (IPs)
  - IPinfo      (IPs)

If no API key is configured the function returns a graceful "not configured"
result and the application continues with local-only analysis.

IMPORTANT: API keys are NEVER hard-coded. They are read from environment
variables via config.py.
"""

from __future__ import annotations

import logging
import json
from typing import Dict, Any, List

import requests

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Shared request helper
# ------------------------------------------------------------------ #

def _get(url: str, headers: dict | None = None, params: dict | None = None, timeout: int = 10) -> Dict:
    """Make a GET request; return parsed JSON or empty dict on failure."""
    try:
        resp = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        logger.warning("Reputation API request failed: %s", exc)
        return {}


# ------------------------------------------------------------------ #
# IP Reputation
# ------------------------------------------------------------------ #

def check_ip_reputation(ip: str) -> Dict[str, Any]:
    """
    Check IP against configured reputation services.

    Returns a normalised dict:
    {
        "source": "abuseipdb" | "ipinfo" | "none",
        "data": {...},
        "risk_score_contribution": int (0-50),
        "reasons": ["..."]
    }
    """
    from config import Config

    # --- AbuseIPDB (preferred for IPs) ---
    if Config.has_abuseipdb():
        return _check_abuseipdb(ip, Config.ABUSEIPDB_API_KEY)

    # --- IPinfo ---
    if Config.has_ipinfo():
        return _check_ipinfo(ip, Config.IPINFO_API_KEY)

    return _not_configured("ip")


def _check_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    raw = _get(url, headers=headers, params=params)

    data = raw.get("data", {})
    abuse_score = data.get("abuseConfidenceScore", 0)
    is_tor      = data.get("isTor", False)
    usage_type  = data.get("usageType", "")
    country     = data.get("countryCode", "")
    asn         = str(data.get("asn", ""))

    reasons: List[str] = []
    contribution = 0

    if abuse_score >= 80:
        contribution += 25
        reasons.append(f"+25  AbuseIPDB confidence {abuse_score}% (high)")
    elif abuse_score >= 20:
        contribution += 10
        reasons.append(f"+10  AbuseIPDB confidence {abuse_score}% (medium)")
    if is_tor:
        contribution += 15
        reasons.append("+15  Identified as Tor exit node by AbuseIPDB")

    normalised = {
        "abuse_confidence_score": abuse_score,
        "is_tor":        is_tor,
        "is_malicious":  abuse_score >= 80,
        "usage_type":    usage_type,
        "country_code":  country,
        "asn":           asn,
        "is_vpn":        False,
        "status":        "AbuseIPDB reputation check completed",
    }

    return {
        "source": "abuseipdb",
        "data":   normalised,
        "risk_score_contribution": min(contribution, 50),
        "reasons": reasons,
    }


def _check_ipinfo(ip: str, token: str) -> Dict[str, Any]:
    url = f"https://ipinfo.io/{ip}/json"
    params = {"token": token}
    raw = _get(url, params=params)

    org     = raw.get("org", "")
    country = raw.get("country", "")
    is_vpn  = raw.get("privacy", {}).get("vpn", False)
    is_tor  = raw.get("privacy", {}).get("tor", False)
    is_dc   = raw.get("privacy", {}).get("hosting", False)

    reasons: List[str] = []
    contribution = 0

    if is_tor:
        contribution += 15
        reasons.append("+15  Identified as Tor exit node by IPinfo")
    if is_vpn:
        contribution += 5
        reasons.append("+5   VPN provider identified by IPinfo")
    if is_dc:
        contribution += 5
        reasons.append("+5   Datacenter / hosting IP (IPinfo)")

    normalised = {
        "abuse_confidence_score": 0,
        "is_tor":        is_tor,
        "is_malicious":  False,
        "usage_type":    "hosting" if is_dc else "",
        "country_code":  country,
        "asn":           org,
        "is_vpn":        is_vpn,
        "status":        "IPinfo reputation check completed",
    }

    return {
        "source": "ipinfo",
        "data":   normalised,
        "risk_score_contribution": min(contribution, 50),
        "reasons": reasons,
    }


# ------------------------------------------------------------------ #
# URL Reputation
# ------------------------------------------------------------------ #

def check_url_reputation(url: str) -> Dict[str, Any]:
    """
    Check URL against configured reputation services.
    Currently supports VirusTotal.
    """
    from config import Config

    if Config.has_virustotal():
        return _check_virustotal_url(url, Config.VIRUSTOTAL_API_KEY)

    return _not_configured("url")


def _check_virustotal_url(url: str, api_key: str) -> Dict[str, Any]:
    """Submit URL to VirusTotal and get analysis results."""
    import base64

    # Step 1 – get existing report (no new scan submission, read-only)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers  = {"x-apikey": api_key}
    raw = _get(endpoint, headers=headers)

    if not raw or "data" not in raw:
        return _not_configured("url")

    stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    reasons: List[str] = []
    contribution = 0

    if malicious >= 5:
        contribution += 30
        reasons.append(f"+30  VirusTotal: {malicious} engines flagged as malicious")
    elif malicious >= 2:
        contribution += 20
        reasons.append(f"+20  VirusTotal: {malicious} engines flagged as malicious")
    elif malicious >= 1:
        contribution += 10
        reasons.append(f"+10  VirusTotal: {malicious} engine flagged as malicious")
    if suspicious >= 2:
        contribution += 5
        reasons.append(f"+5   VirusTotal: {suspicious} engines flagged as suspicious")

    normalised = {
        "malicious_count":  malicious,
        "suspicious_count": suspicious,
        "status":           "VirusTotal reputation check completed",
    }

    return {
        "source": "virustotal",
        "data":   normalised,
        "risk_score_contribution": min(contribution, 50),
        "reasons": reasons,
    }


# ------------------------------------------------------------------ #
# Fallback
# ------------------------------------------------------------------ #

def _not_configured(target_type: str) -> Dict[str, Any]:
    return {
        "source": "none",
        "data": {"status": "External reputation service not configured"},
        "risk_score_contribution": 0,
        "reasons": [],
    }
