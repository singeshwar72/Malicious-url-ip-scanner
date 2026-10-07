"""
scanner/risk_engine.py
~~~~~~~~~~~~~~~~~~~~~~~
Risk scoring engine.

Calculates a deterministic integer score 0-100 from a set of indicator
flags.  The same input will always produce the same score (external API
results may add additional points on top of the base score).

Score bands:
    0  – 19  → SAFE
    20 – 39  → LOW RISK
    40 – 59  → SUSPICIOUS
    60 – 79  → HIGH RISK
    80 – 100 → MALICIOUS
"""

from __future__ import annotations
from typing import Dict, Any, List, Tuple


# ------------------------------------------------------------------ #
# Score thresholds
# ------------------------------------------------------------------ #
VERDICT_THRESHOLDS: List[Tuple[int, str]] = [
    (80, "MALICIOUS"),
    (60, "HIGH RISK"),
    (40, "SUSPICIOUS"),
    (20, "LOW RISK"),
    (0,  "SAFE"),
]

# ------------------------------------------------------------------ #
# Weighted rules
# Each rule is a (weight, key_in_indicators, description) tuple.
# key_in_indicators must match a boolean key returned by url_scanner
# or ip_scanner in their 'indicators' dict.
# ------------------------------------------------------------------ #

URL_RULES: List[Tuple[int, str, str]] = [
    (25, "is_ip_host",          "IP address used instead of domain name"),
    (20, "has_suspicious_keyword", "Suspicious keyword detected in URL"),
    (15, "is_http",             "Connection is plain HTTP (not HTTPS)"),
    (15, "has_punycode",        "Punycode / IDN homograph indicator"),
    (12, "excessive_subdomains","Excessive number of subdomains"),
    (12, "has_credentials",     "Credentials embedded in URL"),
    (10, "has_at_symbol",       "@ symbol found in URL (possible spoofing)"),
    (10, "has_double_slash",    "Double slash in URL path (suspicious redirect)"),
    (10, "url_very_long",       "Unusually long URL"),
    (10, "excessive_encoding",  "Excessive percent-encoding in URL"),
    (8,  "suspicious_tld",      "Suspicious top-level domain"),
    (8,  "has_redirect_indicator", "URL contains redirect parameter"),
    (5,  "non_standard_port",   "Non-standard port specified"),
    (5,  "missing_dns",         "Domain does not resolve (DNS failure)"),
    (5,  "url_long",            "Long URL"),
    (3,  "ftp_scheme",          "FTP scheme (legacy protocol)"),
]

IP_RULES: List[Tuple[int, str, str]] = [
    (30, "is_tor_exit",         "Known Tor exit node"),
    (25, "high_abuse_score",    "High abuse confidence score from AbuseIPDB"),
    (20, "is_known_malicious",  "Flagged as malicious by reputation service"),
    (15, "is_datacenter",       "Datacenter / hosting IP (elevated risk)"),
    (10, "no_reverse_dns",      "No reverse DNS record"),
    (8,  "medium_abuse_score",  "Medium abuse confidence score"),
    (5,  "is_vpn",              "VPN provider IP"),
]


def score_to_verdict(score: int) -> str:
    """Convert a numeric score to a verdict label."""
    for threshold, label in VERDICT_THRESHOLDS:
        if score >= threshold:
            return label
    return "SAFE"


def calculate_risk(
    indicators: Dict[str, Any],
    scan_type: str = "URL",
    external_score: int = 0,
    external_reasons: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Calculate a risk score and verdict from indicator flags.

    Parameters
    ----------
    indicators : dict
        Boolean/numeric flags produced by url_scanner or ip_scanner.
    scan_type : str
        'URL', 'IPv4', or 'IPv6'.
    external_score : int
        Additional points from external reputation APIs (0-50).
    external_reasons : list
        Human-readable reason strings from external APIs.

    Returns
    -------
    dict with keys: score, verdict, reasons, detail_table
    """
    rules = URL_RULES if scan_type == "URL" else IP_RULES
    total = 0
    reasons: List[str] = []
    detail_table: List[Dict[str, Any]] = []

    for weight, key, description in rules:
        value = indicators.get(key)
        triggered = bool(value)

        if triggered:
            total += weight
            reasons.append(f"+{weight:2d}  {description}")
            detail_table.append({"check": description, "result": "FLAGGED", "weight": weight})
        else:
            detail_table.append({"check": description, "result": "PASS", "weight": 0})

    # Clamp base score before adding external
    base_score = min(total, 100)

    # Add external reputation score (up to 50 extra points)
    if external_score > 0:
        clamped_external = min(external_score, 50)
        base_score = min(base_score + clamped_external, 100)
        if external_reasons:
            reasons.extend(external_reasons)

    final_score = base_score
    verdict = score_to_verdict(final_score)

    # Build a short recommendation
    recommendation = _recommendation(verdict)

    return {
        "score": final_score,
        "verdict": verdict,
        "reasons": reasons,
        "detail_table": detail_table,
        "recommendation": recommendation,
    }


def _recommendation(verdict: str) -> str:
    mapping = {
        "SAFE":       "No significant threats detected. Continue using normal security precautions.",
        "LOW RISK":   "Minor concerns noted. Proceed with caution and verify the source.",
        "SUSPICIOUS": "Suspicious indicators detected. Do not share sensitive information with this target.",
        "HIGH RISK":  "High risk target. Avoid accessing or interacting with this target.",
        "MALICIOUS":  "Target shows strong malicious indicators. Block immediately and do not access.",
    }
    return mapping.get(verdict, "Unable to determine recommendation.")
