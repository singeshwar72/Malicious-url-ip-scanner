"""
scanner/ip_scanner.py
~~~~~~~~~~~~~~~~~~~~~~
IP address analysis module.

Supports both IPv4 and IPv6.
Performs DEFENSIVE, read-only analysis:
  - Classification (public, private, loopback, reserved, multicast)
  - Reverse DNS lookup
  - Optional external reputation check via services/reputation_service.py
  - Does NOT perform port scans, traceroutes, or any active probing.
"""

from __future__ import annotations

import ipaddress
import socket
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def scan_ip(ip_str: str, ip_version: int = 4) -> Dict[str, Any]:
    """
    Analyse an IP address and return a structured result dict.

    Parameters
    ----------
    ip_str     : str  – validated IP string
    ip_version : int  – 4 or 6

    Returns
    -------
    dict with keys:
        ip_info    – classification and properties
        indicators – boolean flags for risk_engine
        technical  – extra detail
        errors     – list of non-fatal error messages
    """
    errors: List[str] = []

    # ------------------------------------------------------------------ #
    # 1. Parse IP address
    # ------------------------------------------------------------------ #
    try:
        if ip_version == 6:
            addr = ipaddress.IPv6Address(ip_str.strip("[]"))
        else:
            addr = ipaddress.IPv4Address(ip_str)
    except ipaddress.AddressValueError as exc:
        return _error_result(ip_str, str(exc))

    # ------------------------------------------------------------------ #
    # 2. Classification
    # ------------------------------------------------------------------ #
    is_private    = addr.is_private
    is_loopback   = addr.is_loopback
    is_multicast  = addr.is_multicast
    is_reserved   = addr.is_reserved
    is_global     = addr.is_global
    is_unspecified = addr.is_unspecified
    is_link_local = addr.is_link_local

    if ip_version == 6:
        is_ipv4_mapped = getattr(addr, "ipv4_mapped", None) is not None
    else:
        is_ipv4_mapped = False

    # ------------------------------------------------------------------ #
    # 3. Reverse DNS
    # ------------------------------------------------------------------ #
    reverse_dns: Optional[str] = None
    no_reverse_dns = False

    if is_global:
        try:
            from config import Config
            socket.setdefaulttimeout(Config.DNS_TIMEOUT)
            reverse_dns = socket.gethostbyaddr(ip_str)[0]
        except (socket.herror, socket.gaierror):
            no_reverse_dns = True
        except Exception as exc:
            errors.append(f"Reverse DNS error: {exc}")
            no_reverse_dns = True
        finally:
            socket.setdefaulttimeout(None)

    # ------------------------------------------------------------------ #
    # 4. External reputation check (optional)
    # ------------------------------------------------------------------ #
    reputation_data: Dict[str, Any] = {}
    external_score  = 0
    external_reasons: list = []

    try:
        from services.reputation_service import check_ip_reputation
        rep_result = check_ip_reputation(ip_str)
        reputation_data = rep_result.get("data", {})
        external_score  = rep_result.get("risk_score_contribution", 0)
        external_reasons = rep_result.get("reasons", [])
    except Exception as exc:
        logger.debug("Reputation service unavailable: %s", exc)
        reputation_data = {"status": "External reputation service not configured"}

    # ------------------------------------------------------------------ #
    # 5. Indicator flags for risk engine
    # ------------------------------------------------------------------ #
    high_abuse_score   = reputation_data.get("abuse_confidence_score", 0) >= 80
    medium_abuse_score = 20 <= reputation_data.get("abuse_confidence_score", 0) < 80
    is_tor_exit        = reputation_data.get("is_tor", False)
    is_known_malicious = reputation_data.get("is_malicious", False)
    is_datacenter      = reputation_data.get("usage_type", "").lower() in (
        "data center/web hosting/transit", "hosting", "datacenter",
    )
    is_vpn             = reputation_data.get("is_vpn", False)

    indicators: Dict[str, Any] = {
        "no_reverse_dns":      no_reverse_dns,
        "high_abuse_score":    high_abuse_score,
        "medium_abuse_score":  medium_abuse_score,
        "is_tor_exit":         is_tor_exit,
        "is_known_malicious":  is_known_malicious,
        "is_datacenter":       is_datacenter,
        "is_vpn":              is_vpn,
    }

    ip_info: Dict[str, Any] = {
        "ip":           ip_str,
        "version":      ip_version,
        "is_private":   is_private,
        "is_loopback":  is_loopback,
        "is_multicast": is_multicast,
        "is_reserved":  is_reserved,
        "is_global":    is_global,
        "is_unspecified": is_unspecified,
        "is_link_local": is_link_local,
        "is_ipv4_mapped": is_ipv4_mapped,
        "reverse_dns":  reverse_dns,
        "ip_class":     _classify(addr),
    }

    technical: Dict[str, Any] = {
        "compressed": str(addr.compressed) if hasattr(addr, "compressed") else ip_str,
        "exploded":   str(addr.exploded)   if hasattr(addr, "exploded")   else ip_str,
        "scan_time":  datetime.now(timezone.utc).isoformat(),
        "reputation": reputation_data,
        "country":    reputation_data.get("country_code", ""),
        "asn":        reputation_data.get("asn", ""),
    }

    return {
        "ip":           ip_str,
        "ip_info":      ip_info,
        "indicators":   indicators,
        "technical":    technical,
        "errors":       errors,
        "external_score":   external_score,
        "external_reasons": external_reasons,
    }


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _classify(addr) -> str:
    if addr.is_loopback:
        return "Loopback"
    if addr.is_private:
        return "Private"
    if addr.is_multicast:
        return "Multicast"
    if addr.is_reserved:
        return "Reserved"
    if addr.is_link_local:
        return "Link-Local"
    if addr.is_global:
        return "Public (Global)"
    return "Unknown"


def _error_result(ip: str, message: str) -> Dict[str, Any]:
    return {
        "ip":         ip,
        "ip_info":    {},
        "indicators": {},
        "technical":  {"error": message},
        "errors":     [message],
        "external_score":   0,
        "external_reasons": [],
    }


# Fix missing import
from typing import List
