"""
services/dns_service.py
~~~~~~~~~~~~~~~~~~~~~~~~
DNS helper utilities used by the scanner modules.

All lookups are read-only and defensive.
"""

from __future__ import annotations

import socket
import logging
from typing import Optional, List

logger = logging.getLogger(__name__)


def resolve_hostname(hostname: str, timeout: int = 5) -> Optional[str]:
    """
    Resolve a hostname to its first IPv4 address.
    Returns None if resolution fails.
    """
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.herror) as exc:
        logger.debug("DNS resolution failed for %s: %s", hostname, exc)
        return None
    except Exception as exc:
        logger.debug("Unexpected DNS error for %s: %s", hostname, exc)
        return None
    finally:
        socket.setdefaulttimeout(None)


def resolve_all(hostname: str, timeout: int = 5) -> List[str]:
    """
    Resolve a hostname to all its IPv4 addresses.
    Returns empty list if resolution fails.
    """
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except Exception:
        return []
    finally:
        socket.setdefaulttimeout(None)


def reverse_lookup(ip: str, timeout: int = 3) -> Optional[str]:
    """
    Perform a reverse DNS lookup.
    Returns the hostname or None if not available.
    """
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None
    except Exception as exc:
        logger.debug("Reverse DNS error for %s: %s", ip, exc)
        return None
    finally:
        socket.setdefaulttimeout(None)
