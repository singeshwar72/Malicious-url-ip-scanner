"""
scanner/validators.py
~~~~~~~~~~~~~~~~~~~~~
Input validation – determines whether a user-supplied string is a URL,
an IPv4 address, or an IPv6 address, and rejects obviously bad input
before any scanning begins.

No external libraries required (uses only stdlib).
"""

import re
import ipaddress
import urllib.parse
from enum import Enum
from typing import Tuple, Optional


class InputType(str, Enum):
    URL  = "URL"
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    UNKNOWN = "UNKNOWN"


# Maximum length we accept (guard against DoS-style oversized payloads)
MAX_LENGTH = 2048

# Schemes we are willing to analyse
ALLOWED_SCHEMES = {"http", "https", "ftp"}

# Basic URL-like pattern: must contain "://" or "www."
_URL_RE = re.compile(
    r"^(https?|ftp)://"         # scheme
    r"|^www\."                   # or starts with www.
    r"|^[a-zA-Z0-9]"             # or plain hostname/domain
    r"[a-zA-Z0-9\-\.]*"
    r"\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

# Looks like a plain hostname / domain without scheme
_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$",
    re.IGNORECASE,
)


def validate_input(raw: str) -> Tuple[InputType, str, Optional[str]]:
    """
    Validate and classify raw user input.

    Returns
    -------
    (InputType, normalised_target, error_message)

    error_message is None when validation passes.
    """
    if not raw or not raw.strip():
        return InputType.UNKNOWN, "", "Input must not be empty."

    target = raw.strip()

    if len(target) > MAX_LENGTH:
        return InputType.UNKNOWN, target, f"Input exceeds maximum length of {MAX_LENGTH} characters."

    # ----- Try IPv6 first (before URL, because colons confuse things) -----
    # Strip surrounding brackets that some representations use: [::1]
    ipv6_candidate = target.strip("[]")
    try:
        addr = ipaddress.IPv6Address(ipv6_candidate)
        return InputType.IPV6, str(addr), None
    except ipaddress.AddressValueError:
        pass

    # ----- Try IPv4 -----
    try:
        addr = ipaddress.IPv4Address(target)
        return InputType.IPV4, str(addr), None
    except ipaddress.AddressValueError:
        pass

    # ----- Try URL / domain -----
    # Auto-prefix http:// for bare hostnames so urllib can parse them
    working = target
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", working):
        working = "http://" + working

    try:
        parsed = urllib.parse.urlparse(working)
    except Exception:
        return InputType.UNKNOWN, target, "Could not parse input as a URL."

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return InputType.UNKNOWN, target, (
            f"Unsupported scheme '{parsed.scheme}'. "
            f"Supported: {', '.join(sorted(ALLOWED_SCHEMES))}."
        )

    host = parsed.hostname or ""
    if not host:
        return InputType.UNKNOWN, target, "URL has no host component."

    # Reject hosts that contain clearly invalid characters
    import re as _re
    if _re.search(r"[^a-zA-Z0-9.\-\[\]:]", host):
        return InputType.UNKNOWN, target, f"Host '{host}' contains invalid characters."

    # Reconstruct with the original target if it already had a scheme,
    # else use the working version (which added http://)
    normalised = target if re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", target) else working
    return InputType.URL, normalised, None


def is_valid_ipv4(address: str) -> bool:
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_ipv6(address: str) -> bool:
    try:
        ipaddress.IPv6Address(address.strip("[]"))
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_url(url: str) -> bool:
    _, _, err = validate_input(url)
    return err is None
