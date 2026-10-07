"""
tests/test_ip_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for IP address scanning and validation.
Run with: pytest tests/
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from scanner.validators import validate_input, InputType, is_valid_ipv4, is_valid_ipv6
from scanner.ip_scanner import scan_ip


# ------------------------------------------------------------------ #
# IP Validation tests
# ------------------------------------------------------------------ #

class TestIpValidation:

    def test_valid_ipv4(self):
        """Standard public IPv4 should be classified correctly."""
        itype, normalised, err = validate_input("8.8.8.8")
        assert itype == InputType.IPV4
        assert err is None
        assert normalised == "8.8.8.8"

    def test_valid_private_ipv4(self):
        """Private IPv4 should be classified as IPv4."""
        itype, _, err = validate_input("192.168.1.1")
        assert itype == InputType.IPV4
        assert err is None

    def test_valid_loopback_ipv4(self):
        """Loopback address should be classified as IPv4."""
        itype, _, err = validate_input("127.0.0.1")
        assert itype == InputType.IPV4
        assert err is None

    def test_invalid_ipv4_rejected(self):
        """255.255.255.256 is not a valid IP – should not be IPV4."""
        itype, _, err = validate_input("255.255.255.256")
        # Should be treated as a URL-like or unknown, not IPV4
        assert itype != InputType.IPV4

    def test_valid_ipv6_full(self):
        """Full expanded IPv6 address should be classified correctly."""
        itype, _, err = validate_input("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert itype == InputType.IPV6
        assert err is None

    def test_valid_ipv6_compressed(self):
        """Compressed IPv6 (Google DNS) should be accepted."""
        itype, _, err = validate_input("2001:4860:4860::8888")
        assert itype == InputType.IPV6
        assert err is None

    def test_loopback_ipv6(self):
        """IPv6 loopback ::1 should be classified as IPv6."""
        itype, _, err = validate_input("::1")
        assert itype == InputType.IPV6
        assert err is None

    def test_is_valid_ipv4_helper(self):
        assert is_valid_ipv4("10.0.0.1") is True
        assert is_valid_ipv4("999.0.0.1") is False
        assert is_valid_ipv4("not-an-ip") is False

    def test_is_valid_ipv6_helper(self):
        assert is_valid_ipv6("::1") is True
        assert is_valid_ipv6("2001:db8::1") is True
        assert is_valid_ipv6("not-ipv6") is False


# ------------------------------------------------------------------ #
# IP Scanner tests
# ------------------------------------------------------------------ #

class TestIpScanner:

    def test_public_ip_is_global(self):
        """8.8.8.8 is a public global IP."""
        result = scan_ip("8.8.8.8", ip_version=4)
        assert result["ip_info"]["is_global"] is True
        assert result["ip_info"]["is_private"] is False

    def test_private_ip_classification(self):
        """192.168.1.1 is private, not global."""
        result = scan_ip("192.168.1.1", ip_version=4)
        assert result["ip_info"]["is_private"] is True
        assert result["ip_info"]["is_global"] is False

    def test_loopback_ip_classification(self):
        """127.0.0.1 is loopback."""
        result = scan_ip("127.0.0.1", ip_version=4)
        assert result["ip_info"]["is_loopback"] is True

    def test_ipv6_loopback(self):
        """::1 is IPv6 loopback."""
        result = scan_ip("::1", ip_version=6)
        assert result["ip_info"]["is_loopback"] is True

    def test_ipv6_public_google(self):
        """2001:4860:4860::8888 is a public IPv6 address."""
        result = scan_ip("2001:4860:4860::8888", ip_version=6)
        assert result["ip_info"]["is_global"] is True

    def test_scan_returns_required_keys(self):
        """scan_ip must always return the expected top-level keys."""
        result = scan_ip("8.8.8.8", ip_version=4)
        for key in ("ip", "ip_info", "indicators", "technical", "errors"):
            assert key in result

    def test_ip_class_string_private(self):
        """ip_class should be 'Private' for RFC1918 addresses."""
        result = scan_ip("10.10.10.10", ip_version=4)
        assert result["ip_info"]["ip_class"] == "Private"

    def test_ip_class_string_loopback(self):
        """ip_class should be 'Loopback' for 127.x.x.x."""
        result = scan_ip("127.0.0.1", ip_version=4)
        assert result["ip_info"]["ip_class"] == "Loopback"

    def test_no_crash_on_bad_ip(self):
        """Scanner must not raise exceptions on invalid input."""
        result = scan_ip("not-an-ip", ip_version=4)
        assert "errors" in result
        assert len(result["errors"]) > 0

    def test_indicators_dict_present(self):
        """Indicators dict must be present (may have False values for private IPs)."""
        result = scan_ip("192.168.0.1", ip_version=4)
        assert isinstance(result["indicators"], dict)
