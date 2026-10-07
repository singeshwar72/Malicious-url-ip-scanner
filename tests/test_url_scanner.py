"""
tests/test_url_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for URL scanning and validation.
Run with: pytest tests/
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from scanner.validators import validate_input, InputType, is_valid_url
from scanner.url_scanner import scan_url, _is_ip_host, _count_subdomains, _extract_domain


# ------------------------------------------------------------------ #
# Validator tests
# ------------------------------------------------------------------ #

class TestUrlValidation:

    def test_valid_https_url(self):
        """A well-formed HTTPS URL should be classified as URL."""
        itype, normalised, err = validate_input("https://example.com")
        assert itype == InputType.URL
        assert err is None

    def test_valid_http_url(self):
        """HTTP URLs are accepted (flagged as risk, but valid input)."""
        itype, _, err = validate_input("http://example.com/path?q=1")
        assert itype == InputType.URL
        assert err is None

    def test_bare_domain_classified_as_url(self):
        """A bare domain without scheme should be classified as URL."""
        itype, normalised, err = validate_input("example.com")
        assert itype == InputType.URL
        assert err is None

    def test_url_with_path_and_query(self):
        """URLs with path, query string, and fragment should be accepted."""
        itype, _, err = validate_input("https://sub.example.com/page?id=1&ref=abc#section")
        assert itype == InputType.URL
        assert err is None

    def test_empty_input_rejected(self):
        """Empty string should return an error."""
        itype, _, err = validate_input("")
        assert itype == InputType.UNKNOWN
        assert err is not None

    def test_input_too_long_rejected(self):
        """Input exceeding max length should be rejected."""
        long_input = "https://example.com/" + "a" * 3000
        itype, _, err = validate_input(long_input)
        assert itype == InputType.UNKNOWN
        assert err is not None

    def test_unsupported_scheme_rejected(self):
        """Unsupported schemes (e.g. javascript://) should be rejected."""
        itype, _, err = validate_input("javascript://alert(1)")
        assert itype == InputType.UNKNOWN
        assert err is not None

    def test_is_valid_url_helper_true(self):
        assert is_valid_url("https://google.com") is True

    def test_is_valid_url_helper_false(self):
        assert is_valid_url("not_a_url_###") is False


# ------------------------------------------------------------------ #
# URL scanner tests
# ------------------------------------------------------------------ #

class TestUrlScanner:

    def test_https_detection(self):
        """HTTPS URL sets is_https indicator to True."""
        result = scan_url("https://example.com")
        assert result["indicators"]["is_https"] is True
        assert result["indicators"]["is_http"] is False

    def test_http_detection(self):
        """HTTP URL sets is_http indicator to True."""
        result = scan_url("http://example.com")
        assert result["indicators"]["is_http"] is True
        assert result["indicators"]["is_https"] is False

    def test_ip_host_detection(self):
        """URL with IP as host sets is_ip_host to True."""
        result = scan_url("http://192.168.1.1/admin")
        assert result["indicators"]["is_ip_host"] is True

    def test_suspicious_keyword_detection(self):
        """URLs containing known phishing keywords should be flagged."""
        result = scan_url("http://secure-login.example.com/verify?account=update")
        assert result["indicators"]["has_suspicious_keyword"] is True

    def test_excessive_subdomains(self):
        """URLs with 4+ subdomain levels should be flagged."""
        result = scan_url("http://a.b.c.d.example.com/page")
        assert result["indicators"]["excessive_subdomains"] is True

    def test_credentials_in_url(self):
        """Embedded username:password in URL should be flagged."""
        result = scan_url("http://user:pass@example.com/")
        assert result["indicators"]["has_credentials"] is True

    def test_at_symbol_detection(self):
        """@ in the URL (before query) should be flagged."""
        result = scan_url("http://legitimate.com@evil.com/")
        assert result["indicators"]["has_at_symbol"] is True

    def test_excessive_encoding(self):
        """URLs with many percent-encoded characters should be flagged."""
        encoded = "http://example.com/%61%62%63%64%65%66%67%68"
        result = scan_url(encoded)
        assert result["indicators"]["excessive_encoding"] is True

    def test_parsed_scheme_extracted(self):
        """Scheme should be correctly extracted."""
        result = scan_url("https://example.com")
        assert result["parsed"]["scheme"] == "https"

    def test_domain_extracted(self):
        """Domain should be correctly extracted from subdomain URL."""
        result = scan_url("https://sub.example.com/path")
        assert result["parsed"]["domain"] == "example.com"

    def test_subdomain_count(self):
        assert _count_subdomains("a.b.c.example.com") == 3
        assert _count_subdomains("example.com") == 0
        assert _count_subdomains("sub.example.com") == 1

    def test_is_ip_host(self):
        assert _is_ip_host("192.168.1.1") is True
        assert _is_ip_host("example.com") is False
        assert _is_ip_host("::1") is True

    def test_extract_domain(self):
        assert _extract_domain("sub.example.com") == "example.com"
        assert _extract_domain("a.b.c.example.co.uk") == "co.uk"  # simplified extraction

    def test_scan_returns_required_keys(self):
        """scan_url must always return the expected structure."""
        result = scan_url("https://example.com")
        for key in ("url", "parsed", "indicators", "technical", "errors"):
            assert key in result
