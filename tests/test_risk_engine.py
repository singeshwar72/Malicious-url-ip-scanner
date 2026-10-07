"""
tests/test_risk_engine.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for the risk scoring engine.
Run with: pytest tests/
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from scanner.risk_engine import calculate_risk, score_to_verdict, VERDICT_THRESHOLDS


# ------------------------------------------------------------------ #
# Verdict band tests
# ------------------------------------------------------------------ #

class TestScoreToVerdict:

    def test_score_0_is_safe(self):
        assert score_to_verdict(0) == "SAFE"

    def test_score_19_is_safe(self):
        assert score_to_verdict(19) == "SAFE"

    def test_score_20_is_low_risk(self):
        assert score_to_verdict(20) == "LOW RISK"

    def test_score_39_is_low_risk(self):
        assert score_to_verdict(39) == "LOW RISK"

    def test_score_40_is_suspicious(self):
        assert score_to_verdict(40) == "SUSPICIOUS"

    def test_score_59_is_suspicious(self):
        assert score_to_verdict(59) == "SUSPICIOUS"

    def test_score_60_is_high_risk(self):
        assert score_to_verdict(60) == "HIGH RISK"

    def test_score_79_is_high_risk(self):
        assert score_to_verdict(79) == "HIGH RISK"

    def test_score_80_is_malicious(self):
        assert score_to_verdict(80) == "MALICIOUS"

    def test_score_100_is_malicious(self):
        assert score_to_verdict(100) == "MALICIOUS"


# ------------------------------------------------------------------ #
# calculate_risk tests
# ------------------------------------------------------------------ #

class TestCalculateRisk:

    def test_no_indicators_gives_safe(self):
        """All-False indicators should yield score 0 and SAFE verdict."""
        result = calculate_risk({}, scan_type="URL")
        assert result["score"] == 0
        assert result["verdict"] == "SAFE"
        assert result["reasons"] == []

    def test_http_only_is_low_risk(self):
        """HTTP without HTTPS (15 pts) should give LOW RISK."""
        indicators = {"is_http": True}
        result = calculate_risk(indicators, scan_type="URL")
        assert result["score"] == 15
        assert result["verdict"] == "SAFE"  # 15 < 20

    def test_ip_host_flag(self):
        """IP host indicator contributes 25 points."""
        indicators = {"is_ip_host": True}
        result = calculate_risk(indicators, scan_type="URL")
        assert result["score"] == 25
        assert result["verdict"] == "LOW RISK"

    def test_multiple_flags_accumulate(self):
        """Multiple triggered rules should sum their weights."""
        indicators = {
            "is_ip_host": True,          # 25
            "has_suspicious_keyword": True,  # 20
        }
        result = calculate_risk(indicators, scan_type="URL")
        assert result["score"] == 45
        assert result["verdict"] == "SUSPICIOUS"

    def test_score_capped_at_100(self):
        """Score must never exceed 100."""
        # Trigger every URL rule
        all_true = {
            "is_ip_host": True,
            "has_suspicious_keyword": True,
            "is_http": True,
            "has_punycode": True,
            "excessive_subdomains": True,
            "has_credentials": True,
            "has_at_symbol": True,
            "has_double_slash": True,
            "url_very_long": True,
            "excessive_encoding": True,
            "suspicious_tld": True,
            "has_redirect_indicator": True,
            "non_standard_port": True,
            "missing_dns": True,
            "url_long": True,
            "ftp_scheme": True,
        }
        result = calculate_risk(all_true, scan_type="URL")
        assert result["score"] <= 100
        assert result["verdict"] == "MALICIOUS"

    def test_external_score_adds_points(self):
        """External score contribution should be added to base score."""
        indicators = {"is_http": True}   # 15 base
        result = calculate_risk(indicators, scan_type="URL", external_score=10,
                                external_reasons=["+10  External API flag"])
        assert result["score"] == 25   # 15 + 10
        assert "+10  External API flag" in result["reasons"]

    def test_external_score_capped_at_50(self):
        """External score contribution must not exceed 50 points."""
        indicators = {}
        result = calculate_risk(indicators, scan_type="URL", external_score=999)
        assert result["score"] <= 50

    def test_ip_rule_tor_exit(self):
        """Tor exit node flag should score 30 points in IP mode → LOW RISK band."""
        indicators = {"is_tor_exit": True}
        result = calculate_risk(indicators, scan_type="IPv4")
        assert result["score"] == 30
        assert result["verdict"] == "LOW RISK"

    def test_deterministic_same_input(self):
        """Same indicators must produce same score every time."""
        indicators = {"is_ip_host": True, "excessive_subdomains": True}
        r1 = calculate_risk(indicators, scan_type="URL")
        r2 = calculate_risk(indicators, scan_type="URL")
        assert r1["score"] == r2["score"]
        assert r1["verdict"] == r2["verdict"]

    def test_recommendation_present(self):
        """Result must always include a recommendation string."""
        result = calculate_risk({}, scan_type="URL")
        assert "recommendation" in result
        assert isinstance(result["recommendation"], str)
        assert len(result["recommendation"]) > 0

    def test_detail_table_present(self):
        """detail_table list must always be returned."""
        result = calculate_risk({}, scan_type="URL")
        assert "detail_table" in result
        assert isinstance(result["detail_table"], list)
