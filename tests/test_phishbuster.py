"""
PhishBuster — Unit Tests
Run with: pytest tests/
"""
import pytest
from phishbuster.modules.url_analyzer import analyze_url
from phishbuster.scoring.risk_engine  import compute_score


class TestURLAnalyzer:
    def test_https_detected(self):
        f = analyze_url("https://google.com")
        assert f["uses_https"] is True

    def test_http_detected(self):
        f = analyze_url("http://google.com")
        assert f["uses_https"] is False

    def test_ip_address_detected(self):
        f = analyze_url("http://192.168.1.1/login")
        assert f["has_ip_address"] is True

    def test_at_symbol_detected(self):
        f = analyze_url("http://legit.com@evil.com")
        assert f["has_at_symbol"] is True

    def test_suspicious_keywords(self):
        f = analyze_url("http://secure-login-verify.com/account/update")
        assert f["suspicious_keyword_count"] >= 3

    def test_url_shortener_detected(self):
        f = analyze_url("http://bit.ly/abc123")
        assert f["is_shortened"] is True

    def test_long_url(self):
        f = analyze_url("http://example.com/" + "a" * 80)
        assert f["is_long_url"] is True

    def test_clean_url(self):
        f = analyze_url("https://github.com")
        assert f["suspicious_keyword_count"] == 0
        assert f["has_at_symbol"] is False
        assert f["has_ip_address"] is False


class TestScoringEngine:
    def test_blacklisted_url_is_phishing(self):
        features = {"blacklisted": True, "uses_https": False}
        result = compute_score(features)
        assert result["verdict"] == "Phishing"
        assert result["score"] >= 8

    def test_clean_url_is_safe(self):
        features = {
            "uses_https":        True,
            "ssl_valid":         True,
            "dns_resolves":      True,
            "domain_is_new":     False,
            "has_ip_address":    False,
            "suspicious_keyword_count": 0,
            "blacklisted":       False,
        }
        result = compute_score(features)
        assert result["verdict"] == "Safe"

    def test_score_capped_at_10(self):
        features = {
            "blacklisted":              True,
            "has_ip_address":           True,
            "has_at_symbol":            True,
            "has_obfuscated_js":        True,
            "domain_is_new":            True,
            "ml_phishing_probability":  0.99,
        }
        result = compute_score(features)
        assert result["score"] <= 10.0

    def test_score_not_negative(self):
        features = {
            "uses_https":   True,
            "ssl_valid":    True,
            "dns_resolves": True,
        }
        result = compute_score(features)
        assert result["score"] >= 0.0
