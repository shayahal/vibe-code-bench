"""Tests for utility functions."""

import pytest

from vibe_code_bench.red_team_agent.utils import (
    generate_sql_injection_payloads,
    generate_xss_payloads,
    generate_path_traversal_payloads,
    detect_csrf_token,
    classify_severity,
    get_owasp_category,
    is_api_endpoint,
)


class TestPayloadGeneration:
    """Test payload generation functions."""

    def test_generate_sql_injection_payloads(self):
        """Test SQL injection payload generation."""
        payloads = generate_sql_injection_payloads()
        assert len(payloads) > 0
        assert "' OR '1'='1" in payloads

    def test_generate_xss_payloads(self):
        """Test XSS payload generation."""
        payloads = generate_xss_payloads()
        assert len(payloads) > 0
        assert "<script>alert('XSS')</script>" in payloads

    def test_generate_path_traversal_payloads(self):
        """Test path traversal payload generation."""
        payloads = generate_path_traversal_payloads()
        assert len(payloads) > 0
        assert "../../../etc/passwd" in payloads


class TestCSRFDetection:
    """Test CSRF token detection."""

    def test_detect_csrf_token_present(self):
        """Test detecting CSRF token in HTML."""
        html = '<form><input type="hidden" name="csrf_token" value="abc123"></form>'
        assert detect_csrf_token(html) is True

    def test_detect_csrf_token_absent(self):
        """Test detecting absence of CSRF token."""
        html = "<form><input type='text' name='username'></form>"
        assert detect_csrf_token(html) is False


class TestSeverityClassification:
    """Test severity classification."""

    def test_classify_critical(self):
        """Test classifying critical severity."""
        assert classify_severity("SQL Injection") == "Critical"
        assert classify_severity("SQLi") == "Critical"

    def test_classify_high(self):
        """Test classifying high severity."""
        assert classify_severity("XSS") == "High"
        assert classify_severity("CSRF") == "High"

    def test_classify_medium(self):
        """Test classifying medium severity."""
        assert classify_severity("Information Disclosure") == "Medium"

    def test_classify_low(self):
        """Test classifying low severity."""
        assert classify_severity("Unknown") == "Low"


class TestOWASPCategory:
    """Test OWASP category mapping."""

    def test_sql_injection_category(self):
        """Test SQL injection OWASP category."""
        category = get_owasp_category("SQL Injection")
        assert "Injection" in category

    def test_xss_category(self):
        """Test XSS OWASP category."""
        category = get_owasp_category("XSS")
        assert "Injection" in category


class TestAPIEndpointDetection:
    """Test API endpoint detection."""

    def test_is_api_endpoint(self):
        """Test detecting API endpoints."""
        assert is_api_endpoint("https://example.com/api/users") is True
        assert is_api_endpoint("https://example.com/v1/data") is True
        assert is_api_endpoint("https://example.com/page") is False
