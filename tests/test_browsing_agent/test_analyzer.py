"""Tests for page analyzer."""

import pytest

from vibe_code_bench.browsing_agent.analyzer import PageAnalyzer


class TestPageAnalyzer:
    """Test PageAnalyzer class."""

    def test_analyze_navigation(self):
        """Test navigation analysis."""
        analyzer = PageAnalyzer()
        html = '<html><body><nav><a href="/page1">Nav 1</a></nav><a href="/content1">Content 1</a></body></html>'
        base_url = "https://example.com"
        result = analyzer.analyze_navigation(html, base_url)
        assert isinstance(result, dict)
        assert "navigation_links" in result
        assert "content_links" in result

    def test_extract_forms(self):
        """Test form extraction."""
        analyzer = PageAnalyzer()
        html = '<html><body><form action="/submit" method="post"><input name="username" type="text"><input name="password" type="password"></form></body></html>'
        forms = analyzer.extract_forms(html)
        assert len(forms) > 0
        assert forms[0]["action"] == "/submit"
        assert len(forms[0]["fields"]) > 0

    def test_classify_page_type(self):
        """Test page type classification."""
        analyzer = PageAnalyzer()
        html = '<html><head><title>Homepage</title></head><body></body></html>'
        assert analyzer.classify_page_type(html, "https://example.com/") == "homepage"
        assert analyzer.classify_page_type(html, "https://example.com/product/123") == "product"
        assert analyzer.classify_page_type(html, "https://example.com/blog/post") == "blog"

    def test_detect_authentication_required(self):
        """Test authentication detection."""
        analyzer = PageAnalyzer()
        html = '<html><body>Please log in to continue</body></html>'
        assert analyzer.detect_authentication_required(html) is True

        html2 = '<html><body>Welcome to our site</body></html>'
        assert analyzer.detect_authentication_required(html2) is False

    def test_extract_metadata(self):
        """Test metadata extraction."""
        analyzer = PageAnalyzer()
        html = '<html><head><title>Test Page</title><meta name="description" content="Test description"></head><body></body></html>'
        metadata = analyzer.extract_metadata(html)
        assert metadata["title"] == "Test Page"
        assert metadata["meta_description"] == "Test description"
