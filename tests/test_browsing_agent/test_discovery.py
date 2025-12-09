"""Tests for discovery engine."""

import pytest
from unittest.mock import Mock, patch

from vibe_code_bench.browsing_agent.discovery import DiscoveryEngine


class TestDiscoveryEngine:
    """Test DiscoveryEngine class."""

    def test_normalize_url(self):
        """Test URL normalization."""
        engine = DiscoveryEngine()
        url = "https://example.com/page"
        normalized = engine.normalize_url(url)
        assert normalized.startswith("https://")
        assert "example.com" in normalized

    def test_normalize_url_with_base(self):
        """Test URL normalization with base URL."""
        engine = DiscoveryEngine()
        base_url = "https://example.com"
        relative_url = "/page"
        normalized = engine.normalize_url(relative_url, base_url)
        assert normalized == "https://example.com/page"

    @patch("vibe_code_bench.browsing_agent.discovery.requests.get")
    def test_check_sitemap_not_found(self, mock_get):
        """Test sitemap check when not found."""
        mock_get.return_value.status_code = 404
        engine = DiscoveryEngine()
        urls = engine.check_sitemap("https://example.com")
        assert urls == []

    @patch("vibe_code_bench.browsing_agent.discovery.requests.get")
    def test_parse_robots_not_found(self, mock_get):
        """Test robots.txt parsing when not found."""
        mock_get.return_value.status_code = 404
        engine = DiscoveryEngine()
        result = engine.parse_robots("https://example.com")
        assert isinstance(result, dict)
        assert "allowed_paths" in result

    def test_extract_links(self):
        """Test link extraction from HTML."""
        engine = DiscoveryEngine()
        html = '<html><body><a href="/page1">Link 1</a><a href="https://example.com/page2">Link 2</a></body></html>'
        base_url = "https://example.com"
        links = engine.extract_links(html, base_url)
        assert len(links) > 0
        assert any("page1" in link or "page2" in link for link in links)

    def test_mark_visited(self):
        """Test marking URLs as visited."""
        engine = DiscoveryEngine()
        url = "https://example.com/page"
        engine.mark_visited(url)
        assert engine.is_visited(url)

    def test_is_non_html_content(self):
        """Test non-HTML content detection."""
        engine = DiscoveryEngine()
        assert engine._is_non_html_content("https://example.com/image.jpg")
        assert engine._is_non_html_content("https://example.com/file.pdf")
        assert not engine._is_non_html_content("https://example.com/page.html")
        assert not engine._is_non_html_content("https://example.com/page")
