"""Tests for data models."""

import pytest

from vibe_code_bench.browsing_agent.models import PageInfo, DiscoveryResult


class TestPageInfo:
    """Test PageInfo model."""

    def test_page_info_creation(self):
        """Test creating PageInfo."""
        page = PageInfo(
            url="https://example.com/page",
            title="Test Page",
            status_code=200,
        )
        assert page.url == "https://example.com/page"
        assert page.title == "Test Page"
        assert page.status_code == 200

    def test_page_info_to_dict(self):
        """Test converting PageInfo to dict."""
        page = PageInfo(
            url="https://example.com/page",
            title="Test Page",
            links=["/page1", "/page2"],
        )
        page_dict = page.to_dict()
        assert isinstance(page_dict, dict)
        assert page_dict["url"] == "https://example.com/page"
        assert len(page_dict["links"]) == 2


class TestDiscoveryResult:
    """Test DiscoveryResult model."""

    def test_discovery_result_creation(self):
        """Test creating DiscoveryResult."""
        pages = [
            PageInfo(url="https://example.com/page1"),
            PageInfo(url="https://example.com/page2"),
        ]
        result = DiscoveryResult(
            base_url="https://example.com",
            discovered_at="2024-01-01T00:00:00Z",
            total_pages=2,
            authentication_required=False,
            pages=pages,
        )
        assert result.base_url == "https://example.com"
        assert result.total_pages == 2
        assert len(result.pages) == 2

    def test_discovery_result_to_dict(self):
        """Test converting DiscoveryResult to dict."""
        pages = [PageInfo(url="https://example.com/page1")]
        result = DiscoveryResult(
            base_url="https://example.com",
            discovered_at="2024-01-01T00:00:00Z",
            total_pages=1,
            authentication_required=False,
            pages=pages,
        )
        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict["base_url"] == "https://example.com"
        assert len(result_dict["pages"]) == 1
