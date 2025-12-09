"""Tests for browser wrapper."""

import pytest
from unittest.mock import Mock, patch, MagicMock

from vibe_code_bench.browsing_agent.browser import BrowserWrapper


class TestBrowserWrapper:
    """Test BrowserWrapper class."""

    def test_browser_initialization(self):
        """Test browser initialization."""
        browser = BrowserWrapper(headless=True, timeout=30000)
        assert browser.headless is True
        assert browser.timeout == 30000

    @patch("vibe_code_bench.browsing_agent.browser.sync_playwright")
    def test_browser_start(self, mock_playwright):
        """Test starting browser."""
        mock_playwright_instance = MagicMock()
        mock_browser = MagicMock()
        mock_context = MagicMock()
        mock_playwright_instance.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = mock_context
        mock_playwright.return_value.start.return_value = mock_playwright_instance

        browser = BrowserWrapper()
        browser.start()
        assert browser.playwright is not None
        assert browser.browser is not None
        assert browser.context is not None

    def test_browser_context_manager(self):
        """Test browser as context manager."""
        with patch("vibe_code_bench.browsing_agent.browser.sync_playwright") as mock_playwright:
            mock_playwright_instance = MagicMock()
            mock_browser = MagicMock()
            mock_context = MagicMock()
            mock_playwright_instance.chromium.launch.return_value = mock_browser
            mock_browser.new_context.return_value = mock_context
            mock_playwright.return_value.start.return_value = mock_playwright_instance

            with BrowserWrapper() as browser:
                assert browser.playwright is not None
