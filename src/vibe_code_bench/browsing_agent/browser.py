"""Browser automation module using LangChain Anchor Browser tools."""

import logging
import os
from typing import Dict, Optional, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import httpx

logger = logging.getLogger(__name__)

try:
    from langchain_anchorbrowser import (
        AnchorContentTool,
        AnchorScreenshotTool,
        SimpleAnchorWebTaskTool,
    )
    ANCHOR_BROWSER_AVAILABLE = True
except ImportError as e:
    ANCHOR_BROWSER_AVAILABLE = False
    raise ImportError(
        "langchain-anchorbrowser is required. "
        "Install with: pip install langchain-anchorbrowser"
    ) from e


class BrowserWrapper:
    """Browser wrapper for page fetching with Anchor Browser tools."""

    def __init__(self, headless: bool = True, timeout: int = 30000, enable_javascript: bool = True):
        """
        Initialize browser wrapper.

        Args:
            headless: Run browser in headless mode (not used with Anchor Browser, kept for compatibility)
            timeout: Page load timeout in milliseconds
            enable_javascript: Whether to enable JavaScript rendering (requires Anchor Browser)
        
        Raises:
            ImportError: If langchain-anchorbrowser is not installed when enable_javascript=True
            ValueError: If ANCHORBROWSER_API_KEY is not set when enable_javascript=True
            RuntimeError: If Anchor Browser initialization fails when enable_javascript=True
        """
        self.headless = headless
        self.timeout = timeout / 1000.0  # Convert to seconds for httpx
        self.enable_javascript = enable_javascript
        
        if enable_javascript:
            if not ANCHOR_BROWSER_AVAILABLE:
                raise ImportError(
                    "langchain-anchorbrowser is required when enable_javascript=True. "
                    "Install with: pip install langchain-anchorbrowser"
                )
            
            # Check for API key
            api_key = os.environ.get("ANCHORBROWSER_API_KEY")
            if not api_key:
                raise ValueError(
                    "ANCHORBROWSER_API_KEY environment variable is required when enable_javascript=True. "
                    "Set it in your .env file or environment."
                )
            
            try:
                # Initialize Anchor Browser tools
                self.content_tool = AnchorContentTool()
                self.screenshot_tool = AnchorScreenshotTool()
                self.web_task_tool = SimpleAnchorWebTaskTool()
                self.use_anchor_browser = True
                logger.info("Using Anchor Browser tools for page fetching")
            except Exception as e:
                raise RuntimeError(
                    f"Failed to initialize Anchor Browser tools: {e}. "
                    "Ensure ANCHORBROWSER_API_KEY is valid and langchain-anchorbrowser is properly installed."
                ) from e
        else:
            # JavaScript disabled - not supported, raise error
            raise ValueError(
                "enable_javascript=False is not supported. "
                "Anchor Browser is required for page fetching. Set enable_javascript=True."
            )

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def start(self):
        """Start browser (no-op for Anchor Browser, kept for compatibility)."""
        # Anchor Browser tools don't require explicit startup
        pass

    def close(self):
        """Close browser and cleanup resources."""
        if not self.use_anchor_browser and hasattr(self, 'client'):
            self.client.close()
    
    def fetch_page(self, url: str, wait_for: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch a page and return its content using Anchor Browser tools or httpx fallback.

        Args:
            url: URL to fetch
            wait_for: Optional selector or condition to wait for (not used with Anchor Browser)

        Returns:
            Dictionary with HTML content, status code, and metadata
        """
        if not self.use_anchor_browser:
            raise RuntimeError(
                "Anchor Browser is not initialized. "
                "Ensure langchain-anchorbrowser is installed and ANCHORBROWSER_API_KEY is set."
            )
        
        try:
            # Use AnchorContentTool to fetch page content
            result = self.content_tool.invoke({"url": url, "format": "html"})
            
            # Parse the HTML to extract metadata
            html = result if isinstance(result, str) else result.get("content", "")
            
            # Parse HTML to extract title and meta description
            soup = BeautifulSoup(html, "html.parser")
            title = None
            meta_description = None
            
            title_tag = soup.find("title")
            if title_tag:
                title = title_tag.get_text(strip=True)
            
            meta_desc_tag = soup.find("meta", attrs={"name": "description"})
            if meta_desc_tag:
                meta_description = meta_desc_tag.get("content")
            
            # Try to get status code from result if available
            status_code = None
            if isinstance(result, dict):
                status_code = result.get("status_code", 200)
            
            return {
                "html": html,
                "url": url,
                "status_code": status_code or 200,
                "title": title,
                "meta_description": meta_description,
                "success": True,
            }

        except Exception as e:
            raise RuntimeError(
                f"Failed to fetch {url} with Anchor Browser: {e}. "
                "Ensure ANCHORBROWSER_API_KEY is valid and the service is accessible."
            ) from e

    def get_cookies(self) -> list:
        """Get all cookies (not supported by Anchor Browser, returns empty list for compatibility)."""
        # Anchor Browser tools don't expose cookie management
        return []

    def add_cookies(self, cookies: list):
        """Add cookies (not supported by Anchor Browser, kept for compatibility)."""
        # Anchor Browser tools don't expose cookie management
        logger.warning("Cookie management not supported by Anchor Browser tools")

    def fill_form(self, url: str, form_data: Dict[str, str], submit: bool = True) -> Dict[str, Any]:
        """
        Fill and optionally submit a form on a page using Anchor Browser WebTaskTool.

        Args:
            url: URL of the page with the form
            form_data: Dictionary mapping field names to values
            submit: Whether to submit the form after filling

        Returns:
            Dictionary with result information
        """
        try:
            # Build prompt for form filling
            form_fields = ", ".join([f"{k}: {v}" for k, v in form_data.items()])
            action = "and submit" if submit else "but do not submit"
            prompt = f"Fill the form fields with the following values: {form_fields}, {action} the form."

            # Use SimpleAnchorWebTaskTool to fill and submit form
            result = self.web_task_tool.invoke({
                "url": url,
                "prompt": prompt,
            })

            # Parse result
            if isinstance(result, dict):
                html = result.get("html", result.get("content", ""))
                final_url = result.get("url", url)
            else:
                html = str(result)
                final_url = url

            return {
                "success": True,
                "final_url": final_url,
                "html": html,
                "cookies": [],  # Anchor Browser doesn't expose cookies
            }

        except Exception as e:
            raise RuntimeError(
                f"Failed to fill form on {url} with Anchor Browser: {e}. "
                "Ensure ANCHORBROWSER_API_KEY is valid and the form is accessible."
            ) from e
