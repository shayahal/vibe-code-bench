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
except ImportError:
    ANCHOR_BROWSER_AVAILABLE = False
    logger.warning(
        "langchain-anchorbrowser not installed. Using httpx fallback for page fetching. "
        "Install with: pip install langchain-anchorbrowser for JavaScript rendering support."
    )


class BrowserWrapper:
    """Browser wrapper for page fetching with Anchor Browser tools (or httpx fallback)."""

    def __init__(self, headless: bool = True, timeout: int = 30000):
        """
        Initialize browser wrapper.

        Args:
            headless: Run browser in headless mode (not used with Anchor Browser, kept for compatibility)
            timeout: Page load timeout in milliseconds
        """
        self.headless = headless
        self.timeout = timeout / 1000.0  # Convert to seconds for httpx
        self.use_anchor_browser = False
        
        if ANCHOR_BROWSER_AVAILABLE:
            # Check for API key
            if os.environ.get("ANCHORBROWSER_API_KEY"):
                try:
                    # Initialize Anchor Browser tools
                    self.content_tool = AnchorContentTool()
                    self.screenshot_tool = AnchorScreenshotTool()
                    self.web_task_tool = SimpleAnchorWebTaskTool()
                    self.use_anchor_browser = True
                    logger.info("Using Anchor Browser tools for page fetching")
                except Exception as e:
                    logger.warning(f"Failed to initialize Anchor Browser tools: {e}. Using httpx fallback.")
            else:
                logger.warning(
                    "ANCHORBROWSER_API_KEY not found in environment. "
                    "Using httpx fallback (no JavaScript rendering)."
                )
        
        if not self.use_anchor_browser:
            # Use httpx as fallback
            self.client = httpx.Client(timeout=self.timeout, follow_redirects=True)
            logger.info("Using httpx for page fetching (no JavaScript rendering)")

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
        # Try Anchor Browser first if available
        if self.use_anchor_browser:
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
                logger.warning(f"Error fetching {url} with Anchor Browser: {e}. Falling back to httpx.")
                # Fall through to httpx fallback
        
        # Use httpx fallback (either because Anchor Browser not available or it failed)
        if not hasattr(self, 'client'):
            # Initialize httpx client if not already done
            self.client = httpx.Client(timeout=self.timeout, follow_redirects=True)
        
        try:
            response = self.client.get(url)
            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            
            title = None
            title_tag = soup.find("title")
            if title_tag:
                title = title_tag.get_text(strip=True)
            
            meta_description = None
            meta_desc_tag = soup.find("meta", attrs={"name": "description"})
            if meta_desc_tag:
                meta_description = meta_desc_tag.get("content")
            
            return {
                "html": html,
                "url": str(response.url),
                "status_code": response.status_code,
                "title": title,
                "meta_description": meta_description,
                "success": True,
            }
        except Exception as e:
            logger.error(f"Error fetching {url} with httpx: {e}")
            return {
                "html": "",
                "url": url,
                "status_code": None,
                "title": None,
                "meta_description": None,
                "success": False,
                "error": str(e),
            }

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
            logger.error(f"Error filling form on {url} with Anchor Browser: {e}")
            return {
                "success": False,
                "error": str(e),
            }
