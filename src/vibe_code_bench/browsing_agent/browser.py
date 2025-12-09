"""Browser automation module using Playwright."""

import logging
from typing import Dict, Optional, Any
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page, TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger(__name__)


class BrowserWrapper:
    """Playwright browser wrapper for page fetching and JavaScript rendering."""

    def __init__(self, headless: bool = True, timeout: int = 30000):
        """
        Initialize browser wrapper.

        Args:
            headless: Run browser in headless mode
            timeout: Page load timeout in milliseconds
        """
        self.headless = headless
        self.timeout = timeout
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def start(self):
        """Start browser and create context."""
        if self.playwright is None:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(headless=self.headless)
            self.context = self.browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )

    def close(self):
        """Close browser and cleanup."""
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
            self.playwright = None

    def fetch_page(self, url: str, wait_for: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch a page and return its content.

        Args:
            url: URL to fetch
            wait_for: Optional selector or condition to wait for

        Returns:
            Dictionary with HTML content, status code, and metadata
        """
        if not self.context:
            self.start()

        try:
            page: Page = self.context.new_page()
            response = page.goto(url, wait_until="networkidle", timeout=self.timeout)

            if wait_for:
                page.wait_for_selector(wait_for, timeout=5000)

            html = page.content()
            title = page.title()
            final_url = page.url

            # Extract meta description
            meta_description = None
            try:
                meta_element = page.query_selector('meta[name="description"]')
                if meta_element:
                    meta_description = meta_element.get_attribute("content")
            except Exception:
                pass

            status_code = response.status if response else None

            page.close()

            return {
                "html": html,
                "url": final_url,
                "status_code": status_code,
                "title": title,
                "meta_description": meta_description,
                "success": True,
            }

        except PlaywrightTimeoutError:
            logger.warning(f"Timeout fetching {url}")
            return {
                "html": "",
                "url": url,
                "status_code": None,
                "title": None,
                "meta_description": None,
                "success": False,
                "error": "timeout",
            }
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
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
        """Get all cookies from the current context."""
        if not self.context:
            return []
        return self.context.cookies()

    def add_cookies(self, cookies: list):
        """Add cookies to the browser context."""
        if self.context:
            self.context.add_cookies(cookies)

    def fill_form(self, url: str, form_data: Dict[str, str], submit: bool = True) -> Dict[str, Any]:
        """
        Fill and optionally submit a form on a page.

        Args:
            url: URL of the page with the form
            form_data: Dictionary mapping field names to values
            submit: Whether to submit the form after filling

        Returns:
            Dictionary with result information
        """
        if not self.context:
            self.start()

        try:
            page: Page = self.context.new_page()
            page.goto(url, wait_until="networkidle", timeout=self.timeout)

            # Fill form fields
            for field_name, value in form_data.items():
                try:
                    # Try multiple selectors
                    selectors = [
                        f'input[name="{field_name}"]',
                        f'input[id="{field_name}"]',
                        f'input[type="text"][name="{field_name}"]',
                        f'input[type="password"][name="{field_name}"]',
                    ]
                    filled = False
                    for selector in selectors:
                        try:
                            element = page.query_selector(selector)
                            if element:
                                element.fill(value)
                                filled = True
                                break
                        except Exception:
                            continue

                    if not filled:
                        logger.warning(f"Could not find form field: {field_name}")
                except Exception as e:
                    logger.warning(f"Error filling field {field_name}: {e}")

            if submit:
                # Try to find and click submit button
                submit_selectors = [
                    'button[type="submit"]',
                    'input[type="submit"]',
                    'button:has-text("Submit")',
                    'button:has-text("Login")',
                    'button:has-text("Sign in")',
                ]
                submitted = False
                for selector in submit_selectors:
                    try:
                        button = page.query_selector(selector)
                        if button:
                            button.click()
                            page.wait_for_load_state("networkidle", timeout=5000)
                            submitted = True
                            break
                    except Exception:
                        continue

                if not submitted:
                    # Try pressing Enter on the last filled field
                    page.keyboard.press("Enter")
                    page.wait_for_load_state("networkidle", timeout=5000)

            final_url = page.url
            html = page.content()
            cookies = self.context.cookies()

            page.close()

            return {
                "success": True,
                "final_url": final_url,
                "html": html,
                "cookies": cookies,
            }

        except Exception as e:
            logger.error(f"Error filling form on {url}: {e}")
            return {
                "success": False,
                "error": str(e),
            }
