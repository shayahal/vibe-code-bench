"""Page analyzer for extracting metadata, links, forms, and navigation patterns."""

import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class PageAnalyzer:
    """Analyzer for extracting page information and patterns."""

    def analyze_navigation(self, html: str, base_url: str) -> Dict[str, Any]:
        """
        Analyze page structure and identify navigation patterns.

        Args:
            html: HTML content
            base_url: Base URL of the page

        Returns:
            Dictionary with navigation analysis
        """
        try:
            soup = BeautifulSoup(html, "lxml")
            result = {
                "navigation_links": [],
                "content_links": [],
                "has_nav_menu": False,
                "nav_selectors": [],
            }

            # Find navigation elements
            nav_selectors = [
                "nav",
                'div[class*="nav"]',
                'div[class*="menu"]',
                'ul[class*="nav"]',
                'ul[class*="menu"]',
                "header",
                "footer",
            ]

            nav_links = set()
            for selector in nav_selectors:
                try:
                    elements = soup.select(selector)
                    for element in elements:
                        links = element.find_all("a", href=True)
                        for link in links:
                            href = link.get("href", "")
                            if href:
                                nav_links.add(href)
                        if links:
                            result["has_nav_menu"] = True
                            result["nav_selectors"].append(selector)
                except Exception:
                    continue

            # Extract all links
            all_links = []
            for tag in soup.find_all("a", href=True):
                href = tag.get("href", "")
                if href:
                    all_links.append(href)

            # Classify links
            nav_link_list = list(nav_links)
            content_links = [link for link in all_links if link not in nav_links]

            result["navigation_links"] = nav_link_list[:50]  # Limit to 50
            result["content_links"] = content_links[:100]  # Limit to 100

            return result

        except Exception as e:
            logger.error(f"Error analyzing navigation: {e}")
            return {
                "navigation_links": [],
                "content_links": [],
                "has_nav_menu": False,
                "nav_selectors": [],
            }

    def extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """
        Extract all forms from HTML.

        Args:
            html: HTML content

        Returns:
            List of form information dictionaries
        """
        forms = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for form in soup.find_all("form"):
                form_info = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").lower(),
                    "fields": [],
                }

                # Extract input fields
                for input_field in form.find_all(["input", "textarea", "select"]):
                    field_info = {
                        "name": input_field.get("name", ""),
                        "type": input_field.get("type", "text"),
                        "required": input_field.has_attr("required"),
                    }
                    if input_field.name == "select":
                        options = [opt.get("value", "") for opt in input_field.find_all("option")]
                        field_info["options"] = options
                    form_info["fields"].append(field_info)

                forms.append(form_info)

        except Exception as e:
            logger.error(f"Error extracting forms: {e}")

        return forms

    def classify_page_type(self, html: str, url: str) -> Optional[str]:
        """
        Classify the type of page.

        Args:
            html: HTML content
            url: URL of the page

        Returns:
            Page type classification
        """
        try:
            soup = BeautifulSoup(html, "lxml")
            url_lower = url.lower()
            path = urlparse(url).path.lower()

            # Check URL patterns
            if path == "/" or path == "":
                return "homepage"
            if "/product" in path or "/item" in path or "/p/" in path:
                return "product"
            if "/blog" in path or "/post" in path or "/article" in path:
                return "blog"
            if "/category" in path or "/cat" in path:
                return "category"
            if "/search" in path or "?q=" in url_lower or "?search=" in url_lower:
                return "search"
            if "/login" in path or "/signin" in path or "/auth" in path:
                return "login"
            if "/cart" in path or "/checkout" in path:
                return "checkout"
            if "/account" in path or "/profile" in path or "/user" in path:
                return "account"
            if "/contact" in path:
                return "contact"
            if "/about" in path:
                return "about"

            # Check HTML patterns
            title = soup.find("title")
            if title:
                title_text = title.get_text().lower()
                if "product" in title_text or "buy" in title_text:
                    return "product"
                if "blog" in title_text or "post" in title_text:
                    return "blog"

            # Check for common class names
            if soup.find(class_=lambda x: x and ("product" in str(x).lower() or "item" in str(x).lower())):
                return "product"
            if soup.find(class_=lambda x: x and "blog" in str(x).lower()):
                return "blog"

            return "content"

        except Exception as e:
            logger.debug(f"Error classifying page type: {e}")
            return None

    def detect_authentication_required(self, html: str, status_code: Optional[int] = None) -> bool:
        """
        Detect if page requires authentication.

        Args:
            html: HTML content
            status_code: HTTP status code

        Returns:
            True if authentication appears to be required
        """
        # Check status code
        if status_code == 401 or status_code == 403:
            return True

        # Check HTML content
        html_lower = html.lower()
        auth_indicators = [
            "please log in",
            "login required",
            "authentication required",
            "sign in to continue",
            "access denied",
            "unauthorized",
            "forbidden",
        ]

        return any(indicator in html_lower for indicator in auth_indicators)

    def extract_metadata(self, html: str) -> Dict[str, Any]:
        """
        Extract page metadata.

        Args:
            html: HTML content

        Returns:
            Dictionary with metadata
        """
        metadata = {
            "title": None,
            "meta_description": None,
            "meta_keywords": None,
            "og_title": None,
            "og_description": None,
            "og_image": None,
        }

        try:
            soup = BeautifulSoup(html, "lxml")

            # Title
            title_tag = soup.find("title")
            if title_tag:
                metadata["title"] = title_tag.get_text().strip()

            # Meta description
            meta_desc = soup.find("meta", attrs={"name": "description"})
            if meta_desc:
                metadata["meta_description"] = meta_desc.get("content", "").strip()

            # Meta keywords
            meta_keywords = soup.find("meta", attrs={"name": "keywords"})
            if meta_keywords:
                metadata["meta_keywords"] = meta_keywords.get("content", "").strip()

            # Open Graph tags
            og_title = soup.find("meta", attrs={"property": "og:title"})
            if og_title:
                metadata["og_title"] = og_title.get("content", "").strip()

            og_desc = soup.find("meta", attrs={"property": "og:description"})
            if og_desc:
                metadata["og_description"] = og_desc.get("content", "").strip()

            og_image = soup.find("meta", attrs={"property": "og:image"})
            if og_image:
                metadata["og_image"] = og_image.get("content", "").strip()

        except Exception as e:
            logger.debug(f"Error extracting metadata: {e}")

        return metadata
