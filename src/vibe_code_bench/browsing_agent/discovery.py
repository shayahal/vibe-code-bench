"""Discovery engine for sitemap, robots.txt, and link extraction."""

import logging
import re
from typing import List, Set, Dict, Optional, Any
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser
import xml.etree.ElementTree as ET

import requests
from bs4 import BeautifulSoup
from url_normalize import url_normalize

logger = logging.getLogger(__name__)


class DiscoveryEngine:
    """Engine for discovering pages via sitemap, robots.txt, and link crawling."""

    def __init__(self, respect_robots: bool = True):
        """
        Initialize discovery engine.

        Args:
            respect_robots: Whether to respect robots.txt rules
        """
        self.respect_robots = respect_robots
        self.robots_parser: Optional[RobotFileParser] = None
        self._visited_urls: Set[str] = set()

    def normalize_url(self, url: str, base_url: Optional[str] = None) -> str:
        """
        Normalize a URL.

        Args:
            url: URL to normalize
            base_url: Base URL for resolving relative URLs

        Returns:
            Normalized absolute URL
        """
        if base_url:
            url = urljoin(base_url, url)
        try:
            return url_normalize(url)
        except Exception as e:
            # Try basic normalization as fallback
            try:
                parsed = urlparse(url)
                normalized = urlunparse(
                    (
                        parsed.scheme.lower(),
                        parsed.netloc.lower(),
                        parsed.path,
                        parsed.params,
                        parsed.query,
                        "",  # Remove fragment
                    )
                )
                return normalized
            except Exception as e2:
                raise RuntimeError(f"Failed to normalize URL {url}: {e}, fallback also failed: {e2}") from e2

    def check_sitemap(self, base_url: str) -> List[str]:
        """
        Check for and parse sitemap.xml.

        Args:
            base_url: Base URL of the website

        Returns:
            List of URLs found in sitemap
        """
        urls = []
        sitemap_urls = [
            urljoin(base_url, "/sitemap.xml"),
            urljoin(base_url, "/sitemap_index.xml"),
        ]

        for sitemap_url in sitemap_urls:
            try:
                response = requests.get(sitemap_url, timeout=10)
                if response.status_code == 200:
                    # Check if it's a sitemap index
                    root = ET.fromstring(response.content)
                    namespace = {"sitemap": "http://www.sitemaps.org/schemas/sitemap/0.9"}

                    # Handle sitemap index
                    sitemapindex = root.find("sitemapindex", namespace)
                    if sitemapindex is not None:
                        for sitemap in sitemapindex.findall("sitemap", namespace):
                            loc = sitemap.find("loc", namespace)
                            if loc is not None:
                                nested_urls = self.check_sitemap(loc.text)
                                urls.extend(nested_urls)
                    else:
                        # Regular sitemap
                        for url_elem in root.findall(".//sitemap:url", namespace):
                            loc = url_elem.find("sitemap:loc", namespace)
                            if loc is not None:
                                urls.append(self.normalize_url(loc.text, base_url))
                        # Also try without namespace
                        for url_elem in root.findall(".//url"):
                            loc = url_elem.find("loc")
                            if loc is not None:
                                urls.append(self.normalize_url(loc.text, base_url))

                    logger.info(f"Found {len(urls)} URLs in sitemap: {sitemap_url}")
                    break

            except requests.RequestException as e:
                logger.debug(f"Could not fetch sitemap {sitemap_url}: {e}")
            except ET.ParseError as e:
                logger.debug(f"Could not parse sitemap {sitemap_url}: {e}")
            except Exception as e:
                logger.debug(f"Error processing sitemap {sitemap_url}: {e}")

        return list(set(urls))  # Deduplicate

    def parse_robots(self, base_url: str) -> Dict[str, Any]:
        """
        Parse robots.txt file.

        Args:
            base_url: Base URL of the website

        Returns:
            Dictionary with robots.txt information
        """
        robots_url = urljoin(base_url, "/robots.txt")
        result = {
            "allowed_paths": [],
            "disallowed_paths": [],
            "crawl_delay": None,
            "sitemap_urls": [],
        }

        try:
            response = requests.get(robots_url, timeout=10)
            if response.status_code == 200:
                self.robots_parser = RobotFileParser()
                self.robots_parser.set_url(robots_url)
                self.robots_parser.read()

                # Extract sitemap URLs
                for line in response.text.split("\n"):
                    line = line.strip()
                    if line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        result["sitemap_urls"].append(sitemap_url)

                # Extract crawl delay
                if hasattr(self.robots_parser, "crawl_delay"):
                    result["crawl_delay"] = self.robots_parser.crawl_delay("*")

                logger.info(f"Parsed robots.txt from {robots_url}")
            else:
                logger.debug(f"robots.txt not found at {robots_url}")

        except Exception as e:
            # robots.txt is optional, but if we try to parse it and fail, log and continue
            # Only raise if it's a critical error (not just missing file)
            if "404" not in str(e).lower() and "not found" not in str(e).lower():
                logger.warning(f"Error parsing robots.txt (non-critical, continuing): {e}")
            else:
                logger.debug(f"robots.txt not found or not accessible: {e}")

        return result

    def can_fetch(self, url: str, user_agent: str = "*") -> bool:
        """
        Check if URL can be fetched according to robots.txt.

        Args:
            url: URL to check
            user_agent: User agent string

        Returns:
            True if URL can be fetched
        """
        if not self.respect_robots or not self.robots_parser:
            return True
        return self.robots_parser.can_fetch(user_agent, url)

    def extract_links(self, html: str, base_url: str, same_domain_only: bool = True) -> List[str]:
        """
        Extract all links from HTML content.

        Args:
            html: HTML content
            base_url: Base URL for resolving relative URLs
            same_domain_only: If True, only return links from the same domain

        Returns:
            List of absolute URLs
        """
        links = []
        try:
            soup = BeautifulSoup(html, "lxml")
            base_parsed = urlparse(base_url)
            base_domain = base_parsed.netloc.lower()

            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                absolute_url = urljoin(base_url, href)
                parsed = urlparse(absolute_url)

                # Strictly filter by domain if same_domain_only is True
                if same_domain_only:
                    # Only include links from the exact same domain
                    if parsed.netloc.lower() != base_domain:
                        continue
                else:
                    # Only include links from the same domain or relative links
                    if parsed.netloc and parsed.netloc.lower() != base_domain:
                        continue

                normalized = self.normalize_url(absolute_url, base_url)
                # Filter out non-HTML content
                if not self._is_non_html_content(normalized):
                    links.append(normalized)

            # Also check for JavaScript-based links
            scripts = soup.find_all("script")
            for script in scripts:
                if script.string:
                    # Look for URL patterns in JavaScript
                    url_patterns = re.findall(
                        r"['\"](https?://[^'\"]+)['\"]|['\"](/[^'\"]+)['\"]", script.string
                    )
                    for match in url_patterns:
                        url = match[0] if match[0] else urljoin(base_url, match[1])
                        parsed = urlparse(url)
                        if parsed.netloc == base_parsed.netloc or not parsed.netloc:
                            normalized = self.normalize_url(url, base_url)
                            if not self._is_non_html_content(normalized):
                                links.append(normalized)

        except Exception as e:
            raise RuntimeError(f"Failed to extract links from HTML for {base_url}: {e}") from e

        return list(set(links))  # Deduplicate

    def _is_non_html_content(self, url: str) -> bool:
        """Check if URL points to non-HTML content."""
        non_html_extensions = [
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".svg",
            ".pdf",
            ".zip",
            ".tar",
            ".gz",
            ".css",
            ".js",
            ".json",
            ".xml",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
        ]
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in non_html_extensions)

    def mark_visited(self, url: str):
        """Mark a URL as visited."""
        normalized = self.normalize_url(url)
        self._visited_urls.add(normalized)

    def is_visited(self, url: str) -> bool:
        """Check if a URL has been visited."""
        normalized = self.normalize_url(url)
        return normalized in self._visited_urls

    def get_visited_count(self) -> int:
        """Get count of visited URLs."""
        return len(self._visited_urls)
