"""Data models for the browsing agent."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


@dataclass
class PageInfo:
    """Information about a discovered page."""

    url: str
    title: Optional[str] = None
    status_code: Optional[int] = None
    discovered_via: Optional[str] = None  # "sitemap", "link_crawl", "navigation"
    links: List[str] = field(default_factory=list)
    has_forms: bool = False
    requires_auth: bool = False
    meta_description: Optional[str] = None
    page_type: Optional[str] = None  # "homepage", "product", "blog", etc.
    forms: List[Dict[str, Any]] = field(default_factory=list)
    navigation_links: List[str] = field(default_factory=list)
    content_links: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "url": self.url,
            "title": self.title,
            "status_code": self.status_code,
            "discovered_via": self.discovered_via,
            "links": self.links,
            "has_forms": self.has_forms,
            "requires_auth": self.requires_auth,
            "meta_description": self.meta_description,
            "page_type": self.page_type,
            "forms": self.forms,
            "navigation_links": self.navigation_links,
            "content_links": self.content_links,
        }


@dataclass
class DiscoveryResult:
    """Result of a website discovery operation."""

    base_url: str
    discovered_at: str
    total_pages: int
    authentication_required: bool
    pages: List[PageInfo]
    sitemap_used: bool = False
    robots_respected: bool = True
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "base_url": self.base_url,
            "discovered_at": self.discovered_at,
            "total_pages": self.total_pages,
            "authentication_required": self.authentication_required,
            "sitemap_used": self.sitemap_used,
            "robots_respected": self.robots_respected,
            "pages": [page.to_dict() for page in self.pages],
            "errors": self.errors,
        }
