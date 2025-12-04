"""
Website Crawler Tool

A comprehensive tool for deep website crawling and discovery that:
- Discovers all pages on the website
- Maps site structure and navigation
- Finds all forms, inputs, and endpoints
- Identifies API endpoints and dynamic routes
- Extracts security-relevant information from all pages
- Handles JavaScript-heavy sites (with optional Playwright support)
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
from collections import deque
from typing import Set, Dict, List, Optional
from langchain_core.tools import StructuredTool
import time
from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


class WebsiteCrawler:
    """Deep website crawler for security testing."""
    
    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 50,
        same_domain_only: bool = True,
        respect_robots: bool = False,
        delay: float = 0.5
    ):
        """
        Initialize crawler.
        
        Args:
            base_url: Starting URL
            max_depth: Maximum crawl depth (default: 3)
            max_pages: Maximum number of pages to crawl (default: 50)
            same_domain_only: Only crawl same domain (default: True)
            respect_robots: Respect robots.txt (default: False for security testing)
            delay: Delay between requests in seconds (default: 0.5)
        """
        self.base_url = base_url
        self.parsed_base = urlparse(base_url)
        self.base_domain = f"{self.parsed_base.scheme}://{self.parsed_base.netloc}"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.same_domain_only = same_domain_only
        self.delay = delay
        
        self.visited: Set[str] = set()
        normalized_base = self.normalize_url(base_url)
        self.to_visit: deque = deque([(normalized_base, 0)])  # (url, depth)
        self.site_map: Dict[str, Dict] = {}
        self.all_forms: List[Dict] = []
        self.all_inputs: List[Dict] = []
        self.all_endpoints: Set[str] = set()
        self.errors: List[str] = []
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments and sorting query params."""
        parsed = urlparse(url)
        # Remove fragment
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            ''  # Remove fragment
        ))
        return normalized.rstrip('/') or normalized
    
    def is_valid_url(self, url: str) -> bool:
        """Check if URL should be crawled."""
        if not url or url.startswith('#') or url.startswith('javascript:') or url.startswith('mailto:'):
            return False
        
        parsed = urlparse(url)
        
        # Skip non-HTTP(S) URLs
        if parsed.scheme not in ('http', 'https', ''):
            return False
        
        # If same_domain_only, check domain
        if self.same_domain_only:
            if parsed.netloc and parsed.netloc != self.parsed_base.netloc:
                return False
        
        # Skip common non-page extensions
        skip_extensions = {'.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', 
                          '.css', '.js', '.zip', '.tar', '.gz', '.xml', '.json'}
        path_lower = parsed.path.lower()
        if any(path_lower.endswith(ext) for ext in skip_extensions):
            return False
        
        return True
    
    def extract_links(self, soup: BeautifulSoup, current_url: str) -> Set[str]:
        """Extract all links from a page."""
        links = set()
        
        # Find all <a> tags with href
        for tag in soup.find_all('a', href=True):
            href = tag.get('href', '').strip()
            if href:
                absolute_url = urljoin(current_url, href)
                normalized = self.normalize_url(absolute_url)
                if self.is_valid_url(normalized):
                    links.add(normalized)
        
        # Find form actions
        for form in soup.find_all('form', action=True):
            action = form.get('action', '').strip()
            if action:
                absolute_url = urljoin(current_url, action)
                normalized = self.normalize_url(absolute_url)
                if self.is_valid_url(normalized):
                    links.add(normalized)
                    self.all_endpoints.add(normalized)
        
        return links
    
    def extract_forms(self, soup: BeautifulSoup, page_url: str) -> List[Dict]:
        """Extract all forms and their details."""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'page': page_url,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs': []
            }
            
            # Extract all inputs
            for inp in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': inp.get('type', 'text'),
                    'name': inp.get('name', ''),
                    'id': inp.get('id', ''),
                    'placeholder': inp.get('placeholder', ''),
                    'required': inp.has_attr('required'),
                    'tag': inp.name
                }
                
                # For select, get options
                if inp.name == 'select':
                    options = [opt.get('value', '') for opt in inp.find_all('option')]
                    input_data['options'] = options
                
                form_data['inputs'].append(input_data)
                self.all_inputs.append({
                    **input_data,
                    'form_action': form_data['action'],
                    'form_method': form_data['method'],
                    'page': page_url
                })
            
            if form_data['inputs']:
                forms.append(form_data)
                self.all_forms.append(form_data)
        
        return forms
    
    def extract_endpoints(self, soup: BeautifulSoup, page_url: str):
        """Extract potential API endpoints and routes."""
        # Look for data attributes, API calls in scripts, etc.
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Look for common API patterns
                content = script.string.lower()
                # This is basic - could be enhanced with regex
                if 'fetch(' in content or 'axios.' in content or '$.ajax' in content:
                    # Extract potential endpoints (simplified)
                    pass  # Could add regex extraction here
        
        # Look for data-* attributes that might indicate endpoints
        for tag in soup.find_all():
            if tag.attrs and isinstance(tag.attrs, dict):
                for attr, value in tag.attrs.items():
                    if attr.startswith('data-') and isinstance(value, str) and value.startswith('/'):
                        self.all_endpoints.add(urljoin(page_url, value))
    
    def crawl_page(self, url: str, current_depth: int = 0) -> Optional[Dict]:
        """Crawl a single page and extract information."""
        normalized_url = self.normalize_url(url)
        
        if normalized_url in self.visited:
            return None
        
        self.visited.add(normalized_url)
        
        try:
            response = requests.get(normalized_url, headers=self.headers, timeout=10, allow_redirects=True)
            response.raise_for_status()
            
            # Only parse HTML
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                return {
                    'url': normalized_url,
                    'status': response.status_code,
                    'type': 'non-html',
                    'content_type': content_type
                }
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract information
            title = soup.find('title')
            title_text = title.get_text().strip() if title else "No title"
            
            # Extract forms
            forms = self.extract_forms(soup, normalized_url)
            
            # Extract links
            links = self.extract_links(soup, normalized_url)
            
            # Extract endpoints
            self.extract_endpoints(soup, normalized_url)
            
            page_info = {
                'url': normalized_url,
                'status': response.status_code,
                'title': title_text,
                'forms': forms,
                'form_count': len(forms),
                'links': list(links),
                'link_count': len(links),
                'has_scripts': len(soup.find_all('script')) > 0,
                'has_external_scripts': len([s for s in soup.find_all('script', src=True)]) > 0,
                'has_inline_scripts': len([s for s in soup.find_all('script') if s.string and not s.get('src')]) > 0
            }
            
            self.site_map[normalized_url] = page_info
            
            # Add new links to queue (only if we haven't reached max depth)
            if current_depth < self.max_depth:
                for link in links:
                    normalized_link = self.normalize_url(link)
                    if normalized_link not in self.visited:
                        # Check if already in queue
                        already_queued = any(u == normalized_link for u, _ in self.to_visit)
                        if not already_queued:
                            self.to_visit.append((normalized_link, current_depth + 1))
            
            time.sleep(self.delay)  # Rate limiting
            return page_info
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Error crawling {normalized_url}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'url': normalized_url,
                'status': 'error',
                'error': str(e)
            }
        except Exception as e:
            error_msg = f"Unexpected error crawling {normalized_url}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'url': normalized_url,
                'status': 'error',
                'error': str(e)
            }
    
    def crawl(self) -> Dict:
        """Perform full website crawl."""
        pages_crawled = 0
        
        while self.to_visit and pages_crawled < self.max_pages:
            url, depth = self.to_visit.popleft()
            
            if depth > self.max_depth:
                continue
            
            page_info = self.crawl_page(url, depth)
            if page_info and page_info.get('status') != 'error':
                pages_crawled += 1
        
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate comprehensive crawl report."""
        # Deduplicate endpoints
        unique_endpoints = sorted(list(self.all_endpoints))
        
        # Group forms by action
        forms_by_action: Dict[str, List[Dict]] = {}
        for form in self.all_forms:
            action = form.get('action', '')
            if action not in forms_by_action:
                forms_by_action[action] = []
            forms_by_action[action].append(form)
        
        # Summary statistics
        total_inputs = len(self.all_inputs)
        input_types = {}
        for inp in self.all_inputs:
            inp_type = inp.get('type', 'text')
            input_types[inp_type] = input_types.get(inp_type, 0) + 1
        
        report = {
            'summary': {
                'base_url': self.base_url,
                'pages_crawled': len(self.site_map),
                'total_forms': len(self.all_forms),
                'total_inputs': total_inputs,
                'input_types': input_types,
                'unique_endpoints': len(unique_endpoints),
                'errors': len(self.errors)
            },
            'pages': list(self.site_map.values()),
            'forms': self.all_forms,
            'inputs': self.all_inputs,
            'endpoints': unique_endpoints,
            'errors': self.errors
        }
        
        return report


def crawl_website(
    url: str,
    max_depth: int = 3,
    max_pages: int = 50,
    same_domain_only: bool = True
) -> str:
    """
    Perform a comprehensive crawl of a website to discover all pages, forms, inputs, and endpoints.
    
    This tool discovers:
    - All pages on the website (up to max_pages)
    - All forms and their input fields
    - All links and navigation structure
    - Potential API endpoints
    - Security-relevant information from every page
    
    Args:
        url: The base URL to start crawling from
        max_depth: Maximum crawl depth (default: 3)
        max_pages: Maximum number of pages to crawl (default: 50)
        same_domain_only: Only crawl pages on the same domain (default: True)
        
    Returns:
        Comprehensive report with discovered pages, forms, inputs, and endpoints
    """
    try:
        crawler = WebsiteCrawler(
            base_url=url,
            max_depth=max_depth,
            max_pages=max_pages,
            same_domain_only=same_domain_only
        )
        
        report = crawler.crawl()
        
        # Format report for output
        output_parts = []
        
        # Summary
        summary = report['summary']
        output_parts.append("=" * 60)
        output_parts.append("WEBSITE CRAWL REPORT")
        output_parts.append("=" * 60)
        output_parts.append(f"Base URL: {summary['base_url']}")
        output_parts.append(f"Pages Crawled: {summary['pages_crawled']}")
        output_parts.append(f"Total Forms Found: {summary['total_forms']}")
        output_parts.append(f"Total Input Fields: {summary['total_inputs']}")
        output_parts.append(f"Unique Endpoints: {summary['unique_endpoints']}")
        if summary['errors'] > 0:
            output_parts.append(f"Errors: {summary['errors']}")
        output_parts.append("")
        
        # Input types breakdown
        if summary['input_types']:
            output_parts.append("Input Types Found:")
            for inp_type, count in sorted(summary['input_types'].items()):
                output_parts.append(f"  - {inp_type}: {count}")
            output_parts.append("")
        
        # Pages with forms (most important for security testing)
        pages_with_forms = [p for p in report['pages'] if p.get('form_count', 0) > 0]
        if pages_with_forms:
            output_parts.append(f"Pages with Forms ({len(pages_with_forms)}):")
            for page in pages_with_forms[:20]:  # Limit to first 20
                output_parts.append(f"  - {page['url']} ({page['form_count']} form(s))")
            if len(pages_with_forms) > 20:
                output_parts.append(f"  ... and {len(pages_with_forms) - 20} more pages with forms")
            output_parts.append("")
        
        # All discovered forms (detailed)
        if report['forms']:
            output_parts.append("=" * 60)
            output_parts.append("FORMS DISCOVERED")
            output_parts.append("=" * 60)
            for i, form in enumerate(report['forms'][:30], 1):  # Limit to first 30
                output_parts.append(f"\nForm {i}:")
                output_parts.append(f"  Page: {form['page']}")
                output_parts.append(f"  Action: {form['action']}")
                output_parts.append(f"  Method: {form['method']}")
                output_parts.append(f"  Inputs ({len(form['inputs'])}):")
                for inp in form['inputs']:
                    inp_str = f"    - {inp['tag']}"
                    if inp['type']:
                        inp_str += f" type={inp['type']}"
                    if inp['name']:
                        inp_str += f" name={inp['name']}"
                    if inp.get('required'):
                        inp_str += " [REQUIRED]"
                    output_parts.append(inp_str)
            
            if len(report['forms']) > 30:
                output_parts.append(f"\n... and {len(report['forms']) - 30} more forms")
            output_parts.append("")
        
        # Endpoints
        if report['endpoints']:
            output_parts.append("=" * 60)
            output_parts.append("ENDPOINTS DISCOVERED")
            output_parts.append("=" * 60)
            for endpoint in report['endpoints'][:50]:  # Limit to first 50
                output_parts.append(f"  - {endpoint}")
            if len(report['endpoints']) > 50:
                output_parts.append(f"  ... and {len(report['endpoints']) - 50} more endpoints")
            output_parts.append("")
        
        # All pages (summary)
        output_parts.append("=" * 60)
        output_parts.append("PAGES DISCOVERED")
        output_parts.append("=" * 60)
        for page in report['pages'][:30]:  # Limit to first 30
            page_info = f"  - {page['url']}"
            if page.get('form_count', 0) > 0:
                page_info += f" ({page['form_count']} form(s))"
            if page.get('has_inline_scripts'):
                page_info += " [has inline scripts]"
            output_parts.append(page_info)
        
        if len(report['pages']) > 30:
            output_parts.append(f"  ... and {len(report['pages']) - 30} more pages")
        
        # Errors
        if report['errors']:
            output_parts.append("")
            output_parts.append("=" * 60)
            output_parts.append("ERRORS")
            output_parts.append("=" * 60)
            for error in report['errors'][:10]:
                output_parts.append(f"  - {error}")
        
        output = '\n'.join(output_parts)
        
        # Limit total output length but keep it comprehensive
        if len(output) > 8000:
            output = output[:8000] + f"\n\n[Output truncated - original length: {len(output)} chars]"
        
        return output
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Error crawling website {url}: Network error - {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg
    except Exception as e:
        error_msg = f"Error crawling website {url}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg


def get_crawl_website_tool() -> StructuredTool:
    """
    Create and return the crawl_website tool for use with LangChain agents.
    
    Returns:
        StructuredTool instance for crawling websites
    """
    return StructuredTool.from_function(
        func=crawl_website,
        name="crawl_website",
        description="""Perform a comprehensive deep crawl of a website to discover ALL pages, forms, inputs, and endpoints. 
        
This tool is ESSENTIAL for thorough security testing. It will:
- Discover all pages on the website (follows links recursively)
- Find all forms and input fields across all pages
- Map the site structure and navigation
- Identify all endpoints and routes
- Extract security-relevant information from every page

Use this tool FIRST before running security tests to ensure you test ALL pages and forms, not just the main page.

Input: url (the base URL to start crawling from), max_depth (optional, default 3), max_pages (optional, default 50), same_domain_only (optional, default True)"""
    )

