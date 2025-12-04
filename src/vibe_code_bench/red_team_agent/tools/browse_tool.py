"""
Browse URL Tool

A tool for browsing URLs and extracting security-relevant information including:
- Page content and structure
- Forms and input fields
- Links and endpoints
- Scripts and external resources
- Metadata and headers
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from langchain_core.tools import StructuredTool
from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


def browse_url(url: str) -> str:
    """
    Browse a URL and extract security-relevant information.
    
    Extracts:
    - Page title and basic content
    - Forms and input fields (for vulnerability testing)
    - Links and endpoints (for further exploration)
    - Scripts and external resources
    - HTTP headers and metadata
    
    Args:
        url: The URL to browse
        
    Returns:
        Structured report with security-relevant information
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract information
        info_parts = []
        
        # Basic page info
        title = soup.find('title')
        title_text = title.get_text().strip() if title else "No title"
        info_parts.append(f"Page Title: {title_text}")
        info_parts.append(f"Status Code: {response.status_code}")
        info_parts.append(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        
        # Forms and inputs (critical for security testing)
        forms = soup.find_all('form')
        if forms:
            info_parts.append(f"\nFound {len(forms)} form(s):")
            for i, form in enumerate(forms, 1):
                form_info = []
                form_action = form.get('action', '') or ''
                form_method = (form.get('method', 'GET') or 'GET')
                if isinstance(form_method, str):
                    form_method = form_method.upper()
                else:
                    form_method = str(form_method).upper()
                form_info.append(f"  Form {i}: method={form_method}, action={form_action}")
                
                # Find input fields
                inputs = form.find_all(['input', 'textarea', 'select'])
                if inputs:
                    input_types = []
                    input_names = []
                    for inp in inputs:
                        if inp.name == 'input':
                            inp_type = inp.get('type', 'text')
                            if isinstance(inp_type, str):
                                input_types.append(inp_type)
                            else:
                                input_types.append(str(inp_type) if inp_type else 'text')
                        inp_name = inp.get('name')
                        if inp_name:
                            if isinstance(inp_name, str):
                                input_names.append(inp_name)
                            else:
                                input_names.append(str(inp_name))
                    if input_names:
                        form_info.append(f"    Inputs: {', '.join(input_names[:5])}")
                        if len(input_names) > 5:
                            form_info.append(f"    ... and {len(input_names) - 5} more")
                info_parts.append('\n'.join(form_info))
        else:
            info_parts.append("\nNo forms found")
        
        # Links (for endpoint discovery)
        links = soup.find_all('a', href=True)
        if links:
            unique_links = set()
            internal_links = set()
            external_links = set()
            
            for link in links:
                href_raw = link.get('href')
                if href_raw:
                    href = str(href_raw).strip()
                    if href:
                        absolute_url = urljoin(url, href)
                        parsed = urlparse(absolute_url)
                        
                        if parsed.netloc == urlparse(url).netloc or not parsed.netloc:
                            # Internal link
                            if href.startswith('/') or not parsed.netloc:
                                internal_links.add(href if href.startswith('/') else absolute_url)
                                unique_links.add(href if href.startswith('/') else absolute_url)
                        else:
                            # External link
                            external_links.add(absolute_url)
            
            if unique_links:
                info_parts.append(f"\nFound {len(links)} total links:")
                info_parts.append(f"  Internal links: {len(internal_links)}")
                info_parts.append(f"  External links: {len(external_links)}")
                if internal_links:
                    info_parts.append(f"\n  Internal links (showing up to 15):")
                    for link in list(internal_links)[:15]:
                        info_parts.append(f"    - {link}")
                    if len(internal_links) > 15:
                        info_parts.append(f"    ... and {len(internal_links) - 15} more internal links")
        
        # Scripts (for XSS and security analysis)
        scripts = soup.find_all('script')
        if scripts:
            external_scripts = [s.get('src') for s in scripts if s.get('src')]
            inline_scripts = [s for s in scripts if s.string and s.get('src') is None]
            info_parts.append(f"\nScripts: {len(scripts)} total")
            if external_scripts:
                info_parts.append(f"  External: {len(external_scripts)}")
                for src in external_scripts[:3]:
                    info_parts.append(f"    - {src}")
            if inline_scripts:
                info_parts.append(f"  Inline: {len(inline_scripts)} (potential XSS risk)")
        
        # Meta tags (for security headers check)
        meta_tags = soup.find_all('meta')
        security_meta = [m for m in meta_tags if m.get('http-equiv') in ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']]
        if security_meta:
            info_parts.append(f"\nSecurity Meta Tags: {len(security_meta)}")
            for meta in security_meta:
                content_raw = meta.get('content', '')
                content = str(content_raw) if content_raw else ''
                http_equiv = meta.get('http-equiv', '')
                info_parts.append(f"  - {http_equiv}: {content[:80]}")
        
        # Check for potential security issues
        security_issues = []
        
        # Check for inline event handlers (XSS risk)
        inline_handlers = []
        for tag in soup.find_all():
            if tag.attrs and isinstance(tag.attrs, dict):
                if any(k.startswith('on') for k in tag.attrs.keys()):
                    inline_handlers.append(tag)
        if inline_handlers:
            security_issues.append(f"Found {len(inline_handlers)} elements with inline event handlers (potential XSS risk)")
        
        # Check for password fields without HTTPS
        password_fields = soup.find_all('input', type='password')
        if password_fields and not url.startswith('https://'):
            security_issues.append(f"Found {len(password_fields)} password field(s) on non-HTTPS page (CRITICAL)")
        
        # Check for autocomplete on sensitive fields
        sensitive_autocomplete = []
        for inp in soup.find_all('input'):
            autocomplete = inp.get('autocomplete')
            if autocomplete:
                autocomplete_str = str(autocomplete).lower()
                if autocomplete_str in ['off', 'false']:
                    sensitive_autocomplete.append(inp)
        if sensitive_autocomplete:
            security_issues.append(f"Found {len(sensitive_autocomplete)} input(s) with autocomplete disabled (may indicate sensitive data)")
        
        if security_issues:
            info_parts.append(f"\nSecurity Observations:")
            for issue in security_issues:
                info_parts.append(f"  ⚠ {issue}")
        
        # API endpoints and data attributes
        api_indicators = []
        data_attrs = []
        for tag in soup.find_all():
            if tag.attrs and isinstance(tag.attrs, dict):
                if any(k.startswith('data-') for k in tag.attrs.keys()):
                    data_attrs.append(tag)
        if data_attrs:
            api_indicators.append(f"Found {len(data_attrs)} elements with data-* attributes (may indicate API endpoints)")
        
        # Look for common API patterns in scripts
        api_patterns = ['/api/', '/rest/', '/graphql', '/v1/', '/v2/']
        found_patterns = []
        for script in soup.find_all('script'):
            if script.string:
                for pattern in api_patterns:
                    if pattern in script.string.lower():
                        found_patterns.append(pattern)
        
        if found_patterns:
            api_indicators.append(f"Found API patterns in scripts: {', '.join(set(found_patterns))}")
        
        if api_indicators:
            info_parts.append(f"\nAPI/Endpoint Indicators:")
            for indicator in api_indicators:
                info_parts.append(f"  - {indicator}")
        
        # Build report
        report = '\n'.join(info_parts)
        
        # Limit output length to prevent context bloat (increased limit for more info)
        if len(report) > 2000:
            report = report[:2000] + f"\n\n[Output truncated - original length: {len(report)} chars]"
        
        return report
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Error browsing {url}: Network error - {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg
    except Exception as e:
        error_msg = f"Error browsing {url}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg


def get_browse_tool() -> StructuredTool:
    """
    Create and return the browse_url tool for use with LangChain agents.
    
    Returns:
        StructuredTool instance for browsing URLs
    """
    return StructuredTool.from_function(
        func=browse_url,
        name="browse_url",
        description="Browse a URL and extract security-relevant information including forms, inputs, links, scripts, and metadata. Use this first to understand the target page structure before running security tests. Input: url (the URL to browse)"
    )

