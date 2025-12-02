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
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                form_info.append(f"  Form {i}: method={form_method}, action={form_action}")
                
                # Find input fields
                inputs = form.find_all(['input', 'textarea', 'select'])
                if inputs:
                    input_types = [inp.get('type', 'text') for inp in inputs if inp.name == 'input']
                    input_names = [inp.get('name', 'unnamed') for inp in inputs if inp.get('name')]
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
            for link in links[:20]:  # Limit to first 20
                href = link.get('href')
                if href:
                    absolute_url = urljoin(url, href)
                    parsed = urlparse(absolute_url)
                    if parsed.netloc:  # Only external or absolute links
                        unique_links.add(absolute_url)
                    elif href.startswith('/'):  # Important internal links
                        unique_links.add(href)
            
            if unique_links:
                info_parts.append(f"\nFound {len(links)} links (showing up to 20 unique):")
                for link in list(unique_links)[:10]:
                    info_parts.append(f"  - {link}")
                if len(unique_links) > 10:
                    info_parts.append(f"  ... and {len(unique_links) - 10} more")
        
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
        security_meta = [m for m in meta_tags if m.get('http-equiv') in ['Content-Security-Policy', 'X-Frame-Options']]
        if security_meta:
            info_parts.append(f"\nSecurity Meta Tags: {len(security_meta)}")
            for meta in security_meta:
                info_parts.append(f"  - {meta.get('http-equiv')}: {meta.get('content', '')[:50]}")
        
        # Build report
        report = '\n'.join(info_parts)
        
        # Limit output length to prevent context bloat
        if len(report) > 1000:
            report = report[:1000] + f"\n\n[Output truncated - original length: {len(report)} chars]"
        
        return report
        
    except requests.exceptions.RequestException as e:
        return f"Error browsing {url}: Network error - {str(e)}"
    except Exception as e:
        return f"Error browsing {url}: {str(e)}"


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

