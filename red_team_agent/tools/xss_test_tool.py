"""
XSS Testing Tool

Tests for Cross-Site Scripting (XSS) vulnerabilities by injecting payloads and analyzing responses.
"""

from typing import Optional, Dict, Any
import requests
from bs4 import BeautifulSoup
from langchain_core.tools import StructuredTool


def test_xss_patterns(url: str, form_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Test for XSS vulnerabilities by injecting common XSS payloads.
    
    Tests both reflected and stored XSS patterns. Analyzes responses for:
    - Reflected script tags
    - Event handlers (onerror, onclick, etc.)
    - JavaScript execution indicators
    
    Args:
        url: The URL to test (can include query parameters)
        form_data: Optional dictionary of form data to test (if None, tests URL parameters)
        
    Returns:
        Analysis report of XSS test results
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        # Common XSS payloads to test
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
        ]
        
        findings = []
        vulnerabilities = []
        
        # Test URL parameters if no form data provided
        if form_data is None:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:
                # Test each parameter
                for param_name, param_values in params.items():
                    for payload in xss_payloads[:3]:  # Test first 3 payloads per parameter
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                        ))
                        
                        try:
                            response = requests.get(test_url, headers=headers, timeout=5)
                            if payload in response.text or "<script>" in response.text.lower():
                                vulnerabilities.append(f"⚠ POTENTIAL XSS in parameter '{param_name}' with payload: {payload[:50]}")
                        except:
                            pass
        else:
            # Test form data
            for field_name, field_value in form_data.items():
                for payload in xss_payloads[:2]:  # Test first 2 payloads per field
                    test_data = form_data.copy()
                    test_data[field_name] = payload
                    
                    try:
                        response = requests.post(url, data=test_data, headers=headers, timeout=5)
                        if payload in response.text or "<script>" in response.text.lower():
                            vulnerabilities.append(f"⚠ POTENTIAL XSS in field '{field_name}' with payload: {payload[:50]}")
                    except:
                        pass
        
        # Analyze page for XSS indicators
        try:
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for inline scripts without nonce
            scripts = soup.find_all('script')
            inline_scripts = [s for s in scripts if s.string and not s.get('nonce')]
            if inline_scripts:
                findings.append(f"Found {len(inline_scripts)} inline scripts without nonce - potential XSS risk")
            
            # Check for dangerous event handlers
            dangerous_attrs = ['onerror', 'onclick', 'onload', 'onmouseover']
            for attr in dangerous_attrs:
                elements = soup.find_all(attrs={attr: True})
                if elements:
                    findings.append(f"Found {len(elements)} elements with {attr} handler - potential XSS risk")
        
        except Exception as e:
            findings.append(f"Could not analyze page structure: {str(e)}")
        
        # Build concise report
        report_parts = []
        
        if vulnerabilities:
            report_parts.append(f"XSS Testing for {url}: ⚠ POTENTIAL VULNERABILITIES FOUND")
            report_parts.extend([f"  {vuln}" for vuln in vulnerabilities[:5]])  # Limit to 5 vulnerabilities
            if len(vulnerabilities) > 5:
                report_parts.append(f"  ... and {len(vulnerabilities) - 5} more")
        else:
            report_parts.append(f"XSS Testing for {url}: ✓ No obvious XSS vulnerabilities detected")
        
        if findings:
            report_parts.append("\nFindings:")
            report_parts.extend([f"  • {f}" for f in findings[:3]])  # Limit to 3 findings
            if len(findings) > 3:
                report_parts.append(f"  ... and {len(findings) - 3} more")
        
        report = "\n".join(report_parts)
        
        # Limit output length to prevent context bloat
        if len(report) > 500:
            report = report[:500] + f"\n[Truncated - {len(report)} chars total]"
        
        return report
        
    except Exception as e:
        return f"Error testing XSS patterns for {url}: {str(e)}"


def get_xss_test_tool() -> StructuredTool:
    """
    Create and return the test_xss_patterns tool for use with LangChain agents.
    
    Returns:
        StructuredTool instance for testing XSS vulnerabilities
    """
    return StructuredTool.from_function(
        func=test_xss_patterns,
        name="test_xss_patterns",
        description="Test for Cross-Site Scripting (XSS) vulnerabilities by injecting payloads into URL parameters or form fields. Analyzes responses for reflected XSS. Input: url (the URL to test, can include query parameters), form_data (optional dict of form fields to test)"
    )

