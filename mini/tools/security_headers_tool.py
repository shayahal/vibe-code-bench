"""
Security Headers Analysis Tool

Analyzes HTTP security headers to identify missing or misconfigured security headers.
"""

import requests
from langchain_core.tools import StructuredTool


def analyze_security_headers(url: str) -> str:
    """
    Analyze HTTP security headers for a given URL.
    
    Checks for:
    - Content-Security-Policy (CSP)
    - Strict-Transport-Security (HSTS)
    - X-Frame-Options
    - X-Content-Type-Options
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    
    Args:
        url: The URL to analyze
        
    Returns:
        Analysis report of security headers
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        security_headers = {
            "Content-Security-Policy": response.headers.get("Content-Security-Policy", "MISSING"),
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security", "MISSING"),
            "X-Frame-Options": response.headers.get("X-Frame-Options", "MISSING"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options", "MISSING"),
            "X-XSS-Protection": response.headers.get("X-XSS-Protection", "MISSING"),
            "Referrer-Policy": response.headers.get("Referrer-Policy", "MISSING"),
            "Permissions-Policy": response.headers.get("Permissions-Policy", "MISSING"),
        }
        
        # Analyze findings
        findings = []
        issues = []
        
        if security_headers["Content-Security-Policy"] == "MISSING":
            issues.append("CRITICAL: Content-Security-Policy header is missing - XSS protection is weak")
        else:
            findings.append(f"✓ Content-Security-Policy: {security_headers['Content-Security-Policy']}")
        
        if security_headers["Strict-Transport-Security"] == "MISSING" and url.startswith("https://"):
            issues.append("HIGH: Strict-Transport-Security header is missing - HTTPS enforcement not configured")
        elif security_headers["Strict-Transport-Security"] != "MISSING":
            findings.append(f"✓ Strict-Transport-Security: {security_headers['Strict-Transport-Security']}")
        
        if security_headers["X-Frame-Options"] == "MISSING":
            issues.append("MEDIUM: X-Frame-Options header is missing - clickjacking protection not configured")
        else:
            findings.append(f"✓ X-Frame-Options: {security_headers['X-Frame-Options']}")
        
        if security_headers["X-Content-Type-Options"] == "MISSING":
            issues.append("MEDIUM: X-Content-Type-Options header is missing - MIME type sniffing protection not configured")
        else:
            findings.append(f"✓ X-Content-Type-Options: {security_headers['X-Content-Type-Options']}")
        
        if security_headers["X-XSS-Protection"] == "MISSING":
            issues.append("LOW: X-XSS-Protection header is missing (note: deprecated but still used)")
        else:
            findings.append(f"✓ X-XSS-Protection: {security_headers['X-XSS-Protection']}")
        
        if security_headers["Referrer-Policy"] == "MISSING":
            issues.append("LOW: Referrer-Policy header is missing - referrer information leakage possible")
        else:
            findings.append(f"✓ Referrer-Policy: {security_headers['Referrer-Policy']}")
        
        if security_headers["Permissions-Policy"] == "MISSING":
            issues.append("LOW: Permissions-Policy header is missing - browser feature access not restricted")
        else:
            findings.append(f"✓ Permissions-Policy: {security_headers['Permissions-Policy']}")
        
        # Build report
        report = f"Security Headers Analysis for {url}\n"
        report += "=" * 60 + "\n\n"
        
        if findings:
            report += "PRESENT HEADERS:\n"
            for finding in findings:
                report += f"  {finding}\n"
            report += "\n"
        
        if issues:
            report += "SECURITY ISSUES:\n"
            for issue in issues:
                report += f"  ⚠ {issue}\n"
        else:
            report += "✓ All critical security headers are present\n"
        
        report += f"\nAll Headers:\n"
        for header, value in security_headers.items():
            report += f"  {header}: {value}\n"
        
        return report
        
    except Exception as e:
        return f"Error analyzing security headers for {url}: {str(e)}"


def get_security_headers_tool() -> StructuredTool:
    """
    Create and return the analyze_security_headers tool for use with LangChain agents.
    
    Returns:
        StructuredTool instance for analyzing security headers
    """
    return StructuredTool.from_function(
        func=analyze_security_headers,
        name="analyze_security_headers",
        description="Analyze HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) for a URL. Identifies missing or misconfigured security headers. Input: url (the URL to analyze)"
    )

