"""
Authentication Analysis Tool

Analyzes authentication mechanisms and identifies common security issues.
"""

import requests
from bs4 import BeautifulSoup
from langchain_core.tools import StructuredTool


def analyze_authentication(url: str) -> str:
    """
    Analyze authentication mechanisms on a web page.
    
    Identifies:
    - Login forms and authentication endpoints
    - Session management indicators
    - Password field security (autocomplete, visibility)
    - HTTPS usage for authentication
    - Common authentication vulnerabilities
    
    Args:
        url: The URL to analyze
        
    Returns:
        Analysis report of authentication mechanisms and security issues
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        findings = []
        issues = []
        
        # Find login forms
        login_forms = soup.find_all('form')
        password_fields = soup.find_all('input', {'type': 'password'})
        username_fields = soup.find_all('input', {'type': 'text', 'name': lambda x: x and ('user' in x.lower() or 'email' in x.lower() or 'login' in x.lower())})
        
        if login_forms:
            findings.append(f"Found {len(login_forms)} form(s) on the page")
            
            for form in login_forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                if form_action:
                    # Check if form submits over HTTPS
                    if form_action.startswith('http://'):
                        issues.append(f"HIGH: Login form submits to HTTP (not HTTPS): {form_action}")
                    elif form_action.startswith('https://') or form_action.startswith('/'):
                        findings.append(f"✓ Form action: {form_action} (method: {form_method})")
                    else:
                        findings.append(f"Form action: {form_action} (method: {form_method})")
                
                # Check form method
                if form_method == 'get':
                    issues.append("HIGH: Login form uses GET method - credentials may appear in URL/logs")
        
        if password_fields:
            findings.append(f"Found {len(password_fields)} password field(s)")
            
            for pwd_field in password_fields:
                # Check for autocomplete
                autocomplete = pwd_field.get('autocomplete', '')
                if autocomplete == 'off':
                    findings.append("✓ Password field has autocomplete disabled")
                else:
                    issues.append("MEDIUM: Password field allows autocomplete - potential credential theft risk")
                
                # Check for show/hide password toggle
                # (This would require more complex DOM analysis)
        
        # Check if page uses HTTPS
        if url.startswith('https://'):
            findings.append("✓ Page uses HTTPS")
        else:
            issues.append("CRITICAL: Page does not use HTTPS - credentials transmitted in plaintext")
        
        # Check for session cookies
        cookies = response.cookies
        if cookies:
            findings.append(f"Found {len(cookies)} cookie(s)")
            for cookie in cookies:
                cookie_name = cookie.name.lower()
                if 'session' in cookie_name or 'auth' in cookie_name or 'token' in cookie_name:
                    secure_flag = getattr(cookie, 'secure', False)
                    http_only = getattr(cookie, 'httponly', False)
                    
                    if not secure_flag:
                        issues.append(f"HIGH: Session cookie '{cookie.name}' missing Secure flag - can be sent over HTTP")
                    else:
                        findings.append(f"✓ Session cookie '{cookie.name}' has Secure flag")
                    
                    if not http_only:
                        issues.append(f"MEDIUM: Session cookie '{cookie.name}' missing HttpOnly flag - accessible to JavaScript")
                    else:
                        findings.append(f"✓ Session cookie '{cookie.name}' has HttpOnly flag")
        
        # Check for CSRF tokens
        csrf_inputs = soup.find_all('input', {'name': lambda x: x and ('csrf' in x.lower() or 'token' in x.lower())})
        if csrf_inputs:
            findings.append(f"✓ Found {len(csrf_inputs)} potential CSRF token field(s)")
        else:
            issues.append("MEDIUM: No CSRF token fields detected - CSRF protection may be missing")
        
        # Build report
        report = f"Authentication Analysis for {url}\n"
        report += "=" * 60 + "\n\n"
        
        if findings:
            report += "FINDINGS:\n"
            for finding in findings:
                report += f"  • {finding}\n"
            report += "\n"
        
        if issues:
            report += "SECURITY ISSUES:\n"
            for issue in issues:
                report += f"  ⚠ {issue}\n"
        else:
            report += "✓ No obvious authentication security issues detected\n"
        
        return report
        
    except Exception as e:
        return f"Error analyzing authentication for {url}: {str(e)}"


def get_auth_analysis_tool() -> StructuredTool:
    """
    Create and return the analyze_authentication tool for use with LangChain agents.
    
    Returns:
        StructuredTool instance for analyzing authentication mechanisms
    """
    return StructuredTool.from_function(
        func=analyze_authentication,
        name="analyze_authentication",
        description="Analyze authentication mechanisms on a web page. Identifies login forms, session management, password field security, HTTPS usage, and common authentication vulnerabilities. Input: url (the URL to analyze)"
    )

