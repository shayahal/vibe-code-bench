"""
Utility Tools

These are foundational tools that support the red-team testing workflow.
They handle basic operations like fetching pages, analyzing responses, and generating reports.

Why these tools:
- fetch_page: Essential for understanding target structure before testing
- analyze_response_security: Detects sensitive data exposure and security header issues
- generate_report: Consolidates all findings into actionable security reports
"""

import logging
import re
from datetime import datetime
from typing import Dict, Any, Callable
from bs4 import BeautifulSoup

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_utility_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register utility tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_fetch_page():
        """Create fetch_page tool - fetches and parses web pages."""
        def fetch_page(url: str) -> Dict[str, Any]:
            """Fetch a web page and return its content and metadata."""
            logger.info(f"Fetching page: {url}")
            factory.log_trail("tool_call", {
                "tool": "fetch_page",
                "url": url
            }, f"Fetching page to analyze structure, forms, and links for security testing")
            try:
                response = factory.session.get(url, timeout=20)
                logger.info(f"Fetched {url} - Status: {response.status_code}, Size: {len(response.text)} bytes")
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                forms = []
                for form in soup.find_all('form'):
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        form_data['inputs'].append({
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        })
                    forms.append(form_data)
                
                # Extract links
                links = [a.get('href', '') for a in soup.find_all('a', href=True)]
                
                logger.info(f"Extracted {len(forms)} forms and {len(links)} links from {url}")
                
                result = {
                    "url": url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "forms": forms,
                    "links": links,
                    "content_length": len(response.text),
                    "has_forms": len(forms) > 0,
                    "response_text": response.text
                }
                
                factory.log_trail("tool_result", {
                    "tool": "fetch_page",
                    "url": url,
                    "status_code": response.status_code,
                    "forms_found": len(forms),
                    "links_found": len(links)
                }, f"Successfully fetched page with {len(forms)} forms and {len(links)} links")
                
                return result
            except Exception as e:
                logger.error(f"Error fetching page {url}: {str(e)}")
                factory.log_trail("tool_error", {
                    "tool": "fetch_page",
                    "url": url,
                    "error": str(e)
                }, f"Failed to fetch page: {str(e)}")
                return {"error": str(e), "url": url}
        
        return fetch_page
    
    def create_analyze_response_security():
        """Create analyze_response_security tool - analyzes HTTP responses for security issues."""
        def analyze_response_security(response_text: str) -> Dict[str, Any]:
            """Analyze HTTP response for security issues."""
            logger.info(f"Analyzing response security - Response size: {len(response_text)} bytes")
            issues = []
            
            # Check for sensitive information
            sensitive_patterns = {
                "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "credit_card": r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
                "api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                "password": r'(?i)(password|pwd|pass)\s*[:=]\s*["\']?([^\s"\'<>]{6,})["\']?',
            }
            
            for pattern_name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, response_text)
                if matches:
                    logger.warning(f"Potential {pattern_name} exposure found in response ({len(matches)} matches)")
                    issues.append(f"Potential {pattern_name} exposure found")
            
            if issues:
                logger.warning(f"Security analysis found {len(issues)} issues")
            else:
                logger.info("Security analysis completed - No issues found")
            
            return {
                "issues": issues,
                "has_issues": len(issues) > 0,
                "analysis_timestamp": datetime.now().isoformat()
            }
        
        return analyze_response_security
    
    def create_generate_report():
        """Create generate_report tool - generates comprehensive security reports."""
        def generate_report() -> str:
            """Generate a comprehensive security report."""
            logger.info(f"Generating security report - Total tests: {len(factory.test_results)}")
            vulnerable_tests = [r for r in factory.test_results if r.get('is_vulnerable', False)]
            critical_tests = [r for r in vulnerable_tests if r.get('severity') == 'CRITICAL']
            high_tests = [r for r in vulnerable_tests if r.get('severity') == 'HIGH']
            
            logger.info(f"Report summary - Vulnerabilities: {len(vulnerable_tests)}, Critical: {len(critical_tests)}, High: {len(high_tests)}")
            
            report = f"""# Web Security Red-Teaming Report
Generated: {datetime.now().isoformat()}

## Target URL
{factory.target_url}

## Executive Summary
- Total tests performed: {len(factory.test_results)}
- Vulnerabilities found: {len(vulnerable_tests)}
- Critical vulnerabilities: {len(critical_tests)}
- High severity vulnerabilities: {len(high_tests)}

## Vulnerability Breakdown

### Critical Vulnerabilities ({len(critical_tests)})
"""
            for i, result in enumerate(critical_tests, 1):
                report += f"\n#### {i}. {result.get('issue', 'Unknown issue')}\n"
                report += f"- URL: {result.get('url', 'N/A')}\n"
                report += f"- Parameter: {result.get('parameter', 'N/A')}\n"
                report += f"- Payload: {result.get('payload', 'N/A')}\n"
                report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
            
            report += f"\n### High Severity Vulnerabilities ({len(high_tests)})\n"
            for i, result in enumerate(high_tests, 1):
                report += f"\n#### {i}. {result.get('issue', 'Unknown issue')}\n"
                report += f"- URL: {result.get('url', 'N/A')}\n"
                report += f"- Parameter: {result.get('parameter', 'N/A')}\n"
                report += f"- Payload: {result.get('payload', 'N/A')}\n"
                report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
            
            report += "\n## Detailed Test Results\n"
            for i, result in enumerate(factory.test_results, 1):
                report += f"\n### Test {i}\n"
                report += f"- Type: {result.get('test_type', 'Unknown')}\n"
                report += f"- URL: {result.get('url', 'N/A')}\n"
                report += f"- Status: {'VULNERABLE' if result.get('is_vulnerable') else 'SAFE'}\n"
                if result.get('issue'):
                    report += f"- Issue: {result['issue']}\n"
                report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
            
            logger.info("Security report generated successfully")
            return report
        
        return generate_report
    
    # Register all utility tools
    tools['fetch_page'] = create_fetch_page()
    tools['analyze_response_security'] = create_analyze_response_security()
    tools['generate_report'] = create_generate_report()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_utility_tools',
    'fetch_page',
    'analyze_response_security',
    'generate_report',
]

