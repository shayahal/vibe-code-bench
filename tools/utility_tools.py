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
import json
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
            """Generate a comprehensive, detailed security report with all findings, tool outputs, and recommendations."""
            logger.info(f"Generating comprehensive security report - Total tests: {len(factory.test_results)}")
            
            vulnerable_tests = [r for r in factory.test_results if r.get('is_vulnerable', False)]
            critical_tests = [r for r in vulnerable_tests if r.get('severity') == 'CRITICAL']
            high_tests = [r for r in vulnerable_tests if r.get('severity') == 'HIGH']
            medium_tests = [r for r in vulnerable_tests if r.get('severity') == 'MEDIUM']
            low_tests = [r for r in vulnerable_tests if r.get('severity') == 'LOW']
            
            # Group results by tool
            tool_results = {}
            for result in factory.test_results:
                tool_name = result.get('tool', result.get('test_type', 'unknown'))
                if tool_name not in tool_results:
                    tool_results[tool_name] = []
                tool_results[tool_name].append(result)
            
            logger.info(f"Report summary - Vulnerabilities: {len(vulnerable_tests)}, Critical: {len(critical_tests)}, High: {len(high_tests)}, Medium: {len(medium_tests)}, Low: {len(low_tests)}")
            
            # Calculate risk score
            risk_score = len(critical_tests) * 10 + len(high_tests) * 5 + len(medium_tests) * 2 + len(low_tests) * 1
            risk_level = "CRITICAL" if risk_score >= 20 else "HIGH" if risk_score >= 10 else "MEDIUM" if risk_score >= 5 else "LOW"
            
            report = f"""# Web Security Red-Teaming Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Target URL**: {factory.target_url}  
**Risk Level**: {risk_level} (Score: {risk_score})

---

## Executive Summary

### Overview
This report presents the findings from a comprehensive security assessment of **{factory.target_url}**. The assessment utilized industry-standard security testing tools to identify vulnerabilities and security issues.

### Key Statistics
- **Total Tests Performed**: {len(factory.test_results)}
- **Total Vulnerabilities Found**: {len(vulnerable_tests)}
  - **Critical**: {len(critical_tests)} vulnerabilities
  - **High**: {len(high_tests)} vulnerabilities
  - **Medium**: {len(medium_tests)} vulnerabilities
  - **Low**: {len(low_tests)} vulnerabilities
- **Tests Passed (No Issues)**: {len(factory.test_results) - len(vulnerable_tests)}
- **Overall Risk Score**: {risk_score}/100
- **Overall Risk Level**: **{risk_level}**

### Risk Assessment
Based on the findings, the target application has a **{risk_level}** risk level. {'**Immediate action is required**' if risk_level in ['CRITICAL', 'HIGH'] else '**Review recommended**' if risk_level == 'MEDIUM' else '**Low priority review**'}.

---

## Vulnerability Breakdown by Severity

### 🔴 Critical Vulnerabilities ({len(critical_tests)})
"""
            if critical_tests:
                for i, result in enumerate(critical_tests, 1):
                    report += f"""
#### {i}. {result.get('issue', 'Critical Security Issue')}

- **URL**: `{result.get('url', 'N/A')}`
- **Tool**: {result.get('tool', result.get('test_type', 'Unknown'))}
- **Parameter**: {result.get('parameter', 'N/A')}
- **Payload**: `{result.get('payload', 'N/A')}`
- **Description**: {result.get('description', result.get('issue', 'No description available'))}
- **Impact**: {result.get('impact', 'Critical - Immediate remediation required')}
- **Timestamp**: {result.get('timestamp', 'N/A')}
"""
                    # Include tool-specific findings
                    if result.get('findings'):
                        report += f"\n**Tool Findings**:\n```json\n{json.dumps(result.get('findings'), indent=2)[:500]}\n```\n"
                    if result.get('output'):
                        report += f"\n**Tool Output**:\n```\n{str(result.get('output', ''))[:300]}\n```\n"
            else:
                report += "\n✅ No critical vulnerabilities found.\n"
            
            report += f"\n### 🟠 High Severity Vulnerabilities ({len(high_tests)})\n"
            if high_tests:
                for i, result in enumerate(high_tests, 1):
                    report += f"""
#### {i}. {result.get('issue', 'High Severity Issue')}

- **URL**: `{result.get('url', 'N/A')}`
- **Tool**: {result.get('tool', result.get('test_type', 'Unknown'))}
- **Parameter**: {result.get('parameter', 'N/A')}
- **Payload**: `{result.get('payload', 'N/A')}`
- **Description**: {result.get('description', result.get('issue', 'No description available'))}
- **Impact**: {result.get('impact', 'High - Should be addressed promptly')}
- **Timestamp**: {result.get('timestamp', 'N/A')}
"""
                    if result.get('findings'):
                        report += f"\n**Tool Findings**:\n```json\n{json.dumps(result.get('findings'), indent=2)[:500]}\n```\n"
            else:
                report += "\n✅ No high severity vulnerabilities found.\n"
            
            if medium_tests:
                report += f"\n### 🟡 Medium Severity Vulnerabilities ({len(medium_tests)})\n"
                for i, result in enumerate(medium_tests, 1):
                    report += f"""
#### {i}. {result.get('issue', 'Medium Severity Issue')}

- **URL**: `{result.get('url', 'N/A')}`
- **Tool**: {result.get('tool', result.get('test_type', 'Unknown'))}
- **Description**: {result.get('description', result.get('issue', 'No description available'))}
- **Timestamp**: {result.get('timestamp', 'N/A')}
"""
            
            if low_tests:
                report += f"\n### 🟢 Low Severity Vulnerabilities ({len(low_tests)})\n"
                for i, result in enumerate(low_tests[:10], 1):  # Limit to first 10
                    report += f"- **{result.get('issue', 'Low Severity Issue')}** - {result.get('url', 'N/A')}\n"
                if len(low_tests) > 10:
                    report += f"\n*... and {len(low_tests) - 10} more low severity issues*\n"
            
            report += "\n---\n\n## Tool-Specific Findings\n\n"
            
            # Detailed findings by tool
            for tool_name, results in tool_results.items():
                tool_vulns = [r for r in results if r.get('is_vulnerable', False)]
                report += f"### {tool_name.upper().replace('_', ' ')} ({len(results)} tests, {len(tool_vulns)} vulnerabilities)\n\n"
                
                if tool_vulns:
                    for result in tool_vulns[:5]:  # Show top 5 per tool
                        report += f"- **{result.get('issue', 'Vulnerability found')}**\n"
                        report += f"  - URL: `{result.get('url', 'N/A')}`\n"
                        if result.get('findings'):
                            findings_summary = str(result.get('findings', ''))[:200]
                            report += f"  - Findings: {findings_summary}...\n"
                    if len(tool_vulns) > 5:
                        report += f"  - *... and {len(tool_vulns) - 5} more findings*\n"
                else:
                    report += "✅ No vulnerabilities found.\n"
                report += "\n"
            
            report += "---\n\n## Detailed Test Results\n\n"
            report += "### All Tests Performed\n\n"
            
            for i, result in enumerate(factory.test_results, 1):
                status_icon = "🔴" if result.get('is_vulnerable') else "✅"
                report += f"#### Test {i}: {result.get('test_type', 'Unknown Test')} {status_icon}\n\n"
                report += f"- **Status**: {'VULNERABLE' if result.get('is_vulnerable') else 'SAFE'}\n"
                report += f"- **URL**: `{result.get('url', factory.target_url)}`\n"
                report += f"- **Tool**: {result.get('tool', result.get('test_type', 'Unknown'))}\n"
                report += f"- **Timestamp**: {result.get('timestamp', 'N/A')}\n"
                
                if result.get('issue'):
                    report += f"- **Issue**: {result['issue']}\n"
                if result.get('severity'):
                    report += f"- **Severity**: {result['severity']}\n"
                if result.get('parameter'):
                    report += f"- **Parameter**: {result['parameter']}\n"
                if result.get('payload'):
                    report += f"- **Payload**: `{result['payload']}`\n"
                if result.get('count'):
                    report += f"- **Findings Count**: {result['count']}\n"
                
                # Include detailed findings if available
                if result.get('findings') and isinstance(result.get('findings'), list):
                    report += f"\n**Detailed Findings** ({len(result['findings'])} items):\n"
                    for finding in result['findings'][:3]:  # Show first 3 findings
                        if isinstance(finding, dict):
                            report += f"- {finding.get('info', {}).get('name', finding.get('name', 'Finding'))}\n"
                            if finding.get('matched-at'):
                                report += f"  - Location: {finding.get('matched-at')}\n"
                        else:
                            report += f"- {str(finding)[:100]}\n"
                    if len(result['findings']) > 3:
                        report += f"- *... and {len(result['findings']) - 3} more findings*\n"
                
                report += "\n"
            
            report += "---\n\n## Recommendations\n\n"
            
            if critical_tests or high_tests:
                report += "### Immediate Actions Required\n\n"
                report += "1. **Address Critical Vulnerabilities First**: Focus on fixing all critical vulnerabilities immediately as they pose the highest risk.\n"
                report += "2. **Implement Input Validation**: Ensure all user inputs are properly validated and sanitized.\n"
                report += "3. **Update Security Headers**: Implement proper security headers (CSP, X-Frame-Options, etc.).\n"
                report += "4. **Regular Security Audits**: Schedule regular security assessments to identify new vulnerabilities.\n"
                report += "5. **Security Training**: Provide security awareness training for development teams.\n\n"
            
            if medium_tests or low_tests:
                report += "### Medium Priority Recommendations\n\n"
                report += "1. **Review Medium Severity Issues**: Address medium severity vulnerabilities in the next development cycle.\n"
                report += "2. **Security Best Practices**: Implement security best practices and coding standards.\n"
                report += "3. **Dependency Updates**: Keep all dependencies and frameworks up to date.\n\n"
            
            if not vulnerable_tests:
                report += "### Security Status\n\n"
                report += "✅ **No vulnerabilities detected** in the current assessment. However, security is an ongoing process:\n\n"
                report += "1. Continue regular security testing\n"
                report += "2. Implement security monitoring\n"
                report += "3. Keep security tools and dependencies updated\n"
                report += "4. Follow security best practices\n\n"
            
            report += "---\n\n## Testing Methodology\n\n"
            report += "This assessment utilized the following testing approach:\n\n"
            report += "1. **Reconnaissance**: Initial target analysis and structure discovery\n"
            report += "2. **Vulnerability Scanning**: Comprehensive scanning using Nuclei with 10,000+ templates\n"
            report += "3. **Targeted Testing**: Specific vulnerability testing (XSS, SQL injection)\n"
            report += "4. **Analysis**: Detailed analysis of findings and risk assessment\n"
            report += "5. **Reporting**: Comprehensive documentation of all findings\n\n"
            
            report += "### Tools Used\n\n"
            for tool_name in sorted(tool_results.keys()):
                tool_count = len(tool_results[tool_name])
                tool_vulns = len([r for r in tool_results[tool_name] if r.get('is_vulnerable', False)])
                report += f"- **{tool_name.replace('_', ' ').title()}**: {tool_count} tests, {tool_vulns} vulnerabilities found\n"
            
            report += f"\n---\n\n## Conclusion\n\n"
            
            if critical_tests or high_tests:
                report += f"This security assessment identified **{len(vulnerable_tests)} vulnerabilities** requiring attention. "
                report += f"**{len(critical_tests)} critical** and **{len(high_tests)} high severity** issues should be addressed immediately. "
                report += "The target application requires immediate security improvements to reduce risk.\n\n"
            else:
                report += f"This security assessment found **{len(vulnerable_tests)} vulnerabilities**. "
                if len(vulnerable_tests) == 0:
                    report += "The target application appears to have good security practices in place. "
                else:
                    report += "While no critical issues were found, it is recommended to address the identified issues. "
                report += "Regular security assessments are recommended to maintain security posture.\n\n"
            
            report += f"**Report Generated**: {datetime.now().isoformat()}\n"
            report += f"**Total Execution Time**: See detailed action report for timing information\n"
            
            logger.info("Comprehensive security report generated successfully")
            factory.log_trail("report_generated", {
                "total_tests": len(factory.test_results),
                "vulnerabilities": len(vulnerable_tests),
                "critical": len(critical_tests),
                "high": len(high_tests),
                "risk_level": risk_level,
                "risk_score": risk_score
            }, f"Generated comprehensive security report with {len(vulnerable_tests)} vulnerabilities")
            
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

