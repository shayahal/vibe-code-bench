"""
Security Report Generation Tool

Compiles security findings into a comprehensive report.
"""

from datetime import datetime
from langchain_core.tools import StructuredTool
from typing import Dict, List, Any


def generate_security_report(
    target_url: str,
    findings: str,
    vulnerabilities: str = "",
    recommendations: str = ""
) -> str:
    """
    Generate a comprehensive security assessment report.
    
    Compiles all security findings, vulnerabilities, and recommendations
    into a structured markdown report.
    
    Args:
        target_url: The target URL that was tested
        findings: Summary of all security findings
        vulnerabilities: List of identified vulnerabilities (optional)
        recommendations: Security recommendations (optional)
        
    Returns:
        Comprehensive security report in markdown format
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = f"""# Security Assessment Report - Vulnerability Focused

**Target URL:** {target_url}  
**Assessment Date:** {timestamp}  
**Assessment Type:** Automated Security Testing

---

## Executive Summary

This report contains the results of an automated security assessment performed on {target_url}.
The assessment included analysis of security headers, XSS vulnerabilities, SQL injection patterns,
and authentication mechanisms.

**Focus:** This report prioritizes identified vulnerabilities and security issues over general findings.

---

## Security Findings

{findings}

---

"""
    
    if vulnerabilities:
        report += f"""## 🔴 Identified Vulnerabilities

**CRITICAL:** Review and remediate these vulnerabilities immediately.

{vulnerabilities}

---

"""
    
    if recommendations:
        report += f"""## Recommendations

{recommendations}

---

"""
    
    report += """## Testing Methodology

The following security tests were performed:
1. Security Headers Analysis - Checked for presence and configuration of security headers
2. XSS Testing - Injected common XSS payloads to test for reflected XSS vulnerabilities
3. SQL Injection Testing - Tested for SQL injection vulnerabilities using common payloads
4. Authentication Analysis - Analyzed authentication mechanisms and session management

---

## Notes

- This is an automated assessment and may not identify all security issues
- Manual penetration testing is recommended for comprehensive security evaluation
- Only test systems you have explicit permission to test
- Report any critical vulnerabilities responsibly to the system owner

---

**Report Generated:** {timestamp}
"""
    
    return report


def get_security_report_tool() -> StructuredTool:
    """
    Create and return the generate_security_report tool for use with LangChain agents.
    
    Returns:
        StructuredTool instance for generating security reports
    """
    return StructuredTool.from_function(
        func=generate_security_report,
        name="generate_security_report",
        description="Generate a comprehensive security assessment report. Compiles findings, vulnerabilities, and recommendations into a structured markdown report. Input: target_url (the URL that was tested), findings (summary of security findings), vulnerabilities (optional list of vulnerabilities), recommendations (optional security recommendations)"
    )

