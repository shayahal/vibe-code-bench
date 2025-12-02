"""
Report Generator for Mini Red Team Agent

Generates comprehensive run reports using LLM based on execution data.
"""

import os
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langchain_anthropic import ChatAnthropic
    from langfuse import Langfuse
    from langfuse.langchain import CallbackHandler as LangfuseCallbackHandler


# System prompt for the agent
AGENT_SYSTEM_PROMPT = """You are a web security red team agent testing web applications for common vulnerabilities.

Your mission is to:
1. Analyze the target website for security vulnerabilities
2. Test for common web vulnerabilities (XSS, SQL injection patterns, insecure configurations)
3. Check security headers and HTTPS configuration
4. Identify potential security issues in forms, inputs, and authentication mechanisms
5. Generate a comprehensive security assessment report

Testing Approach:
- Start by fetching and analyzing the target page structure using browse_url
- Look for forms, input fields, and authentication mechanisms
- Test for common vulnerability patterns (XSS payloads, SQL injection patterns)
- Check security headers (CSP, HSTS, X-Frame-Options, etc.)
- Analyze JavaScript for security issues
- Document all findings clearly

Available Tools (choose which ones to use based on your testing needs):
1. browse_url: Fetch and parse web page content, extract HTML, forms, links, and metadata
2. analyze_security_headers: Check HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) for a URL
3. test_xss_patterns: Test for Cross-Site Scripting (XSS) vulnerabilities by injecting payloads into URL parameters or form fields
4. test_sql_injection_patterns: Test for SQL injection vulnerabilities by injecting SQLi payloads into URL parameters or form fields
5. analyze_authentication: Analyze authentication mechanisms on a web page, identify login forms, session management, and common auth vulnerabilities
6. generate_security_report: Generate a comprehensive security assessment report compiling all findings, vulnerabilities, and recommendations

Workflow:
1. First, use browse_url to understand the target page structure
2. Then, strategically choose which security tests to run based on what you find
3. Use analyze_security_headers to check HTTP security headers
4. If you find forms or input fields, use test_xss_patterns and test_sql_injection_patterns
5. If you find authentication mechanisms, use analyze_authentication
6. Finally, use generate_security_report to compile all findings into a comprehensive report

Ethical Guidelines:
- Only test systems you have explicit permission to test
- Do not perform destructive actions or data exfiltration
- Focus on identifying vulnerabilities, not exploiting them
- Report findings responsibly

Always think step by step and document your findings as you test. Choose tools strategically - you don't need to use all tools, only the ones relevant to your testing."""


def get_report_generation_prompt(url: str, output: str, execution_time: float) -> str:
    """
    Get the prompt for generating a vulnerability-focused security report.
    
    Args:
        url: The URL that was tested
        output: The agent's output (should contain tool results and findings)
        execution_time: Execution time in seconds
        
    Returns:
        Formatted prompt string
    """
    return f"""You are generating a security assessment report focused on VULNERABILITIES FOUND.

Target URL: {url}
Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Assessment Duration: {execution_time:.2f} seconds

Agent Output (contains tool results and findings):
{output}

CRITICAL: Extract and organize ALL vulnerabilities and security issues from the agent output above.

Generate a vulnerability-focused security report with this structure:

## 1. Executive Summary
- Target URL: {url}
- Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Total Vulnerabilities Found: [count by severity]
  - Critical: [count]
  - High: [count]
  - Medium: [count]
  - Low: [count]
- Overall Risk Level: [Critical/High/Medium/Low]
- Key Findings: 2-3 sentence summary of the most critical issues

## 2. Vulnerabilities by Severity

### 2.1 Critical Vulnerabilities
For EACH critical vulnerability found, include:
- **VULN-XXX**: [Title]
  - **Severity**: CRITICAL
  - **Description**: What the vulnerability is
  - **Affected Resource**: URL/endpoint/header/etc.
  - **Evidence**: What was found (specific details from tool output)
  - **Impact**: What an attacker could exploit
  - **Recommendation**: How to fix it

### 2.2 High Severity Vulnerabilities
(Same format as Critical)

### 2.3 Medium Severity Vulnerabilities
(Same format as Critical)

### 2.4 Low Severity Vulnerabilities
(Same format as Critical)

## 3. Security Findings by Category

### 3.1 Security Headers Analysis
- Summary of headers checked
- Missing or misconfigured headers found
- Specific issues identified
- Recommendations

### 3.2 XSS Vulnerability Testing
- Parameters/fields tested
- Vulnerabilities found (if any)
- Evidence (payloads, responses)
- Recommendations

### 3.3 SQL Injection Testing
- Parameters/fields tested
- Vulnerabilities found (if any)
- Evidence (payloads, error messages)
- Recommendations

### 3.4 Authentication Analysis
- Authentication mechanisms found
- Security issues identified
- Session management issues
- Recommendations

## 4. Testing Methodology
- Tools used during assessment
- Tests performed
- Scope and limitations

## 5. Recommendations Summary
- Prioritized list of fixes (Critical first)
- Quick wins
- Long-term security improvements

IMPORTANT:
- Extract ALL vulnerabilities from the agent output
- Organize by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Include specific evidence and details
- If NO vulnerabilities found, clearly state that
- Focus on actionable findings, not generic descriptions
- Use the exact tool output data provided above"""


def generate_run_report(
    llm: "ChatAnthropic",
    langfuse_client: "Langfuse",
    url: str,
    output: str,
    execution_time: float,
    langfuse_handler: "LangfuseCallbackHandler"
) -> str:
    """
    Generate a run report using the LLM based on LangFuse trace data.
    
    Args:
        llm: The LLM instance to generate the report
        langfuse_client: LangFuse client to fetch trace data
        url: The URL that was browsed
        output: The agent's output
        execution_time: Execution time in seconds
        langfuse_handler: The LangFuse callback handler
        
    Returns:
        Generated report as markdown string
    """
    try:
        # Get trace ID from handler if available
        trace_id = None
        try:
            # The handler has a last_trace_id attribute that contains the trace ID
            if hasattr(langfuse_handler, 'last_trace_id'):
                trace_id = langfuse_handler.last_trace_id
            elif hasattr(langfuse_handler, 'get_trace_id'):
                trace_id = langfuse_handler.get_trace_id()
        except:
            pass
        
        # Get report generation prompt
        report_prompt = get_report_generation_prompt(url, output, execution_time)
        
        # Generate report using LLM
        report_response = llm.invoke(report_prompt)
        report_content = report_response.content if hasattr(report_response, 'content') else str(report_response)
        
        # Add header and metadata
        full_report = f"""# Security Assessment Report - Vulnerability Focused

**Target URL:** {url}  
**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Assessment Duration:** {execution_time:.2f} seconds  
**Assessment Type:** Automated Security Testing  
**Model:** claude-3-haiku-20240307

---

{report_content}

---

## Technical Details

- **Trace ID:** {trace_id if trace_id else 'Available in LangFuse dashboard'}
- **LangFuse Dashboard:** Check {os.getenv('LANGFUSE_HOST', 'https://cloud.langfuse.com')} for detailed traces
{f'- **Direct Trace Link:** {os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")}/traces/{trace_id}' if trace_id else ''}
- **All observability data** (tokens, costs, detailed traces) is available in LangFuse

---

**Note:** This report focuses on vulnerabilities and security issues found during automated testing. 
For comprehensive security evaluation, manual penetration testing is recommended.
"""
        
        return full_report
        
    except Exception as e:
        # Fallback report if generation fails
        return f"""# Agent Run Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Target URL:** {url}  
**Execution Time:** {execution_time:.2f} seconds  
**Model:** claude-3-haiku-20240307

## Summary

The agent successfully browsed the URL {url} and extracted the first 3 lines of visible text content.

## Tools Used

- **browse_url**: Fetched the webpage, parsed HTML, and extracted visible text content

## Execution Details

- **Total execution time:** {execution_time:.2f} seconds
- **Model:** claude-3-haiku-20240307 (Claude Mini)

## Cost Analysis

- **Model:** claude-3-haiku-20240307
- **Cost:** Check LangFuse dashboard for detailed cost breakdown
- **Token usage:** Available in LangFuse trace data

## Output

{output}

## Observability

All execution traces, token usage, and costs are logged to LangFuse. Check the LangFuse dashboard for detailed information.

**Note:** Report generation encountered an error: {str(e)}
"""

