"""
Report Generator for Red Team Agent

Generates comprehensive run reports using LLM based on execution data.
"""

import os
import re
from datetime import datetime
from typing import TYPE_CHECKING, List, Set

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


def deduplicate_output(output: str) -> str:
    """
    Remove duplicate information from agent output.
    
    Args:
        output: The agent's output string
        
    Returns:
        Deduplicated output string
    """
    if not output:
        return output
    
    lines = output.split('\n')
    seen: Set[str] = set()
    deduplicated_lines: List[str] = []
    
    for line in lines:
        # Normalize line for comparison (lowercase, strip whitespace)
        normalized = line.strip().lower()
        
        # Skip empty lines and very short lines
        if not normalized or len(normalized) < 10:
            deduplicated_lines.append(line)
            continue
        
        # Check for duplicate content (similarity check)
        is_duplicate = False
        for seen_line in seen:
            # Check if this line is very similar to a seen line
            if normalized in seen_line or seen_line in normalized:
                # If one is a substring of the other, it's likely a duplicate
                if abs(len(normalized) - len(seen_line)) < len(normalized) * 0.3:
                    is_duplicate = True
                    break
        
        if not is_duplicate:
            seen.add(normalized)
            deduplicated_lines.append(line)
    
    return '\n'.join(deduplicated_lines)


def deduplicate_report(report_content: str) -> str:
    """
    Remove duplicate sections and lines from generated report.
    
    Args:
        report_content: The generated report content
        
    Returns:
        Deduplicated report content
    """
    if not report_content:
        return report_content
    
    lines = report_content.split('\n')
    seen_vulns: Set[str] = set()
    seen_recommendations: Set[str] = set()
    deduplicated_lines: List[str] = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Extract vulnerability IDs to detect duplicates
        vuln_match = re.search(r'\*\*VULN-(\d+)\*\*', line, re.IGNORECASE)
        if vuln_match:
            vuln_id = vuln_match.group(1)
            if vuln_id in seen_vulns:
                # Skip this duplicate vulnerability
                i += 1
                continue
            seen_vulns.add(vuln_id)
        
        # Extract recommendations to detect duplicates
        is_duplicate_rec = False
        if 'recommendation' in line.lower() or 'fix:' in line.lower():
            normalized_rec = line.strip().lower()
            # Remove common prefixes for comparison
            normalized_rec = re.sub(r'^[-*•]\s*', '', normalized_rec)
            normalized_rec = re.sub(r'\*\*fix:\*\*', '', normalized_rec).strip()
            
            if normalized_rec and len(normalized_rec) > 10:
                # Check if this recommendation is similar to one we've seen
                for seen_rec in seen_recommendations:
                    if normalized_rec in seen_rec or seen_rec in normalized_rec:
                        if abs(len(normalized_rec) - len(seen_rec)) < len(normalized_rec) * 0.4:
                            is_duplicate_rec = True
                            break
                
                if not is_duplicate_rec:
                    seen_recommendations.add(normalized_rec)
        
        # Skip duplicate recommendations, but add everything else
        if not is_duplicate_rec:
            deduplicated_lines.append(line)
        
        i += 1
    
    return '\n'.join(deduplicated_lines)


def get_report_generation_prompt(url: str, output: str, execution_time: float) -> str:
    """
    Get the prompt for generating a concise vulnerability-focused security report.
    
    Args:
        url: The URL that was tested
        output: The agent's output (should contain tool results and findings)
        execution_time: Execution time in seconds
        
    Returns:
        Formatted prompt string
    """
    return f"""Generate a CONCISE security assessment report. Be brief and focus on key findings only.

Target URL: {url}
Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Duration: {execution_time:.2f} seconds

Agent Output:
{output}

Generate a SHORT report with this structure:

## Summary
- Vulnerabilities: [Critical/High/Medium/Low counts]
- Risk Level: [Critical/High/Medium/Low]
- Key Issues: [1-2 sentence summary]

## Vulnerabilities

For each vulnerability, use this format:
- **VULN-XXX**: [Title] - [Brief description]. **Fix:** [One-line recommendation]

Group by severity (Critical, High, Medium, Low). Only include vulnerabilities found.

## Recommendations
- Prioritized list of fixes (one line each)

IMPORTANT:
- Keep it SHORT - maximum 50 lines total
- Only include actual vulnerabilities found
- Use bullet points, avoid verbose explanations
- DO NOT repeat the same vulnerability multiple times - each vulnerability should appear only once
- DO NOT duplicate recommendations - each recommendation should appear only once
- If no vulnerabilities found, state "No vulnerabilities detected" and skip sections"""


def generate_run_report(
    llm: "ChatAnthropic",
    langfuse_client: "Langfuse",
    url: str,
    output: str,
    execution_time: float,
    langfuse_handler: "LangfuseCallbackHandler",
    run_id: str = None,
    model_name: str = "anthropic/claude-3-haiku"
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
        
        # Deduplicate agent output before generating report
        deduplicated_output = deduplicate_output(output)
        
        # Get report generation prompt
        report_prompt = get_report_generation_prompt(url, deduplicated_output, execution_time)
        
        # Generate report using LLM
        report_response = llm.invoke(report_prompt)
        report_content = report_response.content if hasattr(report_response, 'content') else str(report_response)
        
        # Deduplicate the generated report content
        report_content = deduplicate_report(report_content)
        
        # Add header and metadata
        run_id_section = f"**Run ID:** {run_id}\n" if run_id else ""
        full_report = f"""# Security Assessment Report

**Target:** {url} | **Model:** {model_name} | **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | **Duration:** {execution_time:.2f}s
{run_id_section}
---

{report_content}

---

**Run ID:** {run_id if run_id else 'N/A'} (use this to filter traces in LangFuse)  
**Trace ID:** {trace_id if trace_id else 'Available in LangFuse dashboard'}  
**Dashboard:** {os.getenv('LANGFUSE_HOST', 'https://cloud.langfuse.com')}
{f'**Trace Link:** {os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")}/traces/{trace_id}' if trace_id else ''}

**Note:** Search for "run_id: {run_id}" in LangFuse to find all traces for this run.
"""
        
        return full_report
        
    except Exception as e:
        # Fallback report if generation fails
        return f"""# Agent Run Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Target URL:** {url}  
**Model:** {model_name}
**Execution Time:** {execution_time:.2f} seconds  

## Summary

The agent successfully browsed the URL {url} and extracted the first 3 lines of visible text content.

## Tools Used

- **browse_url**: Fetched the webpage, parsed HTML, and extracted visible text content

## Execution Details

- **Total execution time:** {execution_time:.2f} seconds
- **Model:** {model_name}

## Cost Analysis

- **Model:** {model_name}
- **Cost:** Check LangFuse dashboard for detailed cost breakdown
- **Token usage:** Available in LangFuse trace data

## Output

{output}

## Observability

All execution traces, token usage, and costs are logged to LangFuse. Check the LangFuse dashboard for detailed information.

**Note:** Report generation encountered an error: {str(e)}
"""

