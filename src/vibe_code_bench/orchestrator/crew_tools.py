"""
CrewAI Tools Organization

Organizes all tools available to agents in the orchestrator workflow.
"""

from typing import List, Dict, Any
from langchain.tools import BaseTool

from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


def get_red_team_tools() -> List[BaseTool]:
    """
    Get all tools available to the red team agent.
    
    Returns:
        List of LangChain tools for security testing
    """
    from vibe_code_bench.red_team_agent.tools import get_all_tools
    
    tools = get_all_tools()
    logger.info(f"Loaded {len(tools)} tools for red team agent")
    
    return tools


def get_tool_descriptions() -> Dict[str, str]:
    """
    Get descriptions of all available tools.
    
    Returns:
        Dictionary mapping tool names to descriptions
    """
    return {
        "browse_tool": """
        Browse Tool - Navigate and interact with web pages.
        Allows the agent to visit URLs, click elements, fill forms, and extract content.
        """,
        
        "crawl_website_tool": """
        Crawl Website Tool - Discover all pages on a website.
        Crawls the website structure to find all accessible pages and endpoints.
        """,
        
        "xss_test_tool": """
        XSS Test Tool - Test for Cross-Site Scripting vulnerabilities.
        Injects XSS payloads into forms and URL parameters to detect XSS vulnerabilities.
        """,
        
        "sqli_test_tool": """
        SQL Injection Test Tool - Test for SQL injection vulnerabilities.
        Injects SQL payloads into forms and URL parameters to detect SQL injection flaws.
        """,
        
        "auth_analysis_tool": """
        Authentication Analysis Tool - Analyze authentication mechanisms.
        Tests login forms, session management, password policies, and authentication flows.
        """,
        
        "security_headers_tool": """
        Security Headers Tool - Check security header configurations.
        Analyzes HTTP security headers like CSP, HSTS, X-Frame-Options, etc.
        """,
        
        "test_all_pages_tool": """
        Test All Pages Tool - Run security tests on all discovered pages.
        Applies security tests (XSS, SQLi, etc.) to all pages found during crawling.
        """,
        
        "security_report_tool": """
        Security Report Tool - Generate structured security reports.
        Creates comprehensive security assessment reports from test results.
        """
    }


def get_tools_by_agent() -> Dict[str, List[str]]:
    """
    Get tools organized by which agent uses them.
    
    Returns:
        Dictionary mapping agent names to lists of tool names
    """
    return {
        "red_team": [
            "browse_tool",
            "crawl_website_tool",
            "xss_test_tool",
            "sqli_test_tool",
            "auth_analysis_tool",
            "security_headers_tool",
            "test_all_pages_tool",
            "security_report_tool"
        ],
        "static_analysis": [
            # Static analysis uses command-line tools (Bandit, Semgrep, npm audit)
            # These are executed directly, not as LangChain tools
        ],
        "website_builder": [
            # Website builder uses LLM directly, no external tools
        ],
        "website_builder_evaluator": [
            # Evaluator uses LLM directly, no external tools
        ],
        "red_team_evaluator": [
            # Evaluator uses LLM directly, no external tools
        ],
        "final_report": [
            # Report generator uses LLM directly, no external tools
        ]
    }


def get_tool_summary() -> str:
    """
    Get a human-readable summary of all tools.
    
    Returns:
        Markdown-formatted summary of tools
    """
    descriptions = get_tool_descriptions()
    by_agent = get_tools_by_agent()
    
    summary = ["# Tools Summary\n"]
    
    for agent, tool_names in by_agent.items():
        if tool_names:
            summary.append(f"## {agent.replace('_', ' ').title()} Agent Tools\n")
            for tool_name in tool_names:
                if tool_name in descriptions:
                    summary.append(f"### {tool_name.replace('_', ' ').title()}\n")
                    summary.append(descriptions[tool_name].strip())
                    summary.append("\n")
            summary.append("\n")
    
    return "\n".join(summary)


