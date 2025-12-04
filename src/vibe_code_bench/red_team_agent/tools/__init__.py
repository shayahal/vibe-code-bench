"""
Red Team Agent Tools Package

This package contains all tools for the red team agent.
Each tool is in its own module, and the registry maps tool names to their functions.
"""

from typing import Dict, Callable, List
from langchain_core.tools import StructuredTool


def truncate_output(output: str, max_length: int = 500) -> str:
    """
    Truncate tool output to prevent context bloat.
    
    Args:
        output: The tool output string
        max_length: Maximum length in characters (default: 500)
        
    Returns:
        Truncated output with ellipsis if needed
    """
    if len(output) <= max_length:
        return output
    
    # Try to truncate at a sentence boundary
    truncated = output[:max_length]
    last_period = truncated.rfind('.')
    last_newline = truncated.rfind('\n')
    
    # Use the later of period or newline for clean truncation
    cut_point = max(last_period, last_newline)
    if cut_point > max_length * 0.7:  # Only use if it's not too early
        truncated = truncated[:cut_point + 1]
    
    return truncated + f"\n\n[Output truncated - original length: {len(output)} chars]"

# Import tool functions
from .browse_tool import browse_url, get_browse_tool
from .crawl_website_tool import crawl_website, get_crawl_website_tool
from .security_headers_tool import analyze_security_headers, get_security_headers_tool
from .xss_test_tool import test_xss_patterns, get_xss_test_tool
from .sqli_test_tool import test_sql_injection_patterns, get_sqli_test_tool
from .auth_analysis_tool import analyze_authentication, get_auth_analysis_tool
from .security_report_tool import generate_security_report, get_security_report_tool

# Tools Registry
# Maps tool names to their StructuredTool factory functions
TOOLS_REGISTRY: Dict[str, Callable[[], StructuredTool]] = {
    "browse_url": get_browse_tool,
    "crawl_website": get_crawl_website_tool,
    "analyze_security_headers": get_security_headers_tool,
    "test_xss_patterns": get_xss_test_tool,
    "test_sql_injection_patterns": get_sqli_test_tool,
    "analyze_authentication": get_auth_analysis_tool,
    "generate_security_report": get_security_report_tool,
}

# List of all available tool names
AVAILABLE_TOOLS = list(TOOLS_REGISTRY.keys())


def get_tool(tool_name: str) -> StructuredTool:
    """
    Get a tool by name from the registry.
    
    Args:
        tool_name: Name of the tool to retrieve
        
    Returns:
        StructuredTool instance
        
    Raises:
        KeyError: If tool_name is not in the registry
    """
    if tool_name not in TOOLS_REGISTRY:
        available = ", ".join(AVAILABLE_TOOLS)
        raise KeyError(
            f"Tool '{tool_name}' not found in registry. "
            f"Available tools: {available}"
        )
    return TOOLS_REGISTRY[tool_name]()


def get_all_tools() -> List[StructuredTool]:
    """
    Get all registered tools as a list of StructuredTool instances.
    
    Returns:
        List of all available StructuredTool instances
    """
    return [factory() for factory in TOOLS_REGISTRY.values()]


__all__ = [
    "TOOLS_REGISTRY",
    "AVAILABLE_TOOLS",
    "get_tool",
    "get_all_tools",
    "browse_url",
    "get_browse_tool",
    "crawl_website",
    "get_crawl_website_tool",
    "analyze_security_headers",
    "get_security_headers_tool",
    "test_xss_patterns",
    "get_xss_test_tool",
    "test_sql_injection_patterns",
    "get_sqli_test_tool",
    "analyze_authentication",
    "get_auth_analysis_tool",
    "generate_security_report",
    "get_security_report_tool",
]

