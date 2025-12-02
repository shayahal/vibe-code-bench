"""
Essential Tools - Top 5 Core Tools

These are the minimum essential tools needed for basic web security testing.
All other tools are in advanced_tools.py and can be enabled on demand.
"""

from typing import Dict, Any, Callable

from .tool_factory import RedTeamToolFactory
from .utility_tools import register_utility_tools
from .web_app_tools import register_web_app_tools


def register_essential_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register only the top 5 essential tools for basic web security testing.
    
    Essential Tools:
    1. fetch_page - Fetch and parse web pages (foundation)
    2. scan_with_nuclei - Fast, comprehensive vulnerability scanner
    3. scan_with_sqlmap - SQL injection testing
    4. scan_xss_with_dalfox - XSS vulnerability testing
    5. generate_report - Generate security reports
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    # Get all utility tools (includes fetch_page, analyze_response_security, generate_report)
    utility_tools = register_utility_tools(factory)
    
    # Get all web app tools (includes nuclei, sqlmap, dalfox, etc.)
    web_app_tools = register_web_app_tools(factory)
    
    # Select only the essential 5 tools
    essential_tool_names = [
        'fetch_page',           # 1. Foundation - fetch pages
        'scan_with_nuclei',     # 2. Comprehensive scanner
        'scan_with_sqlmap',     # 3. SQL injection testing
        'scan_xss_with_dalfox', # 4. XSS testing
        'generate_report',      # 5. Report generation
    ]
    
    # Add essential tools from utility
    for tool_name in essential_tool_names:
        if tool_name in utility_tools:
            tools[tool_name] = utility_tools[tool_name]
        elif tool_name in web_app_tools:
            tools[tool_name] = web_app_tools[tool_name]
    
    return tools


# Export tool names
__all__ = [
    'register_essential_tools',
]

