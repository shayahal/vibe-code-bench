"""
Tool Loader

This module loads and registers red-team tools.
By default, only essential tools (top 5) are loaded.
Advanced tools can be enabled on demand.
"""

from typing import Dict, Any, Callable

from .tool_factory import RedTeamToolFactory
from .essential_tools import register_essential_tools
from .advanced_tools import register_advanced_tools


def load_essential_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Load only the top 5 essential tools for basic web security testing.
    
    Essential Tools:
    1. fetch_page - Fetch and parse web pages
    2. scan_with_nuclei - Fast vulnerability scanner
    3. scan_with_sqlmap - SQL injection testing
    4. scan_xss_with_dalfox - XSS vulnerability testing
    5. generate_report - Generate security reports
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    return register_essential_tools(factory)


def load_advanced_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Load all advanced tools (everything except the top 5 essential tools).
    
    Advanced tools include network scanning, AD tools, password cracking,
    cloud tools, and additional web app scanners.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    return register_advanced_tools(factory)


def load_all_tools(factory: RedTeamToolFactory, include_advanced: bool = False) -> Dict[str, Callable]:
    """
    Load tools - essential by default, advanced optionally.
    
    Args:
        factory: RedTeamToolFactory instance
        include_advanced: If True, load all tools including advanced ones
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = load_essential_tools(factory)
    
    if include_advanced:
        advanced_tools = load_advanced_tools(factory)
        tools.update(advanced_tools)
    
    return tools

