"""
Mini Red Team Agent Tools Package

This package contains all tools for the mini red team agent.
Each tool is in its own module, and the registry maps tool names to their functions.
"""

from typing import Dict, Callable
from langchain_core.tools import StructuredTool

# Import tool functions
from .browse_tool import browse_url, get_browse_tool

# Tools Registry
# Maps tool names to their StructuredTool factory functions
TOOLS_REGISTRY: Dict[str, Callable[[], StructuredTool]] = {
    "browse_url": get_browse_tool,
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


def get_all_tools() -> list[StructuredTool]:
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
]

