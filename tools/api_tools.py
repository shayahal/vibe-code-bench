"""
API Security Tools

This module contains integrations for API security testing tools.

Tool Selection Rationale:
- REST-Attacker: REST API security testing framework. Comprehensive API vulnerability testing.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Callable

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_api_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register API security tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_scan_api_rest_attacker():
        """
        Create scan_api_rest_attacker tool.
        
        Why REST-Attacker: REST API security testing framework with comprehensive test coverage.
        Excellent for finding API-specific vulnerabilities.
        """
        def scan_api_rest_attacker(api_url: str) -> Dict[str, Any]:
            """Scan REST API with REST-Attacker."""
            logger.info(f"Scanning API with REST-Attacker: {api_url}")
            # REST-Attacker is a Python library
            try:
                import rest_attacker
                # This would require proper REST-Attacker integration
                return {
                    "api_url": api_url,
                    "tool": "rest_attacker",
                    "note": "REST-Attacker integration requires proper setup",
                    "timestamp": datetime.now().isoformat()
                }
            except ImportError:
                logger.warning("REST-Attacker not installed. Install: pip install rest-attacker")
                return {"error": "REST-Attacker not installed", "api_url": api_url}
        
        return scan_api_rest_attacker
    
    # Register API tools
    tools['scan_api_rest_attacker'] = create_scan_api_rest_attacker()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_api_tools',
    'scan_api_rest_attacker',
]

