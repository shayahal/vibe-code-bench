"""
Cloud Security Tools

This module contains integrations for cloud security testing tools.

Tool Selection Rationale:
- Pacu: AWS exploitation framework. Comprehensive AWS security testing.
- Scout Suite: Multi-cloud security auditing tool. Supports AWS, Azure, GCP.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_cloud_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register cloud security tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_scan_aws_pacu():
        """
        Create scan_aws_pacu tool.
        
        Why Pacu: AWS exploitation framework with comprehensive attack modules.
        Excellent for testing AWS security configurations and permissions.
        """
        def scan_aws_pacu(aws_key: str, aws_secret: str, region: str = "us-east-1") -> Dict[str, Any]:
            """Scan AWS environment with Pacu."""
            logger.info(f"Scanning AWS with Pacu: {region}")
            # Pacu requires AWS credentials and proper setup
            return {
                "region": region,
                "tool": "pacu",
                "note": "Pacu requires AWS credentials and proper configuration",
                "timestamp": datetime.now().isoformat()
            }
        
        return scan_aws_pacu
    
    def create_scan_cloud_scout_suite():
        """
        Create scan_cloud_scout_suite tool.
        
        Why Scout Suite: Multi-cloud security auditing tool supporting AWS, Azure, and GCP.
        Comprehensive cloud misconfiguration detection.
        """
        def scan_cloud_scout_suite(provider: str, credentials: Dict[str, str]) -> Dict[str, Any]:
            """Scan cloud environment with Scout Suite."""
            logger.info(f"Scanning cloud with Scout Suite: {provider}")
            if not factory._check_tool_available("scout"):
                logger.warning("Scout Suite not found. Install: pip install scoutsuite")
                return {"error": "Scout Suite not installed", "provider": provider}
            
            try:
                cmd = ["scout", provider]
                result = factory._run_command(cmd, timeout=20)
                
                return {
                    "provider": provider,
                    "tool": "scout_suite",
                    "output": result.stdout[:500],
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Scout Suite: {str(e)}")
                return {"error": str(e), "provider": provider}
        
        return scan_cloud_scout_suite
    
    # Register cloud tools
    tools['scan_aws_pacu'] = create_scan_aws_pacu()
    tools['scan_cloud_scout_suite'] = create_scan_cloud_scout_suite()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_cloud_tools',
    'scan_aws_pacu',
    'scan_cloud_scout_suite',
]

