"""
Active Directory Security Tools

This module contains integrations for Active Directory security testing tools.

Tool Selection Rationale:
- BloodHound: Industry standard for AD attack path mapping. Visualizes privilege escalation paths.
- CrackMapExec: Network pentesting framework for AD environments. Excellent for lateral movement testing.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_ad_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register Active Directory security tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_bloodhound_ingest():
        """
        Create bloodhound_ingest tool.
        
        Why BloodHound: Industry standard for Active Directory attack path mapping.
        Visualizes complex AD relationships and privilege escalation paths.
        """
        def bloodhound_ingest(domain: str, collection_method: str = "all") -> Dict[str, Any]:
            """Collect data for BloodHound analysis."""
            logger.info(f"Collecting BloodHound data for: {domain}")
            if not factory._check_tool_available("bloodhound-python"):
                logger.warning("BloodHound Python not found. Install: pip install bloodhound")
                return {"error": "BloodHound Python not installed", "domain": domain}
            
            try:
                cmd = ["bloodhound-python", "-d", domain, "-c", collection_method, "-gc", domain]
                result = factory._run_command(cmd, timeout=20)
                
                return {
                    "domain": domain,
                    "tool": "bloodhound",
                    "collection_method": collection_method,
                    "output": result.stdout[:500],
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running BloodHound: {str(e)}")
                return {"error": str(e), "domain": domain}
        
        return bloodhound_ingest
    
    def create_crackmapexec_scan():
        """
        Create crackmapexec_scan tool.
        
        Why CrackMapExec: Network pentesting framework for AD environments.
        Excellent for lateral movement, credential testing, and AD enumeration.
        """
        def crackmapexec_scan(target: str, scan_type: str = "smb") -> Dict[str, Any]:
            """Scan with CrackMapExec."""
            logger.info(f"Scanning with CrackMapExec: {target}")
            if not factory._check_tool_available("crackmapexec"):
                logger.warning("CrackMapExec not found. Install: pip install crackmapexec")
                return {"error": "CrackMapExec not installed", "target": target}
            
            try:
                cmd = ["crackmapexec", scan_type, target]
                result = factory._run_command(cmd, timeout=20)
                
                return {
                    "target": target,
                    "tool": "crackmapexec",
                    "scan_type": scan_type,
                    "output": result.stdout,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running CrackMapExec: {str(e)}")
                return {"error": str(e), "target": target}
        
        return crackmapexec_scan
    
    # Register AD tools
    tools['bloodhound_ingest'] = create_bloodhound_ingest()
    tools['crackmapexec_scan'] = create_crackmapexec_scan()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_ad_tools',
    'bloodhound_ingest',
    'crackmapexec_scan',
]

