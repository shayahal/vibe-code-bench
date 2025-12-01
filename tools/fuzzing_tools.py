"""
Fuzzing Tools

This module contains integrations for web fuzzing and parameter testing tools.

Tool Selection Rationale:
- Wfuzz: Powerful web fuzzer with advanced filtering and payload management.
Excellent for testing parameters, headers, and authentication mechanisms.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_fuzzing_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register fuzzing tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_scan_with_wfuzz():
        """
        Create scan_with_wfuzz tool.
        
        Why Wfuzz: Powerful web fuzzer with advanced filtering capabilities.
        Excellent for parameter fuzzing, authentication testing, and custom payloads.
        """
        def scan_with_wfuzz(url: str, parameter: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
            """Fuzz parameters with Wfuzz."""
            logger.info(f"Fuzzing with Wfuzz: {url}, parameter: {parameter}")
            if not factory._check_tool_available("wfuzz"):
                logger.warning("Wfuzz not found in PATH. Install from: https://github.com/xmendez/wfuzz")
                return {"error": "Wfuzz not installed", "url": url}
            
            try:
                fuzz_url = f"{url}?{parameter}=FUZZ"
                cmd = ["wfuzz", "-c", "-z", "file"]
                if wordlist:
                    cmd.append(wordlist)
                else:
                    cmd.append("/usr/share/wordlists/rockyou.txt")
                cmd.extend(["-f", "json", fuzz_url])
                
                result = factory._run_command(cmd, timeout=20)
                
                findings = []
                try:
                    wfuzz_data = json.loads(result.stdout)
                    if isinstance(wfuzz_data, list):
                        findings = wfuzz_data
                except json.JSONDecodeError:
                    for line in result.stdout.split('\n'):
                        if '200' in line or '301' in line or '302' in line:
                            findings.append({"raw": line})
                
                return {
                    "url": url,
                    "parameter": parameter,
                    "tool": "wfuzz",
                    "findings": findings,
                    "count": len(findings),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Wfuzz: {str(e)}")
                return {"error": str(e), "url": url}
        
        return scan_with_wfuzz
    
    # Register fuzzing tools
    tools['scan_with_wfuzz'] = create_scan_with_wfuzz()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_fuzzing_tools',
    'scan_with_wfuzz',
]

