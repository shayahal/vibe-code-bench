"""
Directory & File Discovery Tools

This module contains integrations for directory and file brute-forcing tools.

Tool Selection Rationale:
- Gobuster: Fast directory/file brute-forcing tool written in Go. Excellent performance.
- FFuF: Fast web fuzzer with advanced filtering. Complements Gobuster with different approach.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_directory_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register directory & file discovery tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_brute_force_directories():
        """
        Create brute_force_directories tool.
        
        Why Gobuster + FFuF: Gobuster is fast and reliable, FFuF offers advanced filtering.
        Together they provide comprehensive directory discovery.
        """
        def brute_force_directories(url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
            """Brute force directories/files using Gobuster or FFuF."""
            logger.info(f"Brute forcing directories: {url}")
            found_paths = []
            
            if factory._check_tool_available("gobuster"):
                try:
                    cmd = ["gobuster", "dir", "-u", url, "-q", "-k"]
                    if wordlist:
                        cmd.extend(["-w", wordlist])
                    else:
                        cmd.extend(["-w", "/usr/share/wordlists/dirb/common.txt"])
                    
                    result = factory._run_command(cmd, timeout=20)
                    
                    for line in result.stdout.split('\n'):
                        if line.strip() and ('Status: 200' in line or 'Status: 301' in line or 'Status: 302' in line):
                            parts = line.split()
                            if parts:
                                found_paths.append(parts[0])
                except Exception as e:
                    logger.debug(f"Gobuster error: {str(e)}")
            
            if factory._check_tool_available("ffuf") and not found_paths:
                try:
                    cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w"]
                    if wordlist:
                        cmd.append(wordlist)
                    else:
                        cmd.append("/usr/share/wordlists/dirb/common.txt")
                    cmd.extend(["-s", "-json"])
                    
                    result = factory._run_command(cmd, timeout=20)
                    
                    try:
                        ffuf_data = json.loads(result.stdout)
                        if 'results' in ffuf_data:
                            for item in ffuf_data['results']:
                                if item.get('status') in [200, 301, 302]:
                                    found_paths.append(item.get('url', ''))
                    except json.JSONDecodeError:
                        for line in result.stdout.split('\n'):
                            if '200' in line or '301' in line or '302' in line:
                                found_paths.append(line.strip())
                except Exception as e:
                    logger.debug(f"FFuF error: {str(e)}")
            
            return {
                "url": url,
                "found_paths": found_paths,
                "count": len(found_paths),
                "timestamp": datetime.now().isoformat()
            }
        
        return brute_force_directories
    
    # Register directory tools
    tools['brute_force_directories'] = create_brute_force_directories()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_directory_tools',
    'brute_force_directories',
]

