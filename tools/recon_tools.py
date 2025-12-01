"""
Reconnaissance Tools

This module contains integrations for information gathering and reconnaissance tools.

Tool Selection Rationale:
- Subfinder: Fast subdomain discovery tool. Part of ProjectDiscovery suite.
- Amass: Comprehensive subdomain enumeration with multiple data sources.
- theHarvester: Information gathering tool for emails, subdomains, and people.
- ParamSpider: Parameter discovery from web archives. Excellent for finding hidden parameters.
- Arjun: Fast HTTP parameter discovery tool. Complements ParamSpider.
"""

import json
import os
import re
import tempfile
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable
from urllib.parse import urlparse, parse_qs

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_recon_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register reconnaissance tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_discover_subdomains():
        """
        Create discover_subdomains tool.
        
        Why Subfinder + Amass: Subfinder is fast, Amass is comprehensive.
        Together they provide the best subdomain discovery coverage.
        """
        def discover_subdomains(domain: str) -> Dict[str, Any]:
            """Discover subdomains using subfinder and amass."""
            logger.info(f"Discovering subdomains for: {domain}")
            subdomains = set()
            
            if factory._check_tool_available("subfinder"):
                try:
                    result = factory._run_command(
                        ["subfinder", "-d", domain, "-silent"],
                        timeout=20
                    )
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            subdomains.add(line.strip())
                    logger.info(f"Subfinder found {len(subdomains)} subdomains")
                except Exception as e:
                    logger.debug(f"Subfinder error: {str(e)}")
            
            if factory._check_tool_available("amass"):
                try:
                    result = factory._run_command(
                        ["amass", "enum", "-d", domain, "-passive"],
                        timeout=20
                    )
                    for line in result.stdout.strip().split('\n'):
                        if line.strip() and '.' in line:
                            subdomains.add(line.strip())
                    logger.info(f"Amass found additional subdomains. Total: {len(subdomains)}")
                except Exception as e:
                    logger.debug(f"Amass error: {str(e)}")
            
            return {
                "domain": domain,
                "subdomains": list(subdomains),
                "count": len(subdomains),
                "timestamp": datetime.now().isoformat()
            }
        
        return discover_subdomains
    
    def create_discover_with_theharvester():
        """
        Create discover_with_theharvester tool.
        
        Why theHarvester: Excellent for finding emails, subdomains, and people information.
        Multiple data sources including search engines and public databases.
        """
        def discover_with_theharvester(domain: str, sources: str = "all") -> Dict[str, Any]:
            """Discover emails, subdomains, and people using theHarvester."""
            logger.info(f"Discovering with theHarvester: {domain}")
            if not factory._check_tool_available("theHarvester"):
                logger.warning("theHarvester not found in PATH. Install: pip install theHarvester")
                return {"error": "theHarvester not installed", "domain": domain}
            
            try:
                cmd = ["theHarvester", "-d", domain, "-b", sources, "-f", "/tmp/theharvester_output"]
                result = factory._run_command(cmd, timeout=20)
                
                # Parse output
                emails = []
                hosts = []
                
                for line in result.stdout.split('\n'):
                    if '@' in line:
                        emails.extend(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', line))
                    if domain in line and '.' in line:
                        hosts.append(line.strip())
                
                return {
                    "domain": domain,
                    "tool": "theharvester",
                    "emails": list(set(emails)),
                    "hosts": list(set(hosts)),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running theHarvester: {str(e)}")
                return {"error": str(e), "domain": domain}
        
        return discover_with_theharvester
    
    def create_discover_parameters():
        """
        Create discover_parameters tool.
        
        Why ParamSpider + Arjun: ParamSpider finds parameters from web archives,
        Arjun discovers parameters through active testing. Together they provide comprehensive coverage.
        """
        def discover_parameters(url: str) -> Dict[str, Any]:
            """Discover URL parameters using ParamSpider and Arjun."""
            logger.info(f"Discovering parameters for: {url}")
            parameters = set()
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if factory._check_tool_available("paramspider"):
                try:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        result = factory._run_command(
                            ["paramspider", "-d", domain, "-o", tmpdir],
                            timeout=20
                        )
                        output_file = os.path.join(tmpdir, f"{domain}.txt")
                        if os.path.exists(output_file):
                            with open(output_file, 'r') as f:
                                for line in f:
                                    if '?' in line:
                                        params = parse_qs(urlparse(line.strip()).query)
                                        parameters.update(params.keys())
                except Exception as e:
                    logger.debug(f"ParamSpider error: {str(e)}")
            
            if factory._check_tool_available("arjun"):
                try:
                    result = factory._run_command(
                        ["arjun", "-u", url, "--json"],
                        timeout=20
                    )
                    try:
                        arjun_data = json.loads(result.stdout)
                        if isinstance(arjun_data, dict) and 'params' in arjun_data:
                            parameters.update(arjun_data['params'])
                    except json.JSONDecodeError:
                        for line in result.stdout.split('\n'):
                            if 'Parameter' in line or 'Found' in line:
                                matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)', line)
                                parameters.update(matches)
                except Exception as e:
                    logger.debug(f"Arjun error: {str(e)}")
            
            return {
                "url": url,
                "parameters": list(parameters),
                "count": len(parameters),
                "timestamp": datetime.now().isoformat()
            }
        
        return discover_parameters
    
    # Register all reconnaissance tools
    tools['discover_subdomains'] = create_discover_subdomains()
    tools['discover_with_theharvester'] = create_discover_with_theharvester()
    tools['discover_parameters'] = create_discover_parameters()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_recon_tools',
    'discover_subdomains',
    'discover_with_theharvester',
    'discover_parameters',
]

