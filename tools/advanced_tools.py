"""
Advanced Tools - All Additional Tools

These tools are not loaded by default. Enable them when needed for advanced testing.
Includes: network scanning, AD tools, password cracking, cloud tools, etc.
"""

from typing import Dict, Any, Callable

from .tool_factory import RedTeamToolFactory
from .utility_tools import register_utility_tools
from .web_app_tools import register_web_app_tools
from .network_tools import register_network_tools
from .recon_tools import register_recon_tools
from .directory_tools import register_directory_tools
from .fuzzing_tools import register_fuzzing_tools
from .ad_tools import register_ad_tools
from .exploitation_tools import register_exploitation_tools
from .password_tools import register_password_tools
from .post_exploit_tools import register_post_exploit_tools
from .api_tools import register_api_tools
from .cloud_tools import register_cloud_tools


def register_advanced_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register all advanced tools (everything except the top 5 essential tools).
    
    Advanced Tools Include:
    - Additional web app scanners (XSStrike, OWASP ZAP, Nikto, Wapiti)
    - Network tools (Nmap, Masscan, RustScan)
    - Reconnaissance (Subfinder, Amass, theHarvester, ParamSpider, Arjun)
    - Directory brute forcing (Gobuster, FFuF)
    - Fuzzing (Wfuzz)
    - Active Directory (BloodHound, CrackMapExec)
    - Exploitation (Metasploit)
    - Password tools (Hashcat, John, Hydra)
    - Post-exploitation tools
    - API security tools
    - Cloud security tools
    - Additional utility tools (analyze_response_security)
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    # Load all tool categories
    utility_tools = register_utility_tools(factory)
    web_app_tools = register_web_app_tools(factory)
    network_tools = register_network_tools(factory)
    recon_tools = register_recon_tools(factory)
    directory_tools = register_directory_tools(factory)
    fuzzing_tools = register_fuzzing_tools(factory)
    ad_tools = register_ad_tools(factory)
    exploitation_tools = register_exploitation_tools(factory)
    password_tools = register_password_tools(factory)
    post_exploit_tools = register_post_exploit_tools(factory)
    api_tools = register_api_tools(factory)
    cloud_tools = register_cloud_tools(factory)
    
    # Essential tools that should NOT be in advanced (they're already loaded)
    essential_tool_names = {
        'fetch_page',
        'scan_with_nuclei',
        'scan_with_sqlmap',
        'scan_xss_with_dalfox',
        'generate_report',
    }
    
    # Add all tools except essential ones
    all_tool_sources = [
        utility_tools,
        web_app_tools,
        network_tools,
        recon_tools,
        directory_tools,
        fuzzing_tools,
        ad_tools,
        exploitation_tools,
        password_tools,
        post_exploit_tools,
        api_tools,
        cloud_tools,
    ]
    
    for tool_source in all_tool_sources:
        for tool_name, tool_func in tool_source.items():
            if tool_name not in essential_tool_names:
                tools[tool_name] = tool_func
    
    return tools


# Export tool names
__all__ = [
    'register_advanced_tools',
]

