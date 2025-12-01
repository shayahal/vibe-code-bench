"""
Tool Loader

This module loads and registers all red-team tools from category modules.
It provides a unified interface for accessing all tools through the factory.
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


def load_all_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Load all tools from all category modules.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    all_tools = {}
    
    # Load tools from each category
    all_tools.update(register_utility_tools(factory))
    all_tools.update(register_web_app_tools(factory))
    all_tools.update(register_network_tools(factory))
    all_tools.update(register_recon_tools(factory))
    all_tools.update(register_directory_tools(factory))
    all_tools.update(register_fuzzing_tools(factory))
    all_tools.update(register_ad_tools(factory))
    all_tools.update(register_exploitation_tools(factory))
    all_tools.update(register_password_tools(factory))
    all_tools.update(register_post_exploit_tools(factory))
    all_tools.update(register_api_tools(factory))
    all_tools.update(register_cloud_tools(factory))
    
    return all_tools

