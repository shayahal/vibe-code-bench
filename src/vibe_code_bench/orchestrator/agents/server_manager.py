"""
Server Manager Node

Manages the Flask server lifecycle (start/stop).
"""

import importlib.util
import sys
from pathlib import Path

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.paths import get_repo_root
from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)

# Import WebsiteServer from the main orchestrator module
# We need to import it this way to avoid circular imports
orchestrator_file = get_repo_root() / "orchestrator.py"
spec = importlib.util.spec_from_file_location("orchestrator_main", orchestrator_file)
orchestrator_main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(orchestrator_main)
WebsiteServer = orchestrator_main.WebsiteServer


def server_manager_node(state: OrchestratorState) -> OrchestratorState:
    """
    Manage the Flask server (start or stop).
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Updated state with url (if starting) or server stopped (if stopping)
    """
    website_dir = state.get("website_dir")
    url = state.get("url")
    server = state.get("server")
    port = state.get("port", 5000)
    red_team_result = state.get("red_team_result")
    
    # Determine if we need to start or stop
    if not url and website_dir:
        # Need to start server
        logger.info("="*60)
        logger.info("STEP 2: Starting Website Server")
        logger.info("="*60)
        
        server = WebsiteServer(website_dir, port=port)
        if not server.start():
            logger.error("Failed to start website server")
            raise Exception("Failed to start website server")
        
        url = server.url
        logger.info(f"Website server started at {url}")
        
        return {
            **state,
            'url': url,
            'server': server,
            'next': 'red_team_agent'  # Next step is to run red team agent
        }
    
    elif url and server and red_team_result:
        # Need to stop server (after red team testing)
        logger.info("="*60)
        logger.info("STEP 4: Putting Website to Sleep")
        logger.info("="*60)
        
        server.stop()
        logger.info("Website server stopped (put to sleep)")
        
        return {
            **state,
            'server': None,  # Clear server reference
            'next': 'evaluator'  # Next step is to evaluate findings
        }
    
    else:
        # Unexpected state
        raise ValueError(f"Unexpected server manager state: url={url}, server={server is not None}, red_team_result={red_team_result is not None}")

