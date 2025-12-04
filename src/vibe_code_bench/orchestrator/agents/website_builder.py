"""
Website Builder Agent Node

Builds a website using the website builder agent (evaluation happens separately).
"""

from pathlib import Path

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.logging_setup import get_logger
from vibe_code_bench.website_generator.main import generate_website
from vibe_code_bench.website_generator.prompts import USER_PROMPT

logger = get_logger(__name__)


def website_builder_node(state: OrchestratorState) -> OrchestratorState:
    """
    Build a website using the website builder agent.
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Updated state with build_result and website_dir
    """
    logger.info("="*60)
    logger.info("STEP 1: Building Website")
    logger.info("="*60)
    
    # Get prompt from state or use default
    prompt = state.get("prompt") or USER_PROMPT

    # Get directories from state (created by orchestrator main)
    run_id = state.get("run_id")
    website_dir = state.get("website_dir")

    if not run_id or not website_dir:
        logger.error("run_id or website_dir not set in state")
        raise ValueError("run_id or website_dir not set in state")

    logger.debug(f"Using website directory: {website_dir}")
    
    # Use main.py's generate_website function directly
    website_builder_model = state.get("website_builder_model", "anthropic/claude-3-haiku")
    
    logger.info(f"Generating website with model: {website_builder_model}")
    build_result_dict = generate_website(
        user_prompt=prompt,
        output_dir=website_dir,
        model_name=website_builder_model,
        provider="openrouter",
        skip_langfuse=False  # Use LangFuse for tracking
    )
    
    if build_result_dict.get("status") != "success":
        error_msg = build_result_dict.get("error", "Unknown error")
        logger.error(f"Website build failed: {error_msg}")
        raise Exception(f"Website build failed: {error_msg}")
    
    logger.info("Website built successfully")
    logger.info(f"Output directory: {website_dir}")
    logger.info(f"Files created: {build_result_dict.get('total_files', 0)}")
    
    # Build result structure for state
    build_result = {
        'run_id': run_id,
        'website_dir': website_dir,
        'result': {
            'status': 'success',
            'output_directory': str(website_dir),
            'created_files': build_result_dict.get('created_files', []),
            'total_files': build_result_dict.get('total_files', 0),
            'execution_time': build_result_dict.get('execution_time', 0)
        }
    }

    # Return updated state (evaluation will happen later)
    return {
        **state,
        'build_result': build_result,
        'next': 'server_manager'  # Next step is to start the server
    }

