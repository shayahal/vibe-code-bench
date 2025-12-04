"""
Website Builder Agent Node

Builds a website using the website builder agent.
"""

import os
import time
from datetime import datetime
from pathlib import Path
from langchain_core.messages import HumanMessage, SystemMessage

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.llm_setup import initialize_llm
from vibe_code_bench.website_generator.prompts import SYSTEM_PROMPT, USER_PROMPT
from vibe_code_bench.website_generator.main import parse_json_response, write_files, ensure_main_py


def website_builder_node(state: OrchestratorState) -> OrchestratorState:
    """
    Build a website using the website builder agent.
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Updated state with build_result and website_dir
    """
    print("\n" + "="*60)
    print("STEP 1: Building Website")
    print("="*60)
    
    # Get prompt from state or use default
    prompt = state.get("prompt") or USER_PROMPT
    
    # Get output directory from state (should be set by orchestrator)
    output_dir = state.get("output_dir")
    if not output_dir:
        raise ValueError("output_dir not set in state")
    
    # Create run directory
    run_id = state.get("run_id") or datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = output_dir / f"run_{run_id}"
    website_dir = run_dir / "website"
    website_dir.mkdir(parents=True, exist_ok=True)
    
    # Use main.py's approach: SYSTEM_PROMPT + USER_PROMPT
    system_prompt = SYSTEM_PROMPT
    user_prompt = prompt
    
    # Initialize LLM
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise Exception("OPENROUTER_API_KEY not found")
    
    website_builder_model = state.get("website_builder_model", "anthropic/claude-3-haiku")
    
    llm, model_name = initialize_llm(
        provider="openrouter",
        model_name=website_builder_model,
        temperature=0.7,
        api_key=api_key
    )
    
    # Increase max_tokens for website generation
    if hasattr(llm, 'max_tokens'):
        llm.max_tokens = 8000
    
    print(f"✓ Using model: {model_name}")
    
    # Invoke LLM
    print("Generating website code...")
    start_time = time.time()
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt)
    ])
    
    # Extract content
    if hasattr(response, 'content'):
        response_text = response.content
    else:
        response_text = str(response)
    
    execution_time = time.time() - start_time
    print(f"✓ Generated {len(response_text)} characters in {execution_time:.2f}s")
    
    # Parse JSON response using main.py's robust parser
    print("Parsing JSON response...")
    # Use main.py's parse_json_response function which handles markdown code blocks, etc.
    files = parse_json_response(response_text)
    print(f"✓ Parsed {len(files)} files")
    
    # Ensure main.py exists
    files = ensure_main_py(files)
    
    # Write files using main.py's function
    print("Writing files...")
    created_files = write_files(files, website_dir)
    
    print(f"✓ Website built successfully")
    print(f"  Execution time: {execution_time:.2f}s")
    print(f"  Output directory: {website_dir}")
    print(f"  Files created: {len(created_files)}")
    
    # Update state
    build_result = {
        'run_id': run_id,
        'run_dir': run_dir,
        'website_dir': website_dir,
        'result': {
            'status': 'success',
            'output_directory': str(website_dir),
            'created_files': created_files,
            'total_files': len(created_files),
            'execution_time': execution_time
        }
    }
    
    # Return updated state
    return {
        **state,
        'run_id': run_id,
        'website_dir': website_dir,
        'build_result': build_result,
        'next': 'server_manager'  # Next step is to start the server
    }

