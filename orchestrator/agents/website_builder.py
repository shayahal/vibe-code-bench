"""
Website Builder Agent Node

Builds a website using the website builder agent.
"""

import os
import time
from datetime import datetime
from pathlib import Path
from langchain_core.messages import HumanMessage, SystemMessage

from orchestrator.state import OrchestratorState
from core.llm_setup import initialize_llm
from website_generator.prompts import SYSTEM_PROMPT, USER_PROMPT
from website_generator.main import parse_json_response, write_files, ensure_main_py


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
    
    # Parse JSON response
    print("Parsing JSON response...")
    # Extract JSON object (find first { and matching })
    json_start = response_text.find('{')
    if json_start < 0:
        raise Exception("No JSON object found in LLM response")
    
    # Count braces to find matching closing brace
    brace_count = 0
    json_end = json_start
    for i in range(json_start, len(response_text)):
        if response_text[i] == '{':
            brace_count += 1
        elif response_text[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                json_end = i + 1
                break
    
    if json_end <= json_start:
        raise Exception("Could not find matching closing brace in JSON")
    
    json_text = response_text[json_start:json_end]
    # Use main.py's parse_json_response function on the extracted JSON
    files = parse_json_response(json_text)
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

