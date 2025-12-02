"""
Main entry point for Website Generator.

Flow:
1. Get system & user prompts from constants
2. Send to LLM
3. Parse JSON response
4. Create files in uniquely named folder
5. Ensure exactly one main.py exists
"""

import os
import json
import logging
import sys
import time
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

from langchain_core.messages import HumanMessage, SystemMessage

from core.llm_setup import initialize_llm
from core.run_directory import setup_run_directory
from core.logging_setup import setup_file_logging
from .prompts import SYSTEM_PROMPT, USER_PROMPT

# Load environment variables
load_dotenv()

# Configure logging - same as red team agent
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Import LangFuse (required) - LangChain integration
try:
    from langfuse.langchain import CallbackHandler as LangfuseCallbackHandler
    from langfuse import Langfuse
except ImportError:
    print("Error: langfuse is required. Install with: pip install langfuse")
    sys.exit(1)


def create_unique_folder(base_dir: Path) -> Path:
    """
    Create a uniquely named folder for website files.
    
    Args:
        base_dir: Base directory (run directory)
    
    Returns:
        Path to the created website folder
    """
    website_dir = base_dir / "website"
    website_dir.mkdir(exist_ok=True)
    
    return website_dir


def ensure_main_py(files: dict) -> dict:
    """
    Ensure there is exactly one main.py file.
    If multiple exist, keep the first one.
    If none exist, create a placeholder.
    
    Args:
        files: Dictionary of filename -> content
    
    Returns:
        Updated files dictionary with exactly one main.py
    """
    main_py_files = [f for f in files.keys() if f == "main.py" or f.endswith("/main.py")]
    
    if len(main_py_files) > 1:
        logger.warning(f"Found {len(main_py_files)} main.py files, keeping only the first one")
        # Remove all but the first
        for f in main_py_files[1:]:
            del files[f]
    
    elif len(main_py_files) == 0:
        logger.info("No main.py found, creating placeholder main.py")
        files["main.py"] = """#!/usr/bin/env python3
\"\"\"
Main entry point for the project.
\"\"\"

if __name__ == "__main__":
    print("Project created successfully!")
"""
    
    # Ensure it's exactly "main.py" (not in subdirectory)
    if "main.py" not in files:
        # Check if there's a main.py in a subdirectory
        for key in list(files.keys()):
            if key.endswith("/main.py") or key.endswith("\\main.py"):
                files["main.py"] = files.pop(key)
                logger.info(f"Moved {key} to main.py")
                break
    
    return files


def parse_json_response(response_text: str) -> dict:
    """
    Parse JSON from LLM response.
    Handles cases where JSON might be wrapped in markdown code blocks.
    
    Args:
        response_text: LLM response text
    
    Returns:
        Dictionary with files
    """
    # Try to extract JSON from markdown code blocks
    import re
    json_match = re.search(r'```(?:json)?\s*\n?(\{.*?\})\n?```', response_text, re.DOTALL)
    if json_match:
        response_text = json_match.group(1)
    
    # Try to find JSON object in the text
    json_match = re.search(r'\{.*"files".*\}', response_text, re.DOTALL)
    if json_match:
        response_text = json_match.group(0)
    
    try:
        data = json.loads(response_text)
        if "files" in data:
            return data["files"]
        else:
            # If response is just the files dict directly
            return data
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {e}")
        logger.error(f"Response text (first 500 chars): {response_text[:500]}")
        raise ValueError(f"Invalid JSON response from LLM: {e}")


def write_files(files: dict, output_dir: Path) -> list:
    """
    Write all files to the output directory.
    
    Args:
        files: Dictionary of filename -> content
        output_dir: Directory to write files to
    
    Returns:
        List of created file info
    """
    created_files = []
    
    for filename, content in files.items():
        try:
            # Handle subdirectories in filename
            file_path = output_dir / filename
            
            # Create parent directories if needed
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            file_info = {
                "name": filename,
                "path": str(file_path),
                "size": len(content.encode('utf-8'))
            }
            created_files.append(file_info)
            
            logger.info(f"Created: {filename} ({file_info['size']} bytes)")
            
        except Exception as e:
            logger.error(f"Error writing file {filename}: {e}")
    
    return created_files


def main():
    """Main execution flow."""
    # Create run directory with unique timestamp ID
    run_dir = setup_run_directory(base_dir="runs")
    run_id = run_dir.name
    logger.info("=" * 60)
    logger.info(f"Starting Website Generator Run: {run_id}")
    logger.info(f"Run Directory: {run_dir}")
    logger.info("=" * 60)
    
    # Set up file logging - unified logging system
    setup_file_logging(run_dir)
    
    # Initialize LangFuse (required) - following LangChain integration pattern
    # See: https://langfuse.com/docs/observability/get-started
    # The CallbackHandler reads credentials from environment variables automatically
    langfuse_secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    langfuse_public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    langfuse_host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
    
    if not langfuse_secret_key or not langfuse_public_key:
        logger.error("Error: LangFuse credentials not found.")
        logger.error("  Please set LANGFUSE_SECRET_KEY and LANGFUSE_PUBLIC_KEY in your .env file.")
        logger.error("  You can get these from https://cloud.langfuse.com")
        sys.exit(1)
    
    try:
        # Initialize LangFuse client for fetching trace data
        langfuse_client = Langfuse(
            secret_key=langfuse_secret_key,
            public_key=langfuse_public_key,
            host=langfuse_host
        )
        
        # Initialize LangFuse CallbackHandler for LangChain
        # It automatically reads LANGFUSE_SECRET_KEY, LANGFUSE_PUBLIC_KEY, and LANGFUSE_HOST from env
        # This automatically captures all LLM calls, tool calls, and agent actions
        langfuse_handler = LangfuseCallbackHandler()
        logger.info(f"LangFuse initialized (host: {langfuse_host})")
        logger.info("  Using LangChain integration - all traces will be automatically captured")
    except Exception as e:
        logger.error(f"Error initializing LangFuse: {e}")
        logger.error("  Make sure LANGFUSE_SECRET_KEY and LANGFUSE_PUBLIC_KEY are set in your .env file")
        sys.exit(1)
    
    # Step 1: Get prompts from constants
    system_prompt = SYSTEM_PROMPT
    user_prompt = USER_PROMPT
    
    logger.info("Using prompts from constants")
    logger.info(f"System prompt length: {len(system_prompt)} chars")
    logger.info(f"User prompt length: {len(user_prompt)} chars")
    
    # Step 2: Initialize LLM - always use OpenRouter with cheap model
    provider = "openrouter"  # Always use OpenRouter
    cheap_model = os.getenv("WEBSITE_CREATOR_MODEL", "openai/gpt-3.5-turbo")  # Default to cheap model
    api_key = os.getenv("OPENROUTER_API_KEY")
    
    if not api_key:
        logger.error("Error: OPENROUTER_API_KEY not found. Set it as env var")
        sys.exit(1)
    
    logger.info(f"Initializing LLM (provider: {provider}, model: {cheap_model})...")
    
    try:
        llm, model_name = initialize_llm(
            provider=provider,
            model_name=cheap_model,
            temperature=0.7,
            api_key=api_key
        )
        # Increase max_tokens for website generation (need more tokens for full website)
        if hasattr(llm, 'max_tokens'):
            llm.max_tokens = 8000  # Increase for website generation
        logger.info(f"LLM initialized: {model_name}")
    except Exception as e:
        logger.error(f"Failed to initialize LLM: {e}")
        return 1
    
    # Step 3: Send prompts to LLM
    logger.info("Sending prompts to LLM...")
    
    # Track start time for execution duration
    start_time = time.time()
    
    try:
        # Prepare messages
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ]
        
        # Invoke LLM with LangFuse callback handler if available
        # The handler automatically captures:
        # - All LLM calls (inputs, outputs, tokens, costs)
        # - Full trace structure
        if langfuse_handler:
            response = llm.invoke(
                messages,
                config={
                    "callbacks": [langfuse_handler],
                    "metadata": {
                        "project_type": "pizzeria_website",
                        "model": model_name,
                        "provider": provider,
                        "timestamp": datetime.now().isoformat()
                    }
                }
            )
        else:
            response = llm.invoke(messages)
        
        # Extract content
        if hasattr(response, 'content'):
            response_text = response.content
        else:
            response_text = str(response)
        
        execution_time = time.time() - start_time
        logger.info(f"Received response ({len(response_text)} chars) in {execution_time:.2f}s")
        
    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        return 1
    
    # Step 4: Parse JSON response
    logger.info("Parsing JSON response...")
    
    try:
        files = parse_json_response(response_text)
        logger.info(f"Parsed {len(files)} files from response")
    except Exception as e:
        logger.error(f"Failed to parse JSON: {e}")
        return 1
    
    # Step 5: Ensure exactly one main.py
    files = ensure_main_py(files)
    
    # Step 6: Create unique folder in run directory
    output_dir = create_unique_folder(run_dir)
    logger.info(f"Created output folder: {output_dir}")
    
    # Step 7: Write files
    logger.info("Writing files...")
    created_files = write_files(files, output_dir)
    
    # Summary
    logger.info("=" * 60)
    logger.info("Project creation completed!")
    logger.info("=" * 60)
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Total files created: {len(created_files)}")
    logger.info("\nCreated files:")
    for file_info in created_files:
        logger.info(f"  - {file_info['name']} ({file_info['size']} bytes)")
    logger.info("=" * 60)
    
    # Check for main.py
    main_py_path = output_dir / "main.py"
    if main_py_path.exists():
        logger.info(f"\nmain.py found at: {main_py_path}")
    else:
        logger.warning(f"\nWARNING: main.py not found (this shouldn't happen)")
    
    # Wait a moment for LangFuse to process the trace
    time.sleep(2)
    langfuse_client.flush()  # Ensure data is sent
    time.sleep(1)  # Give it a moment to process
    
    logger.info("=" * 60)
    logger.info(f"All observability data logged to LangFuse")
    logger.info(f"  - Check your LangFuse dashboard: {langfuse_host}")
    logger.info(f"Website files created in: {output_dir}")
    logger.info(f"Run directory: {run_dir}")
    logger.info(f"  - Logs: {run_dir / 'logs'}")
    logger.info(f"  - Website: {output_dir}")
    logger.info("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
