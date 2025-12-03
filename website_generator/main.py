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
from typing import Optional
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from langchain_core.messages import HumanMessage, SystemMessage

from core.llm_setup import initialize_llm
from core.run_directory import setup_run_directory
from core.logging_setup import setup_file_logging
from website_generator.prompts import SYSTEM_PROMPT, USER_PROMPT

# Load environment variables
load_dotenv()

# Configure root logger for early error handling
logger = logging.getLogger(__name__)

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
        logger.info("No main.py found, creating Flask app template")
        # Create a basic Flask app that serves HTML files
        # Use port from environment variable FLASK_PORT or default to 5000
        files["main.py"] = """#!/usr/bin/env python3
\"\"\"
Flask application to serve the website.
\"\"\"
from flask import Flask, send_file
import os

app = Flask(__name__)

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/<path:filename>')
def serve_file(filename):
    if os.path.exists(filename):
        return send_file(filename)
    return send_file('index.html'), 404

if __name__ == '__main__':
    port = int(os.environ.get('FLASK_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
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
    if not response_text or len(response_text.strip()) == 0:
        raise ValueError("Empty response from LLM")
    
    # Strip whitespace from start and end
    response_text = response_text.strip()
    
    # Try to extract JSON from markdown code blocks
    import re
    json_match = re.search(r'```(?:json)?\s*\n?(\{.*?\})\n?```', response_text, re.DOTALL)
    if json_match:
        response_text = json_match.group(1).strip()
    
    # If response doesn't start with {, try to find JSON object in the text
    if not response_text.startswith('{'):
        json_match = re.search(r'\{.*"files".*\}', response_text, re.DOTALL)
        if json_match:
            response_text = json_match.group(0).strip()
    
    # Try to fix common JSON issues
    # Remove trailing commas before closing braces/brackets
    response_text = re.sub(r',(\s*[}\]])', r'\1', response_text)
    
    # Ensure it starts with {
    if not response_text.startswith('{'):
        raise ValueError(f"Response does not start with {{. First 100 chars: {response_text[:100]}")
    
    try:
        data = json.loads(response_text)
        if "files" in data:
            return data["files"]
        else:
            # If response is just the files dict directly
            return data
    except json.JSONDecodeError as e:
        error_str = str(e).lower()
        
        # If it's an unterminated string (truncation), try to salvage what we can
        if 'unterminated' in error_str:
            logger.warning("Response appears truncated. Attempting to extract complete file entries...")
            try:
                # Find the "files" section
                files_match = re.search(r'"files"\s*:\s*\{', response_text)
                if files_match:
                    # Try to find all complete file entries by looking for the pattern:
                    # "filename": "content" where content ends with a closing quote
                    # This is a simplified approach - find entries that are complete
                    files_section = response_text[files_match.end():]
                    
                    # Find all file entries with pattern: "filename": "content"
                    # We'll look for entries that have a closing quote followed by comma or }
                    file_entries = re.finditer(r'"([^"]+)"\s*:\s*"', files_section)
                    salvaged_files = {}
                    
                    for entry_match in file_entries:
                        filename = entry_match.group(1)
                        value_start = entry_match.end()
                        
                        # Try to find the matching closing quote (handling escapes)
                        i = value_start
                        found_closing = False
                        while i < len(files_section):
                            if files_section[i] == '\\':
                                i += 2  # Skip escaped char
                                continue
                            elif files_section[i] == '"':
                                # Check if followed by comma or }
                                j = i + 1
                                while j < len(files_section) and files_section[j] in ' \t\n\r':
                                    j += 1
                                if j < len(files_section) and files_section[j] in [',', '}']:
                                    # Complete entry found
                                    value = files_section[value_start:i]
                                    # Unescape the value
                                    value = value.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
                                    salvaged_files[filename] = value
                                    found_closing = True
                                    break
                            i += 1
                        
                        if not found_closing:
                            # This entry is incomplete, stop here
                            break
                    
                    if salvaged_files:
                        logger.warning(f"Salvaged {len(salvaged_files)} complete files from truncated response")
                        return salvaged_files
            except Exception as salvage_error:
                logger.debug(f"Failed to salvage truncated JSON: {salvage_error}")
        
        # Try to extract just the files portion if the error is in escape sequences
        try:
            # Look for the "files" key and try to extract its value
            files_match = re.search(r'"files"\s*:\s*(\{.*?\})', response_text, re.DOTALL)
            if files_match:
                files_json = files_match.group(1)
                # Try to balance braces and extract valid JSON
                brace_count = 0
                end_pos = 0
                for i, char in enumerate(files_json):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end_pos = i + 1
                            break
                if end_pos > 0:
                    files_json = files_json[:end_pos]
                    files_data = json.loads(files_json)
                    return files_data
        except:
            pass
        
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


def generate_website(
    user_prompt: str,
    output_dir: Path,
    model_name: Optional[str] = None,
    provider: str = "openrouter",
    system_prompt: Optional[str] = None,
    skip_langfuse: bool = False
) -> dict:
    """
    Generate a website programmatically.
    
    Args:
        user_prompt: The user prompt describing the website to create
        output_dir: Directory where website files should be saved
        model_name: Model to use (defaults based on provider)
        provider: LLM provider ('openrouter', 'anthropic', or 'openai')
        system_prompt: Custom system prompt (defaults to SYSTEM_PROMPT)
        skip_langfuse: If True, skip LangFuse initialization (for batch runs)
    
    Returns:
        Dictionary with status and results:
        {
            "status": "success" or "error",
            "output_directory": str,
            "created_files": list,
            "total_files": int,
            "error": str (if status is "error")
        }
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Use default system prompt if not provided
    if system_prompt is None:
        system_prompt = SYSTEM_PROMPT
    
    # Initialize LangFuse if not skipped
    langfuse_client = None
    langfuse_handler = None
    langfuse_host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
    
    if not skip_langfuse:
        langfuse_secret_key = os.getenv("LANGFUSE_SECRET_KEY")
        langfuse_public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
        
        if langfuse_secret_key and langfuse_public_key:
            try:
                langfuse_client = Langfuse(
                    secret_key=langfuse_secret_key,
                    public_key=langfuse_public_key,
                    host=langfuse_host
                )
                langfuse_handler = LangfuseCallbackHandler()
                logger.debug(f"LangFuse initialized (host: {langfuse_host})")
            except Exception as e:
                logger.warning(f"Failed to initialize LangFuse: {e}")
                langfuse_client = None
                langfuse_handler = None
    
    # Determine API key based on provider
    if provider == "openrouter":
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not model_name:
            model_name = os.getenv("WEBSITE_CREATOR_MODEL", "openai/gpt-3.5-turbo")
    elif provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not model_name:
            model_name = os.getenv("ANTHROPIC_MODEL", "claude-3-haiku-20240307")
    elif provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not model_name:
            model_name = "gpt-3.5-turbo"
    else:
        return {
            "status": "error",
            "error": f"Unknown provider: {provider}"
        }
    
    if not api_key:
        return {
            "status": "error",
            "error": f"API key not found for provider {provider}"
        }
    
    # Initialize LLM with higher limits for website generation
    # Note: Many models have context limits (e.g., 16385 tokens total)
    # We need to leave room for input tokens, so use a conservative output limit
    # For gpt-3.5-turbo and similar models, use 12000 to leave room for input
    # For Claude models, they typically support higher output limits
    try:
        # Determine appropriate max_tokens based on model
        model_lower = (model_name or "").lower()
        if "claude" in model_lower or "anthropic" in model_lower:
            # Claude models can handle higher output limits
            max_output_tokens = 14000
        else:
            # For GPT models and others, be more conservative
            # Leave room for input (typically 1000-2000 tokens for prompts)
            # Most models have ~16k context, so use 14000 to be safe
            max_output_tokens = 14000
        
        llm, actual_model_name = initialize_llm(
            provider=provider,
            model_name=model_name,
            temperature=0.7,
            api_key=api_key,
            max_tokens=max_output_tokens,  # Conservative limit to fit within context window
            timeout=300  # 5 minutes for large responses
        )
        logger.info(f"LLM initialized: {actual_model_name}")
        logger.info(f"  max_tokens: {max_output_tokens}")
        logger.info(f"  timeout: 300s")
    except Exception as e:
        logger.error(f"Failed to initialize LLM: {e}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed to initialize LLM: {e}"
        }
    
    # Send prompts to LLM
    start_time = time.time()
    
    # Enhance user prompt with JSON reminder for better compliance
    enhanced_user_prompt = f"""{user_prompt}

REMINDER: Respond with ONLY valid JSON starting with {{ and ending with }}. No markdown, no explanations, just the JSON object with a "files" key containing all website files."""
    
    try:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=enhanced_user_prompt)
        ]
        
        logger.info(f"Invoking LLM with model {actual_model_name}...")
        
        if langfuse_handler:
            response = llm.invoke(
                messages,
                config={
                    "callbacks": [langfuse_handler],
                    "metadata": {
                        "project_type": "website_generation",
                        "model": actual_model_name,
                        "provider": provider,
                        "timestamp": datetime.now().isoformat()
                    }
                }
            )
        else:
            response = llm.invoke(messages)
        
        if hasattr(response, 'content'):
            response_text = response.content
        else:
            response_text = str(response)
        
        execution_time = time.time() - start_time
        logger.info(f"Received response ({len(response_text)} chars) in {execution_time:.2f}s")
        
        # Check for empty response
        if not response_text or len(response_text.strip()) == 0:
            logger.error("LLM returned empty response")
            return {
                "status": "error",
                "error": "LLM returned empty response - no content received"
            }
        
        # Log first 500 chars for debugging
        logger.debug(f"Response preview (first 500 chars): {response_text[:500]}")
        
    except Exception as e:
        logger.error(f"LLM call failed: {e}", exc_info=True)
        return {
            "status": "error",
            "error": f"LLM call failed: {e}"
        }
    
    # Check for truncated response (doesn't end with })
    response_text_stripped = response_text.strip()
    if not response_text_stripped.endswith('}'):
        logger.warning("Response appears to be truncated (doesn't end with })")
        # Try to detect if it's a JSON truncation
        if '"files"' in response_text and '{' in response_text:
            # Try to salvage what we can by finding the last complete file entry
            logger.warning("Attempting to salvage partial JSON...")
            # This is a truncated response - we'll handle it in parse_json_response
    
    # Parse JSON response
    try:
        files = parse_json_response(response_text)
        logger.info(f"Parsed {len(files)} files from response")
    except Exception as e:
        # Check if it's a truncation error
        error_str = str(e).lower()
        if 'unterminated' in error_str or 'truncated' in error_str or not response_text_stripped.endswith('}'):
            logger.error(f"Response appears to be truncated. Error: {e}")
            logger.error(f"Response length: {len(response_text)} chars")
            logger.error(f"Response ends with: {repr(response_text[-100:])}")
            return {
                "status": "error",
                "error": f"Response truncated - max_tokens limit may be too low. Error: {e}"
            }
        
        # Log more details about the failed response
        logger.error(f"Failed to parse JSON: {e}")
        logger.error(f"Response length: {len(response_text)} chars")
        logger.error(f"Response starts with: {repr(response_text[:200])}")
        logger.error(f"Response ends with: {repr(response_text[-200:])}")
        return {
            "status": "error",
            "error": f"Failed to parse JSON: {e}"
        }
    
    # Ensure exactly one main.py
    files = ensure_main_py(files)
    
    # Write files
    logger.info(f"Writing {len(files)} files to {output_dir}...")
    created_files = write_files(files, output_dir)
    
    # Flush LangFuse if initialized
    if langfuse_client:
        try:
            time.sleep(1)
            langfuse_client.flush()
        except Exception as e:
            logger.warning(f"Failed to flush LangFuse: {e}")
    
    return {
        "status": "success",
        "output_directory": str(output_dir),
        "created_files": created_files,
        "total_files": len(created_files),
        "model": actual_model_name,
        "execution_time": execution_time
    }


def main():
    """Main execution flow (CLI entry point)."""
    # Create run directory with unique timestamp ID
    run_dir = setup_run_directory(base_dir="runs/website_generator")
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
    logger.debug("About to call initialize_llm...")
    
    try:
        llm, model_name = initialize_llm(
            provider=provider,
            model_name=cheap_model,
            temperature=0.7,
            api_key=api_key
        )
        logger.debug("initialize_llm returned successfully")
        # Increase max_tokens for website generation (need more tokens for full website)
        if hasattr(llm, 'max_tokens'):
            logger.debug(f"Setting max_tokens to 8000 (was: {llm.max_tokens})")
            llm.max_tokens = 8000  # Increase for website generation
        logger.info(f"LLM initialized: {model_name}")
        logger.debug(f"LLM object type: {type(llm)}")
    except Exception as e:
        logger.error(f"Failed to initialize LLM: {e}", exc_info=True)
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return 1
    
    # Step 3: Send prompts to LLM
    logger.info("Sending prompts to LLM...")
    logger.debug(f"System prompt preview: {system_prompt[:100]}...")
    logger.debug(f"User prompt: {user_prompt}")
    
    # Track start time for execution duration
    start_time = time.time()
    
    try:
        # Prepare messages
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt)
        ]
        
        logger.info("Invoking LLM (this may take a while for large responses)...")
        # Flush immediately so user sees the message
        sys.stdout.flush()
        
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
        logger.error(f"LLM call failed: {e}", exc_info=True)
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
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
    
    # Flush all logging handlers to ensure logs are written
    for handler in logging.getLogger().handlers:
        handler.flush()
    
    # Flush stdout/stderr to ensure output appears immediately
    sys.stdout.flush()
    sys.stderr.flush()
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        # Final flush before exit
        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit(1)
