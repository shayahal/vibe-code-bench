"""
Batch runner for website generator.

Runs website generation in nested loops:
- For each model in a list
- For each prompt in a list
- Saves results to <unified_timestamp>/<model>/<prompt_num>
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from website_generator.main import generate_website
from website_generator.prompts import SYSTEM_PROMPT

# Load environment variables
load_dotenv()

# Configure logging
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


def sanitize_model_name(model_name: str) -> str:
    """
    Sanitize model name for use in directory names.
    
    Args:
        model_name: Model name (e.g., "openai/gpt-3.5-turbo", "claude-3-haiku-20240307")
    
    Returns:
        Sanitized model name safe for directory names
    """
    # Replace slashes and other invalid chars with underscores
    sanitized = model_name.replace("/", "_").replace("\\", "_")
    sanitized = sanitized.replace(":", "_").replace("*", "_")
    sanitized = sanitized.replace("?", "_").replace('"', "_")
    sanitized = sanitized.replace("<", "_").replace(">", "_")
    sanitized = sanitized.replace("|", "_")
    return sanitized


def convert_to_openrouter_model(model_name: str) -> str:
    """
    Convert model name to OpenRouter format.
    Always uses OpenRouter, converting model names as needed.
    
    Args:
        model_name: Model name (e.g., "gpt-3.5-turbo", "claude-3-haiku-20240307", "openai/gpt-3.5-turbo")
    
    Returns:
        OpenRouter model name (e.g., "openai/gpt-3.5-turbo", "anthropic/claude-3-haiku")
    """
    # If already in OpenRouter format (has slash), check and fix if needed
    if "/" in model_name:
        # Check if it's a Claude model with date suffix - remove it
        if model_name.startswith("anthropic/claude") and "-202" in model_name:
            # Extract base model name (e.g., "anthropic/claude-3-haiku" from "anthropic/claude-3-haiku-20240307")
            parts = model_name.split("/")
            if len(parts) == 2:
                model_part = parts[1]
                # Remove date suffix (format: -YYYYMMDD)
                import re
                model_part = re.sub(r'-\d{8}$', '', model_part)
                return f"{parts[0]}/{model_part}"
        return model_name
    
    model_lower = model_name.lower()
    
    # Convert Claude models to OpenRouter format
    if model_lower.startswith("claude"):
        # Remove date suffix if present (format: -YYYYMMDD)
        import re
        base_model = re.sub(r'-\d{8}$', '', model_name)
        return f"anthropic/{base_model}"
    
    # Convert GPT/OpenAI models to OpenRouter format
    elif model_lower.startswith("gpt") or "openai" in model_lower:
        return f"openai/{model_name}"
    
    # Default: assume it's an OpenAI model
    else:
        return f"openai/{model_name}"


def verify_website_success(output_dir: Path) -> bool:
    """
    Verify that website generation was successful by checking for essential files.
    
    Args:
        output_dir: Directory where website files should be
    
    Returns:
        True if website appears to be successfully generated, False otherwise
    """
    # Check for at least one HTML file and main.py
    html_files = list(output_dir.glob("*.html"))
    main_py = output_dir / "main.py"
    
    # Success if we have at least one HTML file and main.py
    return len(html_files) > 0 and main_py.exists()


def log_failure(failures_log: Path, model_name: str, prompt: str, attempt: int, error: str):
    """
    Log a failure to the failures log file.
    
    Args:
        failures_log: Path to the failures log file
        model_name: Model name that failed
        prompt: Prompt that failed
        attempt: Attempt number (1-3)
        error: Error message
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(failures_log, 'a', encoding='utf-8') as f:
        f.write(f"[{timestamp}] FAILURE - Attempt {attempt}\n")
        f.write(f"  Model: {model_name}\n")
        f.write(f"  Prompt: {prompt}\n")
        f.write(f"  Error: {error}\n")
        f.write("-" * 80 + "\n\n")


def run_batch(
    models: List[str],
    prompts: List[str],
    base_output_dir: str = "runs/website_generator",
    skip_langfuse: bool = False
) -> Dict[str, Any]:
    """
    Run website generation in nested loops.
    
    Args:
        models: List of model names (e.g., ["openai/gpt-3.5-turbo", "claude-3-haiku-20240307"])
        prompts: List of prompts (e.g., ["create a website for my pizzeria", ...])
        base_output_dir: Base directory for output (default: "runs")
        skip_langfuse: If True, skip LangFuse initialization for faster batch runs
    
    Returns:
        Dictionary with batch run results:
        {
            "status": "completed" or "partial" or "failed",
            "unified_timestamp": str,
            "base_directory": str,
            "total_runs": int,
            "successful_runs": int,
            "failed_runs": int,
            "results": list of result dicts
        }
    """
    # Create unified timestamp for this batch run
    unified_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = Path(base_output_dir) / f"batch_{unified_timestamp}"
    base_dir.mkdir(parents=True, exist_ok=True)
    
    # Create failures log file
    failures_log = base_dir / "failures.log"
    if failures_log.exists():
        failures_log.unlink()  # Clear previous failures log
    
    logger.info("=" * 80)
    logger.info(f"Starting Batch Website Generation")
    logger.info(f"Unified Timestamp: {unified_timestamp}")
    logger.info(f"Base Directory: {base_dir}")
    logger.info(f"Models: {len(models)}")
    logger.info(f"Prompts: {len(prompts)}")
    logger.info(f"Total Runs: {len(models) * len(prompts)}")
    logger.info(f"Failures Log: {failures_log}")
    logger.info("=" * 80)
    
    results = []
    successful_runs = 0
    failed_runs = 0
    max_retries = 3
    
    # Nested loops: for each model, for each prompt
    for model_idx, model_name in enumerate(models, 1):
        logger.info("")
        logger.info("=" * 80)
        logger.info(f"MODEL {model_idx}/{len(models)}: {model_name}")
        logger.info("=" * 80)
        
        # Convert model to OpenRouter format (always use OpenRouter)
        openrouter_model = convert_to_openrouter_model(model_name)
        logger.info(f"Original model: {model_name}")
        logger.info(f"OpenRouter model: {openrouter_model}")
        
        # Sanitize model name for directory (use original for directory name)
        model_dir_name = sanitize_model_name(model_name)
        model_dir = base_dir / model_dir_name
        model_dir.mkdir(exist_ok=True)
        
        # Always use OpenRouter
        provider = "openrouter"
        logger.info(f"Provider: {provider} (always OpenRouter)")
        
        for prompt_idx, prompt in enumerate(prompts, 1):
            logger.info("")
            logger.info("-" * 80)
            logger.info(f"PROMPT {prompt_idx}/{len(prompts)}: {prompt[:60]}...")
            logger.info("-" * 80)
            
            # Create output directory: <base_dir>/<model>/<prompt_num>
            output_dir = model_dir / str(prompt_idx)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Save prompt to a file for reference
            prompt_file = output_dir / "prompt.txt"
            with open(prompt_file, 'w', encoding='utf-8') as f:
                f.write(prompt)
            
            # Generate website with retry logic
            result = None
            last_error = None
            success = False
            
            for attempt in range(1, max_retries + 1):
                try:
                    logger.info(f"Attempt {attempt}/{max_retries}...")
                    
                    result = generate_website(
                        user_prompt=prompt,
                        output_dir=output_dir,
                        model_name=openrouter_model,  # Use OpenRouter format
                        provider=provider,
                        system_prompt=SYSTEM_PROMPT,
                        skip_langfuse=skip_langfuse
                    )
                    
                    # Verify the website was actually created successfully
                    if result["status"] == "success":
                        # Double-check by verifying files exist
                        if verify_website_success(output_dir):
                            success = True
                            logger.info(f"✓ SUCCESS (attempt {attempt}): {result['total_files']} files created and verified")
                            break
                        else:
                            # Status says success but files don't verify - treat as failure
                            error_msg = "Generation reported success but files verification failed"
                            result["status"] = "error"
                            result["error"] = error_msg
                            last_error = error_msg
                            logger.warning(f"⚠ Verification failed (attempt {attempt}): {error_msg}")
                            log_failure(failures_log, openrouter_model, prompt, attempt, error_msg)
                    else:
                        # Generation failed
                        last_error = result.get('error', 'Unknown error')
                        logger.warning(f"⚠ Failed (attempt {attempt}): {last_error}")
                        log_failure(failures_log, openrouter_model, prompt, attempt, last_error)
                        
                except Exception as e:
                    last_error = str(e)
                    logger.warning(f"⚠ Exception (attempt {attempt}): {e}")
                    log_failure(failures_log, openrouter_model, prompt, attempt, last_error)
                    
                    # Create error result for this attempt
                    result = {
                        "status": "error",
                        "error": last_error,
                        "model": openrouter_model,
                        "provider": provider,
                        "prompt": prompt,
                        "prompt_num": prompt_idx,
                        "model_num": model_idx,
                        "output_path": str(output_dir),
                        "attempt": attempt
                    }
            
            # Finalize result
            if not success:
                failed_runs += 1
                if result is None:
                    # Create error result if all attempts failed
                    result = {
                        "status": "error",
                        "error": last_error or "All retry attempts failed",
                        "model": openrouter_model,
                        "provider": provider,
                        "prompt": prompt,
                        "prompt_num": prompt_idx,
                        "model_num": model_idx,
                        "output_path": str(output_dir),
                        "attempts": max_retries
                    }
                logger.error(f"✗ FAILED after {max_retries} attempts: {result.get('error', 'Unknown error')}")
            else:
                successful_runs += 1
                # Add metadata to successful result (result is guaranteed to be a dict here)
                if result is not None:
                    result["model"] = model_name  # Keep original model name in metadata
                    result["openrouter_model"] = openrouter_model  # Also store OpenRouter format
                    result["provider"] = provider
                    result["prompt"] = prompt
                    result["prompt_num"] = prompt_idx
                    result["model_num"] = model_idx
                    result["output_path"] = str(output_dir)
            
            # Ensure result is not None before appending
            if result is not None:
                results.append(result)
    
    # Summary
    total_runs = len(models) * len(prompts)
    status = "completed" if failed_runs == 0 else ("partial" if successful_runs > 0 else "failed")
    
    summary = {
        "status": status,
        "unified_timestamp": unified_timestamp,
        "base_directory": str(base_dir),
        "total_runs": total_runs,
        "successful_runs": successful_runs,
        "failed_runs": failed_runs,
        "results": results
    }
    
    # Save summary to JSON
    summary_file = base_dir / "batch_summary.json"
    import json
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    logger.info("")
    logger.info("=" * 80)
    logger.info("BATCH RUN COMPLETE")
    logger.info("=" * 80)
    logger.info(f"Status: {status.upper()}")
    logger.info(f"Total Runs: {total_runs}")
    logger.info(f"Successful: {successful_runs}")
    logger.info(f"Failed: {failed_runs}")
    logger.info(f"Base Directory: {base_dir}")
    logger.info(f"Summary File: {summary_file}")
    logger.info("=" * 80)
    
    return summary


def main():
    """Main entry point for batch runner."""
    # Example configuration - modify as needed
    # Models can be in any format - they will be converted to OpenRouter format automatically
    models = [
        "openai/gpt-3.5-turbo",  # Already in OpenRouter format
        "claude-3-haiku-20240307",  # Will be converted to "anthropic/claude-3-haiku-20240307"
    ]
    
    prompts = [
        "create a website for my pizzeria",
        "create an app for exploring local businesses on a map",
    ]
    
    # You can also load from environment variables or config file
    # For now, using hardcoded examples
    logger.info("Using example models and prompts")
    logger.info("All models will be converted to OpenRouter format automatically")
    logger.info("Modify the main() function to customize models and prompts")
    
    # Run batch
    summary = run_batch(
        models=models,
        prompts=prompts,
        base_output_dir="runs",
        skip_langfuse=False  # Set to True for faster batch runs without LangFuse
    )
    
    return 0 if summary["status"] == "completed" else 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)

