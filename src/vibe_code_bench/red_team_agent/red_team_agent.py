"""
Red Team Agent

A CLI-based security testing agent that:
- Takes a URL as input
- Uses any OpenRouter model (default: anthropic/claude-3-haiku) for intelligent tool selection
- Performs automated security testing (XSS, SQL injection, security headers, authentication)
- Generates comprehensive security assessment reports
- Uses LangFuse for observability and trace tracking
"""

import os
import sys
import argparse
import time
import logging
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import shared agent functionality
from vibe_code_bench.red_team_agent.agent_common import (
    initialize_langfuse,
    initialize_llm,
    create_and_run_agent,
    flush_langfuse,
    save_report,
    print_results,
)

# Import tools from the tools package
from vibe_code_bench.red_team_agent.tools import get_all_tools, browse_url
from vibe_code_bench.red_team_agent.report_generator import generate_run_report
from vibe_code_bench.red_team_agent.red_team_prompt import RED_TEAM_AGENT_PROMPT

# Import logging setup
from vibe_code_bench.core.logging_setup import setup_logging, get_logger
from vibe_code_bench.core.run_directory import setup_run_directory

logger = get_logger(__name__)


def main():
    """Main entry point for the red team agent."""
    parser = argparse.ArgumentParser(
        description="Red Team Agent - Automated security testing and vulnerability assessment"
    )
    parser.add_argument(
        "--url",
        type=str,
        default="http://localhost:5000",
        help="URL to browse"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        help="OpenRouter API key (or set OPENROUTER_API_KEY env var)"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="anthropic/claude-3-haiku",
        help="OpenRouter model to use (default: anthropic/claude-3-haiku). Examples: 'openai/gpt-4', 'anthropic/claude-3-opus', 'google/gemini-pro'"
    )
    
    args = parser.parse_args()
    
    # Create run directory and set up logging
    run_dir = setup_run_directory(subdir="red_team_agent")
    # Extract timestamp from run directory name (run_dir.name is "run_TIMESTAMP")
    run_id = run_dir.name.replace("run_", "") if run_dir.name.startswith("run_") else run_dir.name
    setup_logging(run_dir=run_dir)
    
    logger.info(f"Starting Red Team Agent - Run ID: {run_id}")
    
    # Initialize LangFuse
    langfuse_client, langfuse_handler = initialize_langfuse()
    langfuse_host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
    
    # Initialize LLM with user-selected model
    model_name = args.model
    llm = initialize_llm(
        model_name=model_name,
        api_key=args.api_key,
        langfuse_handler=langfuse_handler,
        title="Red Team Agent"
    )
    logger.info(f"Using model: {model_name}")
    
    # Get all available tools
    all_tools = get_all_tools()
    logger.info(f"Loaded {len(all_tools)} security testing tools")
    for tool in all_tools:
        logger.debug(f"  - {tool.name}")
    
    try:
        # Run agent
        output, execution_time, trace_id = create_and_run_agent(
            llm=llm,
            all_tools=all_tools,
            system_prompt=RED_TEAM_AGENT_PROMPT,
            url=args.url,
            langfuse_handler=langfuse_handler,
            langfuse_client=langfuse_client,
            model_name=model_name,
            run_id=run_id
        )
        
        # Generate report (both markdown and structured)
        report, structured_report = generate_run_report(
            llm=llm,
            langfuse_client=langfuse_client,
            url=args.url,
            output=output,
            execution_time=execution_time,
            langfuse_handler=langfuse_handler,
            run_id=run_id,
            model_name=model_name
        )
        
        # Save reports (both markdown and JSON)
        md_file, json_file = save_report(report, run_id, structured_report=structured_report)
        
        # Print results
        print_results(output, run_id, trace_id, langfuse_host, md_file, json_file)
        
    except Exception as e:
        logger.error(f"Error running agent: {e}", exc_info=True)
        logger.warning("Falling back to direct tool call")
        result = browse_url(args.url)
        logger.info("=" * 60)
        logger.info("Direct Tool Call Result")
        logger.info("=" * 60)
        logger.info(result)
        logger.info("=" * 60)
        
        # Generate basic report on error
        try:
            error_run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            report, structured_report = generate_run_report(
                llm=llm,
                langfuse_client=langfuse_client,
                url=args.url,
                output=result,
                execution_time=0,
                langfuse_handler=langfuse_handler,
                run_id=error_run_id,
                model_name=model_name
            )
            md_file, json_file = save_report(report, error_run_id, structured_report=structured_report)
            logger.info(f"Run report generated: {md_file}")
            if json_file:
                logger.info(f"Structured report generated: {json_file}")
        except Exception as report_error:
            logger.error(f"Could not generate report: {report_error}", exc_info=True)


if __name__ == "__main__":
    main()
