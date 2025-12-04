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
    print(f"✓ Using model: {model_name}")
    
    # Get all available tools
    all_tools = get_all_tools()
    print(f"✓ Loaded {len(all_tools)} security testing tools:")
    for tool in all_tools:
        print(f"  - {tool.name}")
    
    # Generate run ID
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
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
        
        # Generate report
        report = generate_run_report(
            llm=llm,
            langfuse_client=langfuse_client,
            url=args.url,
            output=output,
            execution_time=execution_time,
            langfuse_handler=langfuse_handler,
            run_id=run_id,
            model_name=model_name
        )
        
        # Save report (uses standard reports directory)
        report_file = save_report(report, run_id)
        
        # Print results
        print_results(output, run_id, trace_id, langfuse_host, report_file)
        
    except Exception as e:
        start_time = time.time()
        execution_time = 0  # Will be calculated after fallback
        
        execution_time = time.time() - start_time
        print(f"Error running agent: {e}")
        print("\nFalling back to direct tool call...")
        result = browse_url(args.url)
        print("\nResult:")
        print("-" * 60)
        print(result)
        print("-" * 60)
        
        # Generate basic report on error
        try:
            error_run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            report = generate_run_report(
                llm=llm,
                langfuse_client=langfuse_client,
                url=args.url,
                output=result,
                execution_time=execution_time,
                langfuse_handler=langfuse_handler,
                run_id=error_run_id,
                model_name=model_name
            )
            report_file = save_report(report, error_run_id)
            print(f"\n✓ Run report generated: {report_file}")
        except Exception as report_error:
            print(f"\n⚠ Could not generate report: {report_error}")


if __name__ == "__main__":
    main()
