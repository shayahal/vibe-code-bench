"""
Mini Red Team Agent

A CLI-based security testing agent that:
- Takes a URL as input
- Uses Claude Mini (claude-3-haiku) for intelligent tool selection
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
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Try importing LangChain
try:
    from langchain_anthropic import ChatAnthropic
    from langchain.agents import create_agent
except ImportError:
    print("Error: langchain-anthropic is required. Install with: pip install langchain-anthropic")
    sys.exit(1)

# Import LangFuse (required) - LangChain integration
# See: https://langfuse.com/docs/observability/get-started
try:
    from langfuse.langchain import CallbackHandler as LangfuseCallbackHandler
    from langfuse import Langfuse
except ImportError:
    print("Error: langfuse is required. Install with: pip install langfuse")
    sys.exit(1)

# Import tools from the tools package
# Use relative imports when running as script, absolute when running as module
try:
    from tools import get_tool, get_all_tools, browse_url
    from report_generator import generate_run_report
    from red_team_prompt import RED_TEAM_AGENT_PROMPT
except ImportError:
    # Fallback for when running as module
    from mini.tools import get_tool, get_all_tools, browse_url
    from mini.report_generator import generate_run_report
    from mini.red_team_prompt import RED_TEAM_AGENT_PROMPT


def main():
    """Main entry point for the mini red team agent."""
    parser = argparse.ArgumentParser(
        description="Mini Red Team Agent - Automated security testing and vulnerability assessment"
    )
    parser.add_argument(
        "--url",
        type=str,
        required=True,
        help="URL to browse"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)"
    )
    
    args = parser.parse_args()
    
    # Initialize LangFuse (required) - following LangChain integration pattern
    # See: https://langfuse.com/docs/observability/get-started
    # The CallbackHandler reads credentials from environment variables automatically
    langfuse_secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    langfuse_public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    langfuse_host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
    
    if not langfuse_secret_key or not langfuse_public_key:
        print("Error: LangFuse credentials not found.")
        print("  Please set LANGFUSE_SECRET_KEY and LANGFUSE_PUBLIC_KEY in your .env file.")
        print("  You can get these from https://cloud.langfuse.com")
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
        print(f"✓ LangFuse initialized (host: {langfuse_host})")
        print("  Using LangChain integration - all traces will be automatically captured")
    except Exception as e:
        print(f"Error initializing LangFuse: {e}")
        print("  Make sure LANGFUSE_SECRET_KEY and LANGFUSE_PUBLIC_KEY are set in your .env file")
        sys.exit(1)
    
    # Get API key
    api_key = args.api_key or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not found. Set it as env var or use --api-key")
        sys.exit(1)
    
    # Initialize Claude Mini (claude-3-haiku is the mini/fast model)
    # Increased max_tokens for security testing tasks
    try:
        llm = ChatAnthropic(
            model="claude-3-haiku-20240307",  # Claude Mini
            api_key=api_key,
            temperature=0.7,
            max_tokens=2000,  # Increased for security testing tasks
            callbacks=[langfuse_handler]
        )
    except Exception as e:
        print(f"Error initializing LLM: {e}")
        sys.exit(1)
    
    # Get all available tools from the tools registry
    # The agent will choose which tools to use based on the task
    all_tools = get_all_tools()
    
    print(f"✓ Loaded {len(all_tools)} security testing tools:")
    for tool in all_tools:
        print(f"  - {tool.name}")
    
    # System prompt is imported from red_team_prompt module
    system_prompt = RED_TEAM_AGENT_PROMPT
    
    try:
        # Create agent with all available tools
        # The agent will intelligently choose which tools to use based on the task
        # LangFuse handler will automatically capture all traces
        agent = create_agent(
            model=llm,
            tools=all_tools,
            system_prompt=system_prompt,
            debug=False
        )
    except Exception as e:
        print(f"Error creating agent: {e}")
        sys.exit(1)
    
    # Run the agent
    print(f"\n🔴 Red Team Security Assessment")
    print("=" * 60)
    print(f"Target URL: {args.url}")
    print("=" * 60)
    print("The agent will perform automated security testing:")
    print("  • Security headers analysis")
    print("  • XSS vulnerability testing")
    print("  • SQL injection testing")
    print("  • Authentication mechanism analysis")
    print("  • Comprehensive security report generation")
    print("=" * 60)
    
    user_message = f"Perform a comprehensive security assessment on: {args.url}"
    
    # Track start time for execution duration
    start_time = time.time()
    
    try:
        # Invoke agent with LangFuse callback handler
        # The handler automatically captures:
        # - All LLM calls (inputs, outputs, tokens, costs)
        # - All tool calls (inputs, outputs)
        # - Agent reasoning and actions
        # - Full trace structure
        result = agent.invoke(
            {"messages": [("human", user_message)]},
            config={
                "callbacks": [langfuse_handler],
                "metadata": {
                    "url": args.url,
                    "model": "claude-3-haiku-20240307",
                    "timestamp": datetime.now().isoformat()
                }
            }
        )
        
        # Calculate execution time
        execution_time = time.time() - start_time
        
        # Extract the result
        if isinstance(result, dict) and "messages" in result:
            messages = result["messages"]
            if messages:
                last_message = messages[-1]
                output = str(last_message.content) if hasattr(last_message, "content") else str(last_message)
            else:
                output = str(result)
        else:
            output = str(result)
        
        # Wait a moment for LangFuse to process the trace
        time.sleep(2)
        
        # Flush both the handler's client and the main client to ensure data is sent
        # This is critical for short-lived scripts to ensure traces are sent
        try:
            if hasattr(langfuse_handler, 'langfuse') and langfuse_handler.langfuse:
                langfuse_handler.langfuse.flush()
                # Also try shutdown for complete flush
                if hasattr(langfuse_handler.langfuse, 'shutdown'):
                    langfuse_handler.langfuse.shutdown()
        except Exception as e:
            print(f"  Warning: Error flushing handler: {e}")
        
        try:
            langfuse_client.flush()
            # Also try shutdown for complete flush
            if hasattr(langfuse_client, 'shutdown'):
                langfuse_client.shutdown()
        except Exception as e:
            print(f"  Warning: Error flushing client: {e}")
        
        # Try to extract trace ID for verification
        trace_id = None
        try:
            # The handler has a last_trace_id attribute that contains the trace ID
            if hasattr(langfuse_handler, 'last_trace_id'):
                trace_id = langfuse_handler.last_trace_id
            elif hasattr(langfuse_handler, 'get_trace_id'):
                trace_id = langfuse_handler.get_trace_id()
            elif hasattr(langfuse_handler, 'run') and langfuse_handler.run:
                trace_id = langfuse_handler.run.trace_id if hasattr(langfuse_handler.run, 'trace_id') else None
        except Exception as e:
            pass  # Trace ID extraction is optional
        
        # Wait a bit longer for async processing
        time.sleep(3)
        
        # Generate report using the agent
        report = generate_run_report(
            llm=llm,
            langfuse_client=langfuse_client,
            url=args.url,
            output=output,
            execution_time=execution_time,
            langfuse_handler=langfuse_handler
        )
        
        # Save report to file
        report_dir = Path("mini/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = report_dir / f"run_report_{timestamp}.md"
        report_file.write_text(report, encoding='utf-8')
        
        print("\nResult:")
        print("-" * 60)
        print(output)
        print("-" * 60)
        print(f"\n✓ All observability data logged to LangFuse")
        print(f"  - Check your LangFuse dashboard: {langfuse_host}")
        if trace_id:
            print(f"  - Trace ID: {trace_id}")
        print(f"\n✓ Run report generated: {report_file}")
        
    except Exception as e:
        execution_time = time.time() - start_time
        print(f"Error running agent: {e}")
        
        # Fallback: directly call the tool
        print("\nFalling back to direct tool call...")
        from tools import browse_url
        result = browse_url(args.url)
        print("\nResult:")
        print("-" * 60)
        print(result)
        print("-" * 60)
        
        # Generate a basic report even on error
        try:
            report = generate_run_report(
                llm=llm,
                langfuse_client=langfuse_client,
                url=args.url,
                output=result,
                execution_time=execution_time,
                langfuse_handler=langfuse_handler
            )
            report_dir = Path("mini/reports")
            report_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = report_dir / f"run_report_{timestamp}.md"
            report_file.write_text(report, encoding='utf-8')
            print(f"\n✓ Run report generated: {report_file}")
        except Exception as report_error:
            print(f"\n⚠ Could not generate report: {report_error}")


if __name__ == "__main__":
    main()

