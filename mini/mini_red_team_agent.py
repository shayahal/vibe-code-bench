"""
Mini Red Team Agent

A simple CLI-based agent that:
- Takes a URL as input
- Uses Claude Mini (anthropic/claude-3-haiku) via OpenRouter
- Has one browsing tool to fetch the URL
- Returns the first 3 lines from the website
"""

import os
import sys
import argparse
import requests
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from dotenv import load_dotenv
from bs4 import BeautifulSoup

# Load environment variables
load_dotenv()

# Try importing LangChain
try:
    from langchain_openai import ChatOpenAI
    from langchain.agents import create_agent
    from langchain_core.tools import StructuredTool
except ImportError:
    print("Error: langchain-openai is required. Install with: pip install langchain-openai")
    sys.exit(1)

# Import LangFuse (required) - LangChain integration
# See: https://langfuse.com/docs/observability/get-started
try:
    from langfuse.langchain import CallbackHandler as LangfuseCallbackHandler
    from langfuse import Langfuse
except ImportError:
    print("Error: langfuse is required. Install with: pip install langfuse")
    sys.exit(1)


def generate_run_report(
    llm: ChatOpenAI,
    langfuse_client: Langfuse,
    url: str,
    output: str,
    execution_time: float,
    langfuse_handler: LangfuseCallbackHandler
) -> str:
    """
    Generate a run report using the LLM based on LangFuse trace data.
    
    Args:
        llm: The LLM instance to generate the report
        langfuse_client: LangFuse client to fetch trace data
        url: The URL that was browsed
        output: The agent's output
        execution_time: Execution time in seconds
        langfuse_handler: The LangFuse callback handler
        
    Returns:
        Generated report as markdown string
    """
    try:
        # Get trace ID from handler if available
        trace_id = None
        if hasattr(langfuse_handler, 'get_trace_id'):
            try:
                trace_id = langfuse_handler.get_trace_id()
            except:
                pass
        
        # Create report generation prompt
        report_prompt = f"""Generate a comprehensive run report for a web browsing agent execution.

Run Details:
- URL browsed: {url}
- Execution time: {execution_time:.2f} seconds
- Model used: anthropic/claude-3-haiku (via OpenRouter)
- Timestamp: {datetime.now().isoformat()}

Agent Output:
{output}

Please generate a detailed markdown report that includes:

1. **Executive Summary**
   - What the agent did
   - The target URL
   - Overall outcome

2. **Tools Used**
   - List all tools that were used during execution
   - For each tool, describe what it did

3. **Execution Details**
   - Total execution time: {execution_time:.2f} seconds
   - Breakdown of time spent (if available)

4. **Cost Analysis**
   - Model used: anthropic/claude-3-haiku (via OpenRouter)
   - Estimated cost (note: actual costs are tracked in LangFuse dashboard)
   - Token usage (if available from trace data)

5. **Observability**
   - All traces are logged to LangFuse
   - Check LangFuse dashboard for detailed trace information, token counts, and costs

Format the report as clean markdown with proper headers and sections."""

        # Generate report using LLM
        report_response = llm.invoke(report_prompt)
        report_content = report_response.content if hasattr(report_response, 'content') else str(report_response)
        
        # Add header and metadata
        full_report = f"""# Agent Run Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Target URL:** {url}  
**Execution Time:** {execution_time:.2f} seconds  
**Model:** claude-3-haiku-20240307

---

{report_content}

---

## Technical Details

- **Trace ID:** {trace_id if trace_id else 'Available in LangFuse dashboard'}
- **LangFuse Dashboard:** Check {os.getenv('LANGFUSE_HOST', 'https://cloud.langfuse.com')} for detailed traces
- **All observability data** (tokens, costs, detailed traces) is available in LangFuse
"""
        
        return full_report
        
    except Exception as e:
        # Fallback report if generation fails
        return f"""# Agent Run Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Target URL:** {url}  
**Execution Time:** {execution_time:.2f} seconds  
**Model:** anthropic/claude-3-haiku (via OpenRouter)

## Summary

The agent successfully browsed the URL {url} and extracted the first 3 lines of visible text content.

## Tools Used

- **browse_url**: Fetched the webpage, parsed HTML, and extracted visible text content

## Execution Details

- **Total execution time:** {execution_time:.2f} seconds
- **Model:** anthropic/claude-3-haiku (via OpenRouter)

## Cost Analysis

- **Model:** anthropic/claude-3-haiku (via OpenRouter)
- **Cost:** Check LangFuse dashboard for detailed cost breakdown
- **Token usage:** Available in LangFuse trace data

## Output

{output}

## Observability

All execution traces, token usage, and costs are logged to LangFuse. Check the LangFuse dashboard for detailed information.

**Note:** Report generation encountered an error: {str(e)}
"""


def browse_url(url: str) -> str:
    """
    Browse a URL and return the first 3 lines of visible text content.
    
    Args:
        url: The URL to browse
        
    Returns:
        First 3 lines of the website's visible text content
    """
    try:
        # Fetch the URL
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Parse HTML and extract visible text content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text content
        text = soup.get_text()
        
        # Extract first 3 non-empty lines
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        
        # Return first 3 lines
        first_3_lines = '\n'.join(lines[:3]) if len(lines) >= 3 else '\n'.join(lines)
        
        return f"First 3 lines from {url}:\n{first_3_lines}"
    except Exception as e:
        return f"Error browsing {url}: {str(e)}"


def main():
    """Main entry point for the mini red team agent."""
    parser = argparse.ArgumentParser(
        description="Mini Red Team Agent - Browse a URL and return first 3 lines"
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
        help="OpenRouter API key (or set OPENROUTER_API_KEY env var)"
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
    api_key = args.api_key or os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("Error: OPENROUTER_API_KEY not found. Set it as env var or use --api-key")
        sys.exit(1)
    
    # Initialize Claude Mini via OpenRouter (anthropic/claude-3-haiku is the mini/fast model)
    try:
        llm = ChatOpenAI(
            model="anthropic/claude-3-haiku",  # Claude Mini via OpenRouter
            api_key=api_key,
            temperature=0.7,
            max_tokens=200,
            base_url="https://openrouter.ai/api/v1",
            default_headers={
                "HTTP-Referer": "https://github.com/shayahal/vibe-code-bench",
                "X-Title": "Mini Red-Team Agent"
            },
            callbacks=[langfuse_handler]
        )
    except Exception as e:
        print(f"Error initializing LLM: {e}")
        sys.exit(1)
    
    # Create the browsing tool
    browse_tool = StructuredTool.from_function(
        func=browse_url,
        name="browse_url",
        description="Browse a URL and return the first 3 lines of text content. Input: url (the URL to browse)"
    )
    
    # Create agent with just the browsing tool
    system_prompt = """You are a simple web browsing agent. 
Your task is to browse the URL provided by the user and return the first 3 lines from that website.

You have one tool available:
- browse_url: Browse a URL and get the first 3 lines of content

When the user provides a URL, use the browse_url tool to fetch it and return the first 3 lines."""
    
    try:
        # Create agent - LangFuse handler will automatically capture all traces
        # No need to manually create traces - the callback handler does this automatically
        agent = create_agent(
            model=llm,
            tools=[browse_tool],
            system_prompt=system_prompt,
            debug=False
        )
    except Exception as e:
        print(f"Error creating agent: {e}")
        sys.exit(1)
    
    # Run the agent
    print(f"Browsing URL: {args.url}")
    print("=" * 60)
    
    user_message = f"Browse this URL and return the first 3 lines: {args.url}"
    
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
                    "model": "anthropic/claude-3-haiku",
                    "provider": "openrouter",
                    "timestamp": datetime.now().isoformat()
                }
            }
        )
        
        # Calculate execution time
        execution_time = time.time() - start_time
        
        # Extract the result
        if isinstance(result, dict) and "messages" in result:
            last_message = result["messages"][-1]
            output = str(last_message.content) if hasattr(last_message, "content") else str(last_message)
        else:
            output = str(result)
        
        # Wait a moment for LangFuse to process the trace
        time.sleep(2)
        langfuse_client.flush()  # Ensure data is sent
        time.sleep(1)  # Give it a moment to process
        
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
        print(f"\n✓ Run report generated: {report_file}")
        
    except Exception as e:
        execution_time = time.time() - start_time
        print(f"Error running agent: {e}")
        
        # Fallback: directly call the tool
        print("\nFalling back to direct tool call...")
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

