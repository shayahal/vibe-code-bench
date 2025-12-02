"""
Common functionality for Red Team Agent.

This module contains shared code used by red_team_agent.py to avoid code duplication
and provide reusable agent functionality.
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Try importing LangChain
try:
    from langchain_openai import ChatOpenAI
    from langchain.agents import create_agent
except ImportError:
    print("Error: langchain-openai is required. Install with: pip install langchain-openai")
    sys.exit(1)

# Import LangFuse (required) - LangChain integration
try:
    from langfuse.langchain import CallbackHandler as LangfuseCallbackHandler
    from langfuse import Langfuse
except ImportError:
    print("Error: langfuse is required. Install with: pip install langfuse")
    sys.exit(1)


def initialize_langfuse() -> Tuple[Langfuse, LangfuseCallbackHandler]:
    """
    Initialize LangFuse client and handler.
    
    Returns:
        Tuple of (Langfuse client, LangfuseCallbackHandler)
        
    Raises:
        SystemExit: If LangFuse credentials are missing
    """
    langfuse_secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    langfuse_public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    langfuse_host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
    
    if not langfuse_secret_key or not langfuse_public_key:
        print("Error: LangFuse credentials not found.")
        print("  Please set LANGFUSE_SECRET_KEY and LANGFUSE_PUBLIC_KEY in your .env file.")
        print("  You can get these from https://cloud.langfuse.com")
        sys.exit(1)
    
    try:
        langfuse_client = Langfuse(
            secret_key=langfuse_secret_key,
            public_key=langfuse_public_key,
            host=langfuse_host
        )
        
        langfuse_handler = LangfuseCallbackHandler()
        print(f"✓ LangFuse initialized (host: {langfuse_host})")
        print("  Using LangChain integration - all traces will be automatically captured")
        return langfuse_client, langfuse_handler
    except Exception as e:
        print(f"Error initializing LangFuse: {e}")
        print("  Make sure LANGFUSE_SECRET_KEY and LANGFUSE_PUBLIC_KEY are set in your .env file")
        sys.exit(1)


def initialize_llm(
    model_name: str,
    api_key: Optional[str],
    langfuse_handler: LangfuseCallbackHandler,
    title: str = "Red Team Agent"
) -> ChatOpenAI:
    """
    Initialize LLM via OpenRouter.
    
    Args:
        model_name: Model name to use
        api_key: OpenRouter API key (or None to use env var)
        langfuse_handler: LangFuse callback handler
        title: Title for the agent (used in headers)
        
    Returns:
        ChatOpenAI instance
        
    Raises:
        SystemExit: If API key is missing or initialization fails
    """
    api_key = api_key or os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("Error: OPENROUTER_API_KEY not found. Set it as env var or use --api-key")
        sys.exit(1)
    
    try:
        llm = ChatOpenAI(
            model=model_name,
            api_key=api_key,
            temperature=0.7,
            max_tokens=2000,
            base_url="https://openrouter.ai/api/v1",
            default_headers={
                "HTTP-Referer": "https://github.com/shayahal/vibe-code-bench",
                "X-Title": title
            },
            callbacks=[langfuse_handler]
        )
        return llm
    except Exception as e:
        print(f"Error initializing LLM: {e}")
        sys.exit(1)


def create_and_run_agent(
    llm: ChatOpenAI,
    all_tools: list,
    system_prompt: str,
    url: str,
    langfuse_handler: LangfuseCallbackHandler,
    langfuse_client: Langfuse,
    model_name: str,
    run_id: str
) -> Tuple[str, float, Optional[str]]:
    """
    Create agent and run security assessment.
    
    Args:
        llm: ChatOpenAI instance
        all_tools: List of tools to provide to agent
        system_prompt: System prompt for the agent
        url: Target URL to assess
        langfuse_handler: LangFuse callback handler
        langfuse_client: LangFuse client
        model_name: Model name (for metadata)
        run_id: Run ID (for metadata)
        
    Returns:
        Tuple of (output, execution_time, trace_id)
    """
    try:
        agent = create_agent(
            model=llm,
            tools=all_tools,
            system_prompt=system_prompt,
            debug=False
        )
    except Exception as e:
        print(f"Error creating agent: {e}")
        sys.exit(1)
    
    trace_name = f"Security Assessment - {url} - Run {run_id}"
    
    # Try to set trace name if supported
    try:
        if hasattr(langfuse_handler, 'set_trace_name'):
            langfuse_handler.set_trace_name(trace_name)
    except:
        pass
    
    # Print assessment header
    print(f"\n🔴 Red Team Security Assessment")
    print("=" * 60)
    print(f"Target URL: {url}")
    if model_name != "anthropic/claude-3-haiku":  # Only print if not default
        print(f"Model: {model_name}")
    print(f"Run ID: {run_id}")
    print("=" * 60)
    print("The agent will perform automated security testing:")
    print("  • Security headers analysis")
    print("  • XSS vulnerability testing")
    print("  • SQL injection testing")
    print("  • Authentication mechanism analysis")
    print("  • Comprehensive security report generation")
    print("=" * 60)
    
    user_message = f"Perform a comprehensive security assessment on: {url}"
    start_time = time.time()
    
    try:
        result = agent.invoke(
            {"messages": [("human", user_message)]},
            config={
                "callbacks": [langfuse_handler],
                "metadata": {
                    "run_id": run_id,
                    "url": url,
                    "model": model_name,
                    "provider": "openrouter",
                    "timestamp": datetime.now().isoformat(),
                    "trace_name": trace_name
                }
            }
        )
        
        execution_time = time.time() - start_time
        
        # Extract output
        if isinstance(result, dict) and "messages" in result:
            messages = result["messages"]
            if messages:
                last_message = messages[-1]
                output = str(last_message.content) if hasattr(last_message, "content") else str(last_message)
            else:
                output = str(result)
        else:
            output = str(result)
        
        # Extract trace ID
        trace_id = None
        try:
            if hasattr(langfuse_handler, 'last_trace_id'):
                trace_id = langfuse_handler.last_trace_id
            elif hasattr(langfuse_handler, 'get_trace_id'):
                trace_id = langfuse_handler.get_trace_id()
            elif hasattr(langfuse_handler, 'run') and langfuse_handler.run:
                trace_id = langfuse_handler.run.trace_id if hasattr(langfuse_handler.run, 'trace_id') else None
            
            # Update trace metadata
            if trace_id:
                try:
                    langfuse_client.trace(id=trace_id).update(
                        name=trace_name,
                        metadata={"run_id": run_id, "url": url}
                    )
                except Exception:
                    pass
        except Exception:
            pass
        
        # Flush LangFuse data
        flush_langfuse(langfuse_handler, langfuse_client, trace_id)
        
        return output, execution_time, trace_id
        
    except Exception as e:
        execution_time = time.time() - start_time
        raise e


def flush_langfuse(
    langfuse_handler: LangfuseCallbackHandler,
    langfuse_client: Langfuse,
    trace_id: Optional[str]
):
    """
    Flush LangFuse data and verify trace if available.
    
    Args:
        langfuse_handler: LangFuse callback handler
        langfuse_client: LangFuse client
        trace_id: Optional trace ID to verify
    """
    time.sleep(2)
    
    flush_success = False
    try:
        if hasattr(langfuse_handler, 'langfuse') and langfuse_handler.langfuse:
            langfuse_handler.langfuse.flush()
            flush_success = True
    except Exception as e:
        print(f"  Warning: Error flushing handler: {e}")
    
    try:
        langfuse_client.flush()
        flush_success = True
    except Exception as e:
        print(f"  Warning: Error flushing client: {e}")
    
    if flush_success:
        time.sleep(5)
    else:
        print("  Warning: Flush may have failed - trace might not be available immediately")
    
    # Verify trace if available
    if trace_id:
        try:
            trace = langfuse_client.trace(id=trace_id)
            if trace:
                print(f"  ✓ Trace verified in LangFuse")
        except Exception:
            pass


def save_report(
    report: str,
    run_id: str,
    report_dir_path: str
) -> Path:
    """
    Save report to file.
    
    Args:
        report: Report content
        run_id: Run ID for filename
        report_dir_path: Path to report directory (relative or absolute)
        
    Returns:
        Path to saved report file
    """
    report_dir = Path(report_dir_path)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_file = report_dir / f"run_report_{run_id}.md"
    report_file.write_text(report, encoding='utf-8')
    return report_file


def print_results(
    output: str,
    run_id: str,
    trace_id: Optional[str],
    langfuse_host: str,
    report_file: Path
):
    """
    Print results and observability information.
    
    Args:
        output: Agent output
        run_id: Run ID
        trace_id: Optional trace ID
        langfuse_host: LangFuse host URL
        report_file: Path to saved report file
    """
    print("\nResult:")
    print("-" * 60)
    print(output)
    print("-" * 60)
    print(f"\n✓ All observability data logged to LangFuse")
    print(f"  - Check your LangFuse dashboard: {langfuse_host}")
    print(f"  - Run ID: {run_id} (use this to filter traces)")
    if trace_id:
        print(f"  - Trace ID: {trace_id}")
        print(f"  - Direct Trace Link: {langfuse_host}/traces/{trace_id}")
        print(f"  Note: Traces may take a few seconds to appear in the dashboard")
    else:
        print(f"  Note: Trace ID not available - check dashboard for recent traces")
    print(f"\n✓ Run report generated: {report_file}")

