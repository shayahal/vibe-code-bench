"""
Common functionality for Red Team Agent.

This module contains shared code used by red_team_agent.py to avoid code duplication
and provide reusable agent functionality.
"""

import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Any, Dict
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langfuse.langchain import CallbackHandler as LangfuseCallbackHandler
from langfuse import Langfuse

from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


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
        logger.error("LangFuse credentials not found")
        logger.error("Please set LANGFUSE_SECRET_KEY and LANGFUSE_PUBLIC_KEY in your .env file")
        logger.error("You can get these from https://cloud.langfuse.com")
        sys.exit(1)
    
    try:
        langfuse_client = Langfuse(
            secret_key=langfuse_secret_key,
            public_key=langfuse_public_key,
            host=langfuse_host
        )
        
        langfuse_handler = LangfuseCallbackHandler()
        logger.info(f"LangFuse initialized (host: {langfuse_host})")
        logger.debug("Using LangChain integration - all traces will be automatically captured")
        return langfuse_client, langfuse_handler
    except Exception as e:
        logger.error(f"Error initializing LangFuse: {e}")
        logger.error("Make sure LANGFUSE_SECRET_KEY and LANGFUSE_PUBLIC_KEY are set in your .env file")
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
        logger.error("OPENROUTER_API_KEY not found. Set it as env var or use --api-key")
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
        logger.error(f"Error initializing LLM: {e}")
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
        logger.error(f"Error creating agent: {e}")
        sys.exit(1)
    
    trace_name = f"Security Assessment - {url} - Run {run_id}"
    
    # Try to set trace name if supported
    try:
        if hasattr(langfuse_handler, 'set_trace_name'):
            langfuse_handler.set_trace_name(trace_name)
    except:
        pass
    
    # Log assessment header
    logger.info("=" * 60)
    logger.info("Red Team Security Assessment")
    logger.info("=" * 60)
    logger.info(f"Target URL: {url}")
    if model_name != "anthropic/claude-3-haiku":  # Only log if not default
        logger.info(f"Model: {model_name}")
    logger.info(f"Run ID: {run_id}")
    logger.info("=" * 60)
    logger.info("The agent will perform automated security testing:")
    logger.info("  • Security headers analysis")
    logger.info("  • XSS vulnerability testing")
    logger.info("  • SQL injection testing")
    logger.info("  • Authentication mechanism analysis")
    logger.info("  • Comprehensive security report generation")
    logger.info("=" * 60)
    
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
        logger.warning(f"Error flushing LangFuse handler: {e}")
    
    try:
        langfuse_client.flush()
        flush_success = True
    except Exception as e:
        logger.warning(f"Error flushing LangFuse client: {e}")
    
    if flush_success:
        time.sleep(5)
        logger.debug("LangFuse data flushed successfully")
    else:
        logger.warning("LangFuse flush may have failed - trace might not be available immediately")
    
    # Verify trace if available
    if trace_id:
        try:
            trace = langfuse_client.trace(id=trace_id)
            if trace:
                logger.debug(f"Trace verified in LangFuse: {trace_id}")
        except Exception as e:
            logger.debug(f"Could not verify trace in LangFuse: {e}")


def save_report(
    report: str,
    run_id: str,
    report_dir_path: str = None,
    structured_report: Dict[str, Any] = None
) -> Tuple[Path, Optional[Path]]:
    """
    Save report to file (both markdown and JSON formats).
    
    Args:
        report: Report content (markdown)
        run_id: Run ID for filename
        report_dir_path: Optional path to report directory (default: standard reports dir)
        structured_report: Optional structured report dictionary (JSON format)
        
    Returns:
        Tuple of (markdown_file_path, json_file_path)
    """
    from vibe_code_bench.core.paths import get_reports_dir, get_absolute_path
    from vibe_code_bench.red_team_agent.structured_report import save_structured_report
    
    if report_dir_path:
        report_dir = get_absolute_path(report_dir_path)
    else:
        report_dir = get_reports_dir()
    
    report_dir.mkdir(parents=True, exist_ok=True)
    
    # Save markdown report
    md_file = report_dir / f"run_report_{run_id}.md"
    md_file.write_text(report, encoding='utf-8')
    
    # Save structured JSON report if provided
    json_file = None
    if structured_report:
        json_file = save_structured_report(
            structured_report=structured_report,
            run_id=run_id,
            report_dir_path=report_dir_path
        )
    else:
        logger.warning("No structured report provided - only markdown report saved")
    
    return md_file, json_file


def print_results(
    output: str,
    run_id: str,
    trace_id: Optional[str],
    langfuse_host: str,
    md_file: Path,
    json_file: Optional[Path] = None
):
    """
    Log results and observability information.
    
    Args:
        output: Agent output
        run_id: Run ID
        trace_id: Optional trace ID
        langfuse_host: LangFuse host URL
        md_file: Path to saved markdown report file
        json_file: Optional path to saved JSON structured report file
    """
    logger.info("=" * 60)
    logger.info("Assessment Result")
    logger.info("=" * 60)
    logger.info(output)
    logger.info("=" * 60)
    logger.info("All observability data logged to LangFuse")
    logger.info(f"Check your LangFuse dashboard: {langfuse_host}")
    logger.info(f"Run ID: {run_id} (use this to filter traces)")
    if trace_id:
        logger.info(f"Trace ID: {trace_id}")
        logger.info(f"Direct Trace Link: {langfuse_host}/traces/{trace_id}")
        logger.debug("Traces may take a few seconds to appear in the dashboard")
    else:
        logger.warning("Trace ID not available - check dashboard for recent traces")
    logger.info(f"Markdown report generated: {md_file}")
    if json_file:
        logger.info(f"Structured JSON report generated: {json_file}")
    else:
        logger.warning("Structured JSON report not generated")

