"""
Custom callback handlers for agent execution flow logging.

Logs all agent interactions at INFO level for visibility.
"""

from typing import Any, Dict, List, Optional
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult
from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


class AgentFlowCallbackHandler(BaseCallbackHandler):
    """
    Callback handler that logs agent execution flow at INFO level.
    
    Logs:
    - Tool calls (when tools are invoked)
    - Tool results (success/failure)
    - Agent reasoning steps
    """
    
    def __init__(self):
        super().__init__()
        self.tool_call_count = 0
    
    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts running."""
        try:
            tool_name = serialized.get("name", "unknown_tool") if serialized else "unknown_tool"
            self.tool_call_count += 1
            
            # Extract URL or key parameter for context
            params_summary = self._summarize_input(str(input_str), tool_name)
            
            logger.info(f"→ Tool #{self.tool_call_count}: {tool_name}({params_summary})")
        except Exception as e:
            logger.debug(f"Error in on_tool_start: {e}")
            self.tool_call_count += 1
            logger.info(f"→ Tool #{self.tool_call_count}: unknown_tool")
    
    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes running."""
        try:
            # Convert output to string if it's not already
            if hasattr(output, 'content'):
                output_str = str(output.content)
            elif hasattr(output, 'text'):
                output_str = str(output.text)
            else:
                output_str = str(output)
            
            # Check if output indicates an error
            if output_str.startswith("Error ") or "error" in output_str.lower()[:50]:
                logger.warning(f"  Tool completed with error: {output_str[:200]}...")
            else:
                # Log success with brief summary
                output_preview = output_str[:100].replace('\n', ' ')
                if len(output_str) > 100:
                    output_preview += "..."
                logger.info(f"  ✓ Tool completed successfully")
                logger.debug(f"  Tool output: {output_preview}")
        except Exception as e:
            logger.debug(f"Error in on_tool_end: {e}")
            logger.info(f"  ✓ Tool completed")
    
    def on_tool_error(
        self,
        error: Exception,
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool encounters an error."""
        logger.error(f"  ✗ Tool failed with error: {error}", exc_info=True)
    
    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts running."""
        # Only log if it's a new reasoning step (not tool result processing)
        if not any("tool" in str(p).lower() for p in prompts):
            logger.debug("LLM reasoning step started")
    
    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when LLM finishes."""
        # Check if response contains tool calls
        if response.llm_output and response.llm_output.get("tool_calls"):
            logger.debug("LLM decided to use tools")
    
    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain starts."""
        try:
            if serialized:
                chain_name = serialized.get("name") or (serialized.get("id", ["unknown"])[-1] if serialized.get("id") else "unknown")
                if "agent" in str(chain_name).lower():
                    logger.info("Agent execution started")
        except Exception as e:
            logger.debug(f"Error in on_chain_start: {e}")
    
    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain ends."""
        try:
            # Only log if this is the main agent chain (not sub-chains)
            # We'll log the final completion separately
            pass
        except Exception as e:
            logger.debug(f"Error in on_chain_end: {e}")
    
    def on_chain_error(
        self,
        error: Exception,
        *,
        run_id: str,
        parent_run_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain encounters an error."""
        logger.error(f"Agent execution error: {error}", exc_info=True)
    
    def _summarize_input(self, input_str: str, tool_name: str) -> str:
        """Extract key parameters from tool input for logging."""
        try:
            # Try to parse as JSON-like string
            import json
            import re
            
            # Look for URL parameter (most common)
            url_match = re.search(r'"url"\s*:\s*"([^"]+)"', input_str)
            if url_match:
                url = url_match.group(1)
                # Truncate long URLs
                if len(url) > 50:
                    url = url[:47] + "..."
                return f"url={url}"
            
            # Look for other common parameters
            target_match = re.search(r'"target_url"\s*:\s*"([^"]+)"', input_str)
            if target_match:
                target = target_match.group(1)
                if len(target) > 50:
                    target = target[:47] + "..."
                return f"target_url={target}"
            
            # Fallback: show first 50 chars
            summary = input_str.replace('\n', ' ').strip()
            if len(summary) > 50:
                summary = summary[:47] + "..."
            return summary
            
        except Exception:
            # If parsing fails, just show truncated input
            summary = str(input_str)[:50]
            if len(str(input_str)) > 50:
                summary += "..."
            return summary

