"""Observability module with Langfuse tracing and structured logging.

All LLM calls and tool executions are traced for debugging and monitoring.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

from vibe_code_bench.core.paths import get_logs_dir, get_runs_dir
from vibe_code_bench.red_team_agent.exceptions import ConfigurationError

# Langfuse imports - optional for tracing
LANGFUSE_AVAILABLE = False
Langfuse = None
LangfuseCallbackHandler = None

try:
    from langfuse import Langfuse
    from langfuse.callback import CallbackHandler as LangfuseCallbackHandler
    LANGFUSE_AVAILABLE = True
except ImportError:
    pass  # Langfuse is optional


class ObservabilityManager:
    """Manages Langfuse tracing and structured logging."""
    
    _instance: "ObservabilityManager | None" = None
    
    def __init__(self, run_id: str | None = None):
        """Initialize observability.
        
        Args:
            run_id: Optional run identifier for grouping traces and logs.
        """
        self.run_id = run_id or f"red_team_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self._langfuse_client: Langfuse | None = None
        self._callback_handler: LangfuseCallbackHandler | None = None
        self._logger: logging.Logger | None = None
        self._run_dir: Path | None = None
        
        self._setup_logging()
        self._setup_langfuse()
    
    @classmethod
    def get_instance(cls, run_id: str | None = None) -> "ObservabilityManager":
        """Get singleton instance of ObservabilityManager."""
        if cls._instance is None:
            cls._instance = cls(run_id)
        return cls._instance
    
    @classmethod
    def reset(cls) -> None:
        """Reset singleton instance (for testing)."""
        if cls._instance is not None:
            cls._instance.shutdown()
        cls._instance = None
    
    def _setup_logging(self) -> None:
        """Setup structured logging with file and console handlers."""
        # Create run directory
        self._run_dir = get_runs_dir() / "red_team_agent" / self.run_id
        self._run_dir.mkdir(parents=True, exist_ok=True)
        
        # Create logs directory
        logs_dir = self._run_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logger
        self._logger = logging.getLogger("vibe_code_bench.red_team_agent")
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()
        
        # File handler - detailed logs
        log_file = logs_dir / "red_team.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        self._logger.addHandler(file_handler)
        
        # Console handler - info and above
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(console_formatter)
        self._logger.addHandler(console_handler)
        
        self._logger.info(f"Logging initialized | run_id={self.run_id}")
        self._logger.info(f"Log file: {log_file}")
    
    def _setup_langfuse(self) -> None:
        """Setup Langfuse tracing.
        
        Langfuse is optional - if keys not set, tracing is disabled but logging continues.
        """
        if not LANGFUSE_AVAILABLE:
            self._logger.warning(
                "Langfuse not installed. Install with: pip install langfuse"
            )
            return
        
        public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
        secret_key = os.getenv("LANGFUSE_SECRET_KEY")
        host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
        
        if not public_key or not secret_key:
            self._logger.warning(
                "Langfuse keys not set. Set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY "
                "environment variables to enable tracing."
            )
            return
        
        try:
            self._langfuse_client = Langfuse(
                public_key=public_key,
                secret_key=secret_key,
                host=host,
            )
            
            self._callback_handler = LangfuseCallbackHandler(
                public_key=public_key,
                secret_key=secret_key,
                host=host,
                session_id=self.run_id,
            )
            
            self._logger.info(f"Langfuse tracing enabled | host={host}")
        except Exception as e:
            self._logger.error(f"Failed to initialize Langfuse: {e}")
            self._langfuse_client = None
            self._callback_handler = None
    
    @property
    def logger(self) -> logging.Logger:
        """Get the logger instance."""
        if self._logger is None:
            raise RuntimeError("ObservabilityManager not initialized")
        return self._logger
    
    @property
    def callback_handler(self) -> Any:
        """Get the Langfuse callback handler for LangChain/LangGraph."""
        return self._callback_handler
    
    @property
    def langfuse(self) -> Any:
        """Get the Langfuse client for custom tracing."""
        return self._langfuse_client
    
    @property
    def run_dir(self) -> Path:
        """Get the run directory path."""
        if self._run_dir is None:
            raise RuntimeError("ObservabilityManager not initialized")
        return self._run_dir
    
    def create_trace(self, name: str, metadata: dict | None = None) -> Any:
        """Create a new Langfuse trace.
        
        Args:
            name: Name of the trace
            metadata: Optional metadata dict
            
        Returns:
            Langfuse trace object or None if Langfuse not available
        """
        if self._langfuse_client is None:
            return None
        
        return self._langfuse_client.trace(
            name=name,
            session_id=self.run_id,
            metadata=metadata or {},
        )
    
    def log_tool_start(self, tool_name: str, target: str) -> None:
        """Log tool execution start."""
        self.logger.info(f"[TOOL] {tool_name} | Starting | target={target}")
    
    def log_tool_end(self, tool_name: str, findings_count: int, duration_ms: float) -> None:
        """Log tool execution end."""
        self.logger.info(
            f"[TOOL] {tool_name} | Completed | findings={findings_count} | duration={duration_ms:.0f}ms"
        )
    
    def log_tool_error(self, tool_name: str, error: Exception) -> None:
        """Log tool execution error."""
        self.logger.error(f"[TOOL] {tool_name} | Error | {type(error).__name__}: {error}")
    
    def log_finding(self, vuln_type: str, severity: str, url: str) -> None:
        """Log a vulnerability finding."""
        self.logger.warning(f"[FINDING] {vuln_type} | {severity} | {url}")
    
    def shutdown(self) -> None:
        """Shutdown observability - flush traces and close handlers."""
        if self._langfuse_client is not None:
            try:
                self._langfuse_client.flush()
            except Exception:
                pass
        
        if self._logger is not None:
            for handler in self._logger.handlers[:]:
                handler.close()
                self._logger.removeHandler(handler)


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
    """
    obs = ObservabilityManager.get_instance()
    if name:
        return logging.getLogger(name)
    return obs.logger


def get_callback_handler() -> Any:
    """Get the Langfuse callback handler for LangChain/LangGraph."""
    obs = ObservabilityManager.get_instance()
    return obs.callback_handler


def traced(name: str | None = None):
    """Decorator to trace a function with Langfuse.
    
    Args:
        name: Optional trace name (defaults to function name)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            obs = ObservabilityManager.get_instance()
            trace_name = name or func.__name__
            
            trace = obs.create_trace(
                name=trace_name,
                metadata={"args_count": len(args), "kwargs_keys": list(kwargs.keys())}
            )
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                obs.logger.error(f"[TRACE] {trace_name} | Error | {e}")
                raise
        
        return wrapper
    return decorator
