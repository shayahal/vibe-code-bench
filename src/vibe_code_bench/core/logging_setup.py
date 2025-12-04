"""
Unified logging configuration for all agents.

This module provides a centralized logging system with:
- Separate file handles for each log level (DEBUG, INFO, WARNING, ERROR)
- Console output for user feedback (INFO and above)
- Consistent formatting across all modules
- No print statements - all output goes through logging

Log Level Guidelines:
- DEBUG: Non-important information, detailed execution traces
- INFO: Logical steps in the process, interesting events, normal operation
- WARNING: Things that aren't perfect but don't break the flow
- ERROR: Things that went wrong, exceptions, failures
"""

import logging
import sys
from pathlib import Path
from typing import Optional

# Global logger instance - use get_logger() to get module-specific loggers
_root_logger_configured = False


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance for a module.
    
    This is the unified API for all logging in the system.
    Use this instead of logging.getLogger() directly.
    
    Args:
        name: Logger name (typically __name__). If None, returns root logger.
        
    Returns:
        Logger instance configured with the unified logging system
    """
    if name is None:
        return logging.getLogger()
    return logging.getLogger(name)


def setup_logging(run_dir: Optional[Path] = None, console_level: int = logging.INFO) -> None:
    """
    Set up unified logging system with separate file handles for each log level.
    
    This function:
    - Creates separate log files for DEBUG, INFO, WARNING, and ERROR
    - Adds console handler for user feedback (INFO and above by default)
    - Configures all loggers to use the same handlers
    - Should be called once at application startup
    
    Args:
        run_dir: Optional path to run directory. If provided, creates log files there.
                 If None, only console logging is configured.
        console_level: Minimum log level for console output (default: INFO)
    """
    global _root_logger_configured
    
    root_logger = logging.getLogger()
    
    # Only configure once
    if _root_logger_configured:
        root_logger.debug("Logging already configured, skipping reconfiguration")
        return
    
    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    
    # Set root logger level to DEBUG to capture everything
    root_logger.setLevel(logging.DEBUG)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )
    
    # Console handler - for user feedback (INFO and above)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handlers (only if run_dir is provided)
    if run_dir:
        logs_dir = run_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        # DEBUG log - DEBUG and above (most verbose, detailed formatter)
        debug_handler = logging.FileHandler(logs_dir / "agent.debug", mode='w', encoding='utf-8')
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(debug_handler)
        
        # INFO log - INFO and above (normal operation)
        info_handler = logging.FileHandler(logs_dir / "agent.info", mode='w', encoding='utf-8')
        info_handler.setLevel(logging.INFO)
        info_handler.setFormatter(simple_formatter)
        root_logger.addHandler(info_handler)
        
        # WARNING log - WARNING and above (issues, non-critical problems)
        warning_handler = logging.FileHandler(logs_dir / "agent.warning", mode='w', encoding='utf-8')
        warning_handler.setLevel(logging.WARNING)
        warning_handler.setFormatter(simple_formatter)
        root_logger.addHandler(warning_handler)
        
        # ERROR log - ERROR and CRITICAL only (failures, exceptions)
        error_handler = logging.FileHandler(logs_dir / "agent.error", mode='w', encoding='utf-8')
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(error_handler)
        
        root_logger.info(f"Logging configured - log files created in: {logs_dir}")
    else:
        root_logger.info("Logging configured - console output only")
    
    root_logger.debug("DEBUG logging enabled")
    _root_logger_configured = True


def setup_file_logging(run_dir: Path) -> None:
    """
    Legacy function name - calls setup_logging() for backward compatibility.
    
    Args:
        run_dir: Path to the run directory
    """
    setup_logging(run_dir=run_dir)

