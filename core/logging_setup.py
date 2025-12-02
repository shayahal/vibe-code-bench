"""
Unified logging configuration for all agents.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def setup_file_logging(run_dir: Path) -> None:
    """
    Set up file logging for the current run with separate files for each log level.
    Used by both red team agent and website creator agent.
    
    Args:
        run_dir: Path to the run directory
    """
    # Get the root logger to ensure all loggers inherit the handlers
    root_logger = logging.getLogger()
    
    # Remove existing file handlers
    for handler in root_logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            root_logger.removeHandler(handler)
    
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(exist_ok=True)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # DEBUG log - DEBUG and above (most verbose)
    debug_handler = logging.FileHandler(logs_dir / "agent.debug", mode='w')
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(debug_handler)
    
    # INFO log - INFO and above (normal operation + errors)
    info_handler = logging.FileHandler(logs_dir / "agent.info", mode='w')
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(simple_formatter)
    root_logger.addHandler(info_handler)
    
    # WARNING log - WARNING and above (security issues, errors)
    warning_handler = logging.FileHandler(logs_dir / "agent.warning", mode='w')
    warning_handler.setLevel(logging.WARNING)
    warning_handler.setFormatter(simple_formatter)
    root_logger.addHandler(warning_handler)
    
    # ERROR log - ERROR and CRITICAL only (failures, exceptions)
    error_handler = logging.FileHandler(logs_dir / "agent.error", mode='w')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    root_logger.addHandler(error_handler)
    
    # Ensure the root logger captures everything so handlers can filter it
    root_logger.setLevel(logging.DEBUG)
    
    # Use root logger to log the configuration message
    root_logger.info(f"Logging configured - separate log files created in: {logs_dir}")
    root_logger.debug("DEBUG logging enabled with detailed formatter")

