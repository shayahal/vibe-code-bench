"""
Logging configuration for the Red Team Agent.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def setup_file_logging(run_dir: Path) -> None:
    """
    Set up file logging for the current run with separate files for each log level.
    
    Args:
        run_dir: Path to the run directory
    """
    global logger
    
    # Get the root logger
    logger = logging.getLogger()
    
    # Remove existing file handlers
    for handler in logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            logger.removeHandler(handler)
    
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
    
    # DEBUG log - DEBUG level only (most verbose, includes function names and line numbers)
    debug_handler = logging.FileHandler(logs_dir / "debug.log", mode='w')
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(detailed_formatter)
    debug_handler.addFilter(lambda record: record.levelno == logging.DEBUG)
    logger.addHandler(debug_handler)
    
    # INFO log - INFO level only (normal operation)
    info_handler = logging.FileHandler(logs_dir / "info.log", mode='w')
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(simple_formatter)
    info_handler.addFilter(lambda record: record.levelno == logging.INFO)
    logger.addHandler(info_handler)
    
    # WARNING log - WARNING level only (unexpected conditions, security issues)
    warning_handler = logging.FileHandler(logs_dir / "warnings.log", mode='w')
    warning_handler.setLevel(logging.WARNING)
    warning_handler.setFormatter(simple_formatter)
    warning_handler.addFilter(lambda record: record.levelno == logging.WARNING)
    logger.addHandler(warning_handler)
    
    # ERROR log - ERROR and CRITICAL only (failures, exceptions)
    error_handler = logging.FileHandler(logs_dir / "errors.log", mode='w')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    error_handler.addFilter(lambda record: record.levelno >= logging.ERROR)
    logger.addHandler(error_handler)
    
    # Combined log - all messages (for convenience)
    all_handler = logging.FileHandler(logs_dir / "agent.log", mode='w')
    all_handler.setLevel(logging.DEBUG)
    all_handler.setFormatter(simple_formatter)
    logger.addHandler(all_handler)
    
    logger.info(f"Logging configured - separate log files created in: {logs_dir}")
    logger.debug("DEBUG logging enabled with detailed formatter")

