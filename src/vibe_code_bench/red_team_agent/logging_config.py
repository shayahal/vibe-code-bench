"""Logging configuration for red team agent."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from vibe_code_bench.core.paths import get_runs_dir


def setup_red_team_logging(run_id: Optional[str] = None) -> tuple[Path, logging.Logger]:
    """
    Setup logging for red team agent.

    Args:
        run_id: Optional run ID. If not provided, generates timestamp-based ID.

    Returns:
        Tuple of (run_directory, logger)
    """
    # Create run directory
    if run_id is None:
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    run_dir = get_runs_dir() / "red_team_agent" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Create logs directory
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Setup main log file
    log_file = logs_dir / "red_team.log"

    # Configure root logger for red_team_agent
    logger = logging.getLogger("vibe_code_bench.red_team_agent")
    logger.setLevel(logging.INFO)

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Create specialized loggers for different components
    setup_component_logger("automated_scanning", logs_dir)
    setup_component_logger("form_testing", logs_dir)
    setup_component_logger("auth_testing", logs_dir)
    setup_component_logger("api_testing", logs_dir)
    setup_component_logger("llm_testing", logs_dir)

    logger.info(f"[SETUP] Red team agent logging initialized - Run ID: {run_id}")
    logger.info(f"[SETUP] Log directory: {logs_dir}")

    return run_dir, logger


def setup_component_logger(component_name: str, logs_dir: Path) -> logging.Logger:
    """
    Setup a specialized logger for a component.

    Args:
        component_name: Name of the component
        logs_dir: Directory for log files

    Returns:
        Logger instance
    """
    logger = logging.getLogger(f"vibe_code_bench.red_team_agent.{component_name}")
    logger.setLevel(logging.INFO)

    # Component-specific log file
    log_file = logs_dir / f"{component_name}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
