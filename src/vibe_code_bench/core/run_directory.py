"""
Run directory management for organizing test runs.

All paths are absolute from repository root.
"""

from pathlib import Path
from datetime import datetime
from vibe_code_bench.core.paths import get_runs_dir

# Global variable to track current run directory
_current_run_dir: Path = None


def setup_run_directory(subdir: str = "") -> Path:
    """
    Create a unique run directory based on timestamp.
    
    All runs are stored in data/runs/ at repo root.
    
    Args:
        subdir: Optional subdirectory within runs (e.g., "website_generator", "red_team")
    
    Returns:
        Absolute Path to the created run directory
    """
    global _current_run_dir
    
    # Get standard runs directory (absolute from repo root)
    base_runs_dir = get_runs_dir()
    
    # Add subdirectory if specified
    if subdir:
        base_path = base_runs_dir / subdir
    else:
        base_path = base_runs_dir
    
    base_path.mkdir(parents=True, exist_ok=True)
    
    # Create timestamp-based directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"run_{timestamp}"
    run_dir = base_path / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    
    # Create subdirectories
    (run_dir / "logs").mkdir(exist_ok=True)
    (run_dir / "reports").mkdir(exist_ok=True)
    (run_dir / "website").mkdir(exist_ok=True)
    
    _current_run_dir = run_dir
    return run_dir

