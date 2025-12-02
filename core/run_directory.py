"""
Run directory management for organizing test runs.
"""

from pathlib import Path
from datetime import datetime

# Global variable to track current run directory
_current_run_dir: Path = None


def setup_run_directory(base_dir: str = "runs") -> Path:
    """
    Create a unique run directory based on timestamp.
    
    Args:
        base_dir: Base directory for runs (default: "runs")
    
    Returns:
        Path to the created run directory
    """
    global _current_run_dir
    
    # Create base runs directory if it doesn't exist
    base_path = Path(base_dir)
    base_path.mkdir(exist_ok=True)
    
    # Create timestamp-based directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"run_{timestamp}"
    run_dir = base_path / run_id
    run_dir.mkdir(exist_ok=True)
    
    # Create subdirectories
    (run_dir / "logs").mkdir(exist_ok=True)
    (run_dir / "reports").mkdir(exist_ok=True)
    
    _current_run_dir = run_dir
    return run_dir

