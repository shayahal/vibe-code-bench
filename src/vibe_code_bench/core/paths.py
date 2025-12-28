"""Path management utilities for absolute paths from repo root."""

from pathlib import Path
from typing import Optional


def get_repo_root() -> Path:
    """Get the repository root directory."""
    # This file is at src/vibe_code_bench/core/paths.py
    # Repo root is 3 levels up
    current_file = Path(__file__).resolve()
    repo_root = current_file.parent.parent.parent.parent
    return repo_root


def get_runs_dir() -> Path:
    """Get the runs directory."""
    repo_root = get_repo_root()
    runs_dir = repo_root / "data" / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    return runs_dir


def get_reports_dir() -> Path:
    """Get the reports directory."""
    repo_root = get_repo_root()
    reports_dir = repo_root / "data" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def get_reports_dir_for_date(date_str: Optional[str] = None) -> Path:
    """
    Get the reports directory for a specific date.
    
    Args:
        date_str: Date string in format YYYY-MM-DD. If None, uses today's date.
    
    Returns:
        Path to the date-specific reports directory
    """
    from datetime import datetime
    
    if date_str is None:
        date_str = datetime.now().strftime("%Y-%m-%d")
    
    reports_dir = get_reports_dir()
    date_dir = reports_dir / date_str
    date_dir.mkdir(parents=True, exist_ok=True)
    return date_dir


def get_logs_dir() -> Path:
    """Get the logs directory."""
    repo_root = get_repo_root()
    logs_dir = repo_root / "data" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir


def get_cache_dir() -> Path:
    """Get the cache directory."""
    repo_root = get_repo_root()
    cache_dir = repo_root / "data" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_resources_dir() -> Path:
    """Get the resources directory."""
    repo_root = get_repo_root()
    resources_dir = repo_root / "data" / "resources"
    resources_dir.mkdir(parents=True, exist_ok=True)
    return resources_dir


def get_absolute_path(path: str) -> Path:
    """
    Resolve a path relative to repo root to an absolute path.

    Args:
        path: Path relative to repo root or absolute path

    Returns:
        Absolute Path object
    """
    path_obj = Path(path)
    if path_obj.is_absolute():
        return path_obj

    repo_root = get_repo_root()
    return repo_root / path_obj


def extract_base_run_id(run_id: Optional[str] = None, timestamp: Optional[str] = None) -> str:
    """
    Extract base run ID (timestamp) from a run_id string, removing prefixes.
    
    This function extracts the timestamp portion (YYYYMMDD_HHMMSS) from run_ids
    like "browsing_20251213_225122", "red_team_20251213_225122", etc.
    
    Args:
        run_id: Run ID string (e.g., "browsing_20251213_225122")
        timestamp: Optional timestamp string in ISO format
    
    Returns:
        Base run ID in format "run_YYYYMMDD_HHMMSS"
    """
    from datetime import datetime
    
    # If timestamp provided, extract date from it
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return f"run_{dt.strftime('%Y%m%d_%H%M%S')}"
        except:
            pass
    
    # Extract from run_id
    if run_id:
        # Remove common prefixes
        for prefix in ["browsing_", "red_team_", "combined_", "run_"]:
            if run_id.startswith(prefix):
                base_id = run_id[len(prefix):]
                # Check if it's a valid timestamp format (YYYYMMDD_HHMMSS)
                if len(base_id) >= 15 and base_id[8] == '_':
                    return f"run_{base_id}"
                break
        
        # If run_id already looks like a timestamp, use it
        if len(run_id) >= 15 and run_id[8] == '_':
            return f"run_{run_id}"
    
    # Fallback to current timestamp
    return f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
