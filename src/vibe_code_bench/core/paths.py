"""Path management utilities for absolute paths from repo root."""

from pathlib import Path


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
