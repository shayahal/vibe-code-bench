"""
Path utilities for consistent file and directory management.

All paths are absolute from the repository root, enabling execution from any location.
"""

import os
from pathlib import Path
from typing import Optional


def get_repo_root() -> Path:
    """
    Get the absolute path to the repository root.
    
    Finds the repo root by looking for pyproject.toml or .git directory,
    starting from the current file and walking up.
    
    Returns:
        Path to repository root
        
    Raises:
        RuntimeError: If repo root cannot be found
    """
    # Start from this file's directory
    current = Path(__file__).resolve()
    
    # Walk up the directory tree
    for parent in [current] + list(current.parents):
        # Check for repo root markers
        if (parent / "pyproject.toml").exists():
            return parent
        if (parent / ".git").exists():
            return parent
        if (parent / "README.md").exists() and (parent / "src").exists():
            return parent
    
    # Fallback: try to find from common locations
    # If we're in src/vibe_code_bench/core, go up 3 levels
    if "src" in current.parts and "vibe_code_bench" in current.parts:
        idx = current.parts.index("src")
        return Path(*current.parts[:idx])
    
    raise RuntimeError(
        "Could not find repository root. "
        "Make sure you're running from within the vibe-code-bench repository."
    )


# Cache the repo root
_REPO_ROOT: Optional[Path] = None


def get_data_dir() -> Path:
    """
    Get the standard data directory at repo root.
    
    Structure:
        data/
          runs/          - All run directories
          reports/       - All reports
          logs/          - All logs
          resources/     - Resources and static files
    
    Returns:
        Path to data directory (created if doesn't exist)
    """
    repo_root = get_repo_root()
    data_dir = repo_root / "data"
    data_dir.mkdir(exist_ok=True)
    return data_dir


def get_runs_dir() -> Path:
    """
    Get the standard runs directory.
    
    Returns:
        Path to runs directory (created if doesn't exist)
    """
    runs_dir = get_data_dir() / "runs"
    runs_dir.mkdir(exist_ok=True)
    return runs_dir


def get_reports_dir() -> Path:
    """
    Get the standard reports directory.
    
    Returns:
        Path to reports directory (created if doesn't exist)
    """
    reports_dir = get_data_dir() / "reports"
    reports_dir.mkdir(exist_ok=True)
    return reports_dir


def get_logs_dir() -> Path:
    """
    Get the standard logs directory.
    
    Returns:
        Path to logs directory (created if doesn't exist)
    """
    logs_dir = get_data_dir() / "logs"
    logs_dir.mkdir(exist_ok=True)
    return logs_dir


def get_resources_dir() -> Path:
    """
    Get the standard resources directory.
    
    Returns:
        Path to resources directory (created if doesn't exist)
    """
    resources_dir = get_data_dir() / "resources"
    resources_dir.mkdir(exist_ok=True)
    return resources_dir


def get_absolute_path(path: str | Path, base: Optional[Path] = None) -> Path:
    """
    Convert a path to absolute, resolving from repo root if relative.
    
    Args:
        path: Path to resolve (can be relative or absolute)
        base: Base directory (default: repo root)
        
    Returns:
        Absolute Path
    """
    path = Path(path)
    
    # If already absolute, return as-is
    if path.is_absolute():
        return path
    
    # Resolve from base (default: repo root)
    if base is None:
        base = get_repo_root()
    
    return (base / path).resolve()

