"""
Path utilities for consistent file and directory management.

All paths are absolute from the repository root, enabling execution from any location.
"""

import os
from pathlib import Path
from typing import Optional, Dict


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


def get_daily_reports_dir(run_id: Optional[str] = None) -> Path:
    """
    Get the daily reports directory for orchestrator runs.

    Organizes reports by date: runs/orchestrator/YYYYMMDD/

    DEPRECATED: Use get_run_dir() instead for new structure.

    Args:
        run_id: Optional run ID (format: YYYYMMDD_HHMMSS). If provided, extracts date from it.
                If None, uses current date.

    Returns:
        Path to daily reports directory (created if doesn't exist)
    """
    repo_root = get_repo_root()

    if run_id:
        # Extract date from run_id (format: YYYYMMDD_HHMMSS)
        # Take first 8 characters for date
        if len(run_id) >= 8:
            date_str = run_id[:8]
        else:
            # Fallback to current date if run_id format is unexpected
            from datetime import datetime
            date_str = datetime.now().strftime("%Y%m%d")
    else:
        # Use current date
        from datetime import datetime
        date_str = datetime.now().strftime("%Y%m%d")

    daily_dir = repo_root / "runs" / "orchestrator" / date_str
    daily_dir.mkdir(parents=True, exist_ok=True)
    return daily_dir


def get_run_dir(
    run_id: str,
    website_builder_model: Optional[str] = None,
    red_team_model: Optional[str] = None,
    create: bool = True
) -> Path:
    """
    Get the run directory for a specific orchestrator run.

    New structure: runs/orchestrator/YYYYMMDD/HHMMSS_{wb_model}_{rt_model}/

    Args:
        run_id: Run ID (format: YYYYMMDD_HHMMSS)
        website_builder_model: Website builder model name (e.g., "claude-3-haiku")
        red_team_model: Red team model name (e.g., "claude-3-haiku")
        create: Whether to create the directory if it doesn't exist

    Returns:
        Path to run directory
    """
    repo_root = get_repo_root()

    # Extract date and time from run_id
    if len(run_id) >= 8:
        date_str = run_id[:8]  # YYYYMMDD
        time_str = run_id[9:] if len(run_id) > 9 else run_id  # HHMMSS or full
    else:
        from datetime import datetime
        now = datetime.now()
        date_str = now.strftime("%Y%m%d")
        time_str = run_id

    # Extract time portion (HHMMSS)
    if '_' in time_str:
        time_str = time_str.split('_')[0]

    # Build directory name with model info
    dir_name_parts = [time_str]

    if website_builder_model:
        # Extract short model name (e.g., "claude-3-haiku" -> "haiku")
        wb_short = _extract_short_model_name(website_builder_model)
        dir_name_parts.append(wb_short)

    if red_team_model:
        rt_short = _extract_short_model_name(red_team_model)
        dir_name_parts.append(rt_short)

    dir_name = "_".join(dir_name_parts)

    # Create path: runs/orchestrator/YYYYMMDD/HHMMSS_model_model/
    run_dir = repo_root / "runs" / "orchestrator" / date_str / dir_name

    if create:
        run_dir.mkdir(parents=True, exist_ok=True)

    return run_dir


def _extract_short_model_name(model: str) -> str:
    """
    Extract short model name from full model identifier.

    Examples:
        "anthropic/claude-3-haiku" -> "haiku"
        "claude-3-5-sonnet" -> "sonnet"
        "gpt-4" -> "gpt4"

    Args:
        model: Full model identifier

    Returns:
        Short model name
    """
    # Remove provider prefix
    if '/' in model:
        model = model.split('/')[-1]

    # Extract key part
    if 'haiku' in model.lower():
        return 'haiku'
    elif 'sonnet' in model.lower():
        return 'sonnet'
    elif 'opus' in model.lower():
        return 'opus'
    elif 'gpt-4' in model.lower():
        return 'gpt4'
    elif 'gpt-3' in model.lower():
        return 'gpt3'
    else:
        # Fallback: use last part
        parts = model.replace('-', '_').split('_')
        return parts[-1] if parts else model


def create_run_structure(
    run_id: str,
    website_builder_model: Optional[str] = None,
    red_team_model: Optional[str] = None
) -> Dict[str, Path]:
    """
    Create complete directory structure for a run organized by agents.

    Structure:
        YYYYMMDD/HHMMSS_{wb_model}_{rt_model}/
            ├── run.json
            ├── report.md
            ├── website/
            ├── logs/
            └── reports/
                ├── website_builder/
                ├── static_analysis/
                ├── red_team/
                ├── website_builder_evaluator/
                ├── red_team_evaluator/
                └── final/

    Args:
        run_id: Run ID (format: YYYYMMDD_HHMMSS)
        website_builder_model: Website builder model name
        red_team_model: Red team model name

    Returns:
        Dictionary with paths to all key directories and files
    """
    run_dir = get_run_dir(run_id, website_builder_model, red_team_model, create=True)

    # Create subdirectories
    website_dir = run_dir / "website"
    website_dir.mkdir(exist_ok=True)

    logs_dir = run_dir / "logs"
    logs_dir.mkdir(exist_ok=True)

    # Create agent-specific report directories
    reports_dir = run_dir / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    agent_dirs = {
        'website_builder': reports_dir / "website_builder",
        'static_analysis': reports_dir / "static_analysis",
        'red_team': reports_dir / "red_team",
        'website_builder_evaluator': reports_dir / "website_builder_evaluator",
        'red_team_evaluator': reports_dir / "red_team_evaluator",
        'final': reports_dir / "final"
    }
    
    for agent_dir in agent_dirs.values():
        agent_dir.mkdir(exist_ok=True)

    return {
        'run_dir': run_dir,
        'website_dir': website_dir,
        'logs_dir': logs_dir,
        'reports_dir': reports_dir,
        'agent_dirs': agent_dirs,
        'run_json': run_dir / "run.json",
        'report_md': run_dir / "report.md",
        'red_team_report_md': agent_dirs['red_team'] / "red_team_report.md"
    }


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

