"""Run directory management utilities for linking reports to run directories."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from vibe_code_bench.core.paths import get_runs_dir, get_reports_dir


def setup_run_directory(subdir: str, run_id: Optional[str] = None) -> Path:
    """
    Create a run directory for organizing agent runs.

    Args:
        subdir: Subdirectory name (e.g., "browsing_agent", "red_team_agent")
        run_id: Optional run ID. If not provided, generates timestamp-based ID.

    Returns:
        Path to the created run directory
    """
    if run_id is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_id = f"run_{timestamp}"

    runs_dir = get_runs_dir()
    run_dir = runs_dir / subdir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Create standard subdirectories
    (run_dir / "logs").mkdir(exist_ok=True)
    (run_dir / "data").mkdir(exist_ok=True)

    # Create metadata file
    metadata = {
        "run_id": run_id,
        "subdir": subdir,
        "created_at": datetime.now().isoformat(),
        "reports": {
            "browsing": None,
            "red_team": None,
            "combined": None,
        },
    }
    metadata_file = run_dir / "metadata.json"
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return run_dir


def link_report_to_run(
    run_dir: Path,
    report_type: str,
    report_path: Path,
) -> None:
    """
    Link a report to a run directory by updating metadata.

    Args:
        run_dir: Path to run directory
        report_type: Type of report ("browsing", "red_team", or "combined")
        report_path: Path to the report file
    """
    metadata_file = run_dir / "metadata.json"
    
    if not metadata_file.exists():
        # Create metadata if it doesn't exist
        metadata = {
            "run_id": run_dir.name,
            "subdir": run_dir.parent.name,
            "created_at": datetime.now().isoformat(),
            "reports": {
                "browsing": None,
                "red_team": None,
                "combined": None,
            },
        }
    else:
        with open(metadata_file, "r", encoding="utf-8") as f:
            metadata = json.load(f)

    # Update report path
    if report_type in metadata["reports"]:
        # Store relative path from reports directory for portability
        reports_dir = get_reports_dir()
        try:
            relative_path = report_path.relative_to(reports_dir)
            metadata["reports"][report_type] = str(relative_path)
        except ValueError:
            # If not relative to reports_dir, store absolute path
            metadata["reports"][report_type] = str(report_path)

    # Update metadata file
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)


def get_run_reports(run_dir: Path) -> Dict[str, Optional[str]]:
    """
    Get report paths linked to a run directory.

    Args:
        run_dir: Path to run directory

    Returns:
        Dictionary with report paths (keys: "browsing", "red_team", "combined")
    """
    metadata_file = run_dir / "metadata.json"
    
    if not metadata_file.exists():
        return {
            "browsing": None,
            "red_team": None,
            "combined": None,
        }

    with open(metadata_file, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    reports = metadata.get("reports", {})
    
    # Resolve relative paths to absolute paths
    reports_dir = get_reports_dir()
    resolved_reports = {}
    for report_type, report_path in reports.items():
        if report_path:
            try:
                # Try relative path first
                resolved_path = reports_dir / report_path
                if resolved_path.exists():
                    resolved_reports[report_type] = str(resolved_path)
                else:
                    # Fall back to absolute path
                    resolved_path = Path(report_path)
                    if resolved_path.exists():
                        resolved_reports[report_type] = str(resolved_path)
                    else:
                        resolved_reports[report_type] = None
            except (ValueError, TypeError):
                resolved_reports[report_type] = None
        else:
            resolved_reports[report_type] = None

    return resolved_reports


def find_report_by_run_id(run_id: str, report_type: str = "browsing") -> Optional[Path]:
    """
    Find a report file by run ID.

    Args:
        run_id: Run ID to search for
        report_type: Type of report ("browsing", "red_team", or "combined")

    Returns:
        Path to report file if found, None otherwise
    """
    reports_dir = get_reports_dir()
    
    # Ensure run_id has the correct prefix
    if report_type == "browsing" and not run_id.startswith("browsing_"):
        filename = f"browsing_{run_id}.md"
    elif report_type == "red_team" and not run_id.startswith("red_team_"):
        filename = f"red_team_{run_id}.md"
    elif report_type == "combined" and not run_id.startswith("combined_"):
        filename = f"combined_{run_id}.md"
    else:
        filename = f"{run_id}.md"
    
    # Try markdown first
    report_file = reports_dir / filename
    if report_file.exists():
        return report_file
    
    # Try JSON
    json_file = reports_dir / filename.replace(".md", ".json")
    if json_file.exists():
        return json_file
    
    return None
