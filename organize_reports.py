#!/usr/bin/env python3
"""
Organize all existing reports into daily directories.

Moves reports from various locations into runs/orchestrator/YYYYMMDD/
"""

import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional

from vibe_code_bench.core.paths import get_repo_root, get_daily_reports_dir

def extract_date_from_filename(filename: str) -> Optional[str]:
    """Extract date from filename (format: YYYYMMDD_HHMMSS or YYYYMMDD)."""
    # Try to extract date from run_id pattern
    parts = filename.split('_')
    for part in parts:
        if len(part) == 8 and part.isdigit():
            # Check if it's a valid date (YYYYMMDD)
            try:
                datetime.strptime(part, '%Y%m%d')
                return part
            except ValueError:
                continue
    return None

def extract_date_from_run_id(run_id: str) -> Optional[str]:
    """Extract date from run_id (format: YYYYMMDD_HHMMSS)."""
    if len(run_id) >= 8:
        date_str = run_id[:8]
        try:
            datetime.strptime(date_str, '%Y%m%d')
            return date_str
        except ValueError:
            pass
    return None

def organize_reports():
    """Organize all reports into daily directories."""
    repo_root = get_repo_root()
    
    # Find all report files
    report_files = []
    
    # 1. Reports in run directories (runs/orchestrator/run_*/reports/)
    runs_dir = repo_root / "runs" / "orchestrator"
    if runs_dir.exists():
        for run_dir in runs_dir.glob("run_*/reports/*"):
            if run_dir.is_file() and (run_dir.suffix in ['.json', '.md']):
                report_files.append(run_dir)
    
    # 2. Reports in data/reports/
    data_reports_dir = repo_root / "data" / "reports"
    if data_reports_dir.exists():
        for report_file in data_reports_dir.glob("*"):
            if report_file.is_file() and (report_file.suffix in ['.json', '.md']):
                report_files.append(report_file)
    
    # 3. Reports already in daily directories (skip these)
    daily_dirs = list((repo_root / "runs" / "orchestrator").glob("20*"))
    already_organized = set()
    for daily_dir in daily_dirs:
        if daily_dir.is_dir() and len(daily_dir.name) == 8:
            for report_file in daily_dir.glob("*"):
                if report_file.is_file():
                    already_organized.add(report_file.name)
    
    print(f"Found {len(report_files)} report files to organize")
    print(f"Skipping {len(already_organized)} already organized files")
    
    organized_count = 0
    skipped_count = 0
    
    for report_file in report_files:
        # Skip if already in daily directory
        if report_file.name in already_organized:
            skipped_count += 1
            continue
        
        # Extract date from filename or parent directory
        date_str = None
        
        # Try to extract from filename
        date_str = extract_date_from_filename(report_file.stem)
        
        # If not found, try to extract from parent run directory name
        if not date_str:
            parent = report_file.parent
            if parent.name == "reports":
                run_dir = parent.parent
                if run_dir.name.startswith("run_"):
                    run_id = run_dir.name[4:]  # Remove "run_" prefix
                    date_str = extract_date_from_run_id(run_id)
        
        # If still not found, try to extract from file content (for JSON files)
        if not date_str and report_file.suffix == '.json':
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Check metadata for run_id or timestamp
                    if isinstance(data, dict):
                        metadata = data.get('metadata', {})
                        run_id = metadata.get('run_id') or metadata.get('timestamp', '')
                        if run_id:
                            date_str = extract_date_from_run_id(str(run_id))
            except Exception:
                pass
        
        # If still not found, use file modification date
        if not date_str:
            try:
                mtime = report_file.stat().st_mtime
                date_str = datetime.fromtimestamp(mtime).strftime('%Y%m%d')
            except Exception:
                print(f"Warning: Could not determine date for {report_file}, skipping")
                skipped_count += 1
                continue
        
        # Get or create daily directory
        daily_dir = get_daily_reports_dir(date_str)
        
        # Move file to daily directory
        dest_file = daily_dir / report_file.name
        
        # Handle duplicates
        if dest_file.exists():
            # Add suffix if file already exists
            counter = 1
            while dest_file.exists():
                stem = report_file.stem
                suffix = report_file.suffix
                dest_file = daily_dir / f"{stem}_{counter}{suffix}"
                counter += 1
        
        try:
            shutil.move(str(report_file), str(dest_file))
            print(f"Moved: {report_file.name} -> {daily_dir.name}/")
            organized_count += 1
        except Exception as e:
            print(f"Error moving {report_file}: {e}")
            skipped_count += 1
    
    print(f"\n✓ Organized {organized_count} reports")
    print(f"  Skipped {skipped_count} reports")
    
    # Clean up empty directories
    print("\nCleaning up empty directories...")
    cleaned = 0
    
    # Clean up empty reports directories in run folders
    for run_dir in (repo_root / "runs" / "orchestrator").glob("run_*/reports"):
        if run_dir.exists() and run_dir.is_dir():
            try:
                if not any(run_dir.iterdir()):
                    run_dir.rmdir()
                    print(f"Removed empty directory: {run_dir}")
                    cleaned += 1
            except Exception:
                pass
    
    print(f"Cleaned up {cleaned} empty directories")

if __name__ == "__main__":
    organize_reports()

