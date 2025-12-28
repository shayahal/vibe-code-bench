"""Script to migrate existing reports to day-based folder structure."""

import json
import sys
import os
from pathlib import Path
from datetime import datetime

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from vibe_code_bench.core.paths import get_reports_dir, get_reports_dir_for_date


def extract_date_from_filename(filename: str) -> str:
    """Extract date from filename like browsing_20251211_133142.md"""
    try:
        # Try to find YYYYMMDD pattern
        parts = filename.split('_')
        for part in parts:
            if len(part) == 8 and part.isdigit():
                # YYYYMMDD format
                year = part[:4]
                month = part[4:6]
                day = part[6:8]
                return f"{year}-{month}-{day}"
    except:
        pass
    
    # Fallback: try to extract from JSON content
    return None


def extract_run_id_from_filename(filename: str) -> str:
    """Extract run_id from filename to group related reports."""
    try:
        # Patterns: browsing_20251211_133142.md, red_team_20251211_133142.json, combined_20251211_133142.md
        # Or: browsing_discovery_20251211_133142_comprehensive.json
        
        # Remove extension
        base_name = filename.rsplit('.', 1)[0]
        
        # Check for browsing_discovery pattern
        if 'browsing_discovery_' in base_name:
            # Extract timestamp part: browsing_discovery_20251211_133142_comprehensive
            parts = base_name.split('_')
            if len(parts) >= 3:
                date_part = parts[2]  # 20251211
                time_part = parts[3] if len(parts) > 3 else None
                if time_part and len(time_part) == 6:  # HHMMSS
                    return f"browsing_{date_part}_{time_part}"
                else:
                    return f"browsing_{date_part}"
        
        # Check for standard patterns: browsing_YYYYMMDD_HHMMSS, red_team_YYYYMMDD_HHMMSS, combined_YYYYMMDD_HHMMSS
        if base_name.startswith('browsing_') or base_name.startswith('red_team_') or base_name.startswith('combined_'):
            # Already has run_id format
            return base_name
        
        # Try to extract date and time
        parts = base_name.split('_')
        for i, part in enumerate(parts):
            if len(part) == 8 and part.isdigit():  # YYYYMMDD
                # Check if next part is time
                if i + 1 < len(parts) and len(parts[i+1]) == 6 and parts[i+1].isdigit():
                    # Has both date and time
                    prefix = '_'.join(parts[:i]) if i > 0 else 'unknown'
                    return f"{prefix}_{part}_{parts[i+1]}"
                else:
                    # Only date
                    prefix = '_'.join(parts[:i]) if i > 0 else 'unknown'
                    return f"{prefix}_{part}"
    except:
        pass
    
    return None


def extract_date_from_json(file_path: Path) -> str:
    """Extract date from JSON file content."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # Try discovered_at or tested_at
        timestamp = data.get('discovered_at') or data.get('tested_at')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.strftime("%Y-%m-%d")
            except:
                pass
    except:
        pass
    
    return None


def migrate_reports():
    """Migrate all reports from root reports directory to day-based folders."""
    reports_dir = get_reports_dir()
    
    if not reports_dir.exists():
        print(f"Reports directory does not exist: {reports_dir}")
        return
    
    # Find all report files (including those already in day folders)
    report_files = []
    # Files in root
    report_files.extend(reports_dir.glob("*.json"))
    report_files.extend(reports_dir.glob("*.md"))
    # Files in day folders (but not in run folders yet)
    for day_folder in reports_dir.iterdir():
        if day_folder.is_dir() and len(day_folder.name) == 10 and day_folder.name.count('-') == 2:
            # This is a date folder (YYYY-MM-DD)
            report_files.extend(day_folder.glob("*.json"))
            report_files.extend(day_folder.glob("*.md"))
    
    # Filter out files already in run folders (nested in day folders)
    report_files = [f for f in report_files if f.parent.name == f.parent.parent.name or not (f.parent.parent.name.count('-') == 2)]
    
    print(f"Found {len(report_files)} report files to migrate")
    
    migrated = 0
    skipped = 0
    errors = 0
    
    # Group files by run_id
    files_by_run = {}
    
    for file_path in report_files:
        try:
            # Try to extract date from filename
            date_str = extract_date_from_filename(file_path.name)
            
            # If not found, try JSON content
            if not date_str and file_path.suffix == '.json':
                date_str = extract_date_from_json(file_path)
            
            # If still not found, use file modification time
            if not date_str:
                mtime = file_path.stat().st_mtime
                date_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
            
            # Extract run_id to group related files
            run_id = extract_run_id_from_filename(file_path.name)
            if not run_id:
                # Fallback: use filename without extension as run_id
                run_id = file_path.stem
            
            # Group by date and run_id
            key = (date_str, run_id)
            if key not in files_by_run:
                files_by_run[key] = []
            files_by_run[key].append(file_path)
            
        except Exception as e:
            print(f"Error processing {file_path.name}: {e}")
            errors += 1
    
    # Migrate files grouped by run
    for (date_str, run_id), files in files_by_run.items():
        try:
            # Create destination directory with run folder
            dest_dir = get_reports_dir_for_date(date_str)
            run_folder = dest_dir / run_id
            run_folder.mkdir(parents=True, exist_ok=True)
            
            for file_path in files:
                dest_path = run_folder / file_path.name
                
                # Skip if already exists
                if dest_path.exists():
                    print(f"Skipping {file_path.name} (already exists in {date_str}/{run_id}/)")
                    skipped += 1
                    continue
                
                # Move file
                file_path.rename(dest_path)
                print(f"Migrated {file_path.name} -> {date_str}/{run_id}/{file_path.name}")
                migrated += 1
                
        except Exception as e:
            print(f"Error migrating run {run_id}: {e}")
            errors += len(files)
    
    print(f"\nMigration complete:")
    print(f"  - Migrated: {migrated}")
    print(f"  - Skipped: {skipped}")
    print(f"  - Errors: {errors}")


if __name__ == "__main__":
    print("Migrating reports to day-based folder structure with run folders...")
    migrate_reports()
