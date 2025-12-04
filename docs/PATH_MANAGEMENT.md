# Path Management Guidelines

This document describes the path management system for the Vibe Code Bench project.

## Overview

All file operations in this codebase use **absolute paths from the repository root**. This ensures the code works correctly regardless of the current working directory.

## Standard Directory Structure

All output is organized under `data/` at the repository root:

```
data/
├── runs/          # All run directories (organized by subdirectory and timestamp)
├── reports/       # All reports
├── logs/          # All logs
└── resources/     # Resources and static files
```

## Using the Path Utilities

Import the path utilities from `vibe_code_bench.core.paths`:

```python
from vibe_code_bench.core.paths import (
    get_repo_root,      # Get absolute path to repo root
    get_runs_dir,        # Get data/runs/ directory
    get_reports_dir,     # Get data/reports/ directory
    get_logs_dir,        # Get data/logs/ directory
    get_resources_dir,   # Get data/resources/ directory
    get_absolute_path,   # Resolve any path to absolute from repo root
)
```

## Common Operations

### Creating Run Directories

```python
from vibe_code_bench.core.run_directory import setup_run_directory

# Creates: data/runs/website_generator/run_20251204_123456/
run_dir = setup_run_directory(subdir="website_generator")

# Creates: data/runs/red_team/run_20251204_123456/
run_dir = setup_run_directory(subdir="red_team")
```

### Saving Reports

```python
from vibe_code_bench.red_team_agent.agent_common import save_report

# Saves to: data/reports/run_report_12345.md
report_file = save_report(report_content, run_id="12345")
```

### Resolving User-Provided Paths

```python
from vibe_code_bench.core.paths import get_absolute_path

# User provides relative or absolute path
user_path = get_absolute_path("config.json")  # Resolves from repo root
user_path = get_absolute_path("../other/config.json")  # Also works
```

### Working with Standard Directories

```python
from vibe_code_bench.core.paths import get_reports_dir

# Save evaluation results
eval_file = get_reports_dir() / "evaluation_results.json"
```

## Rules

### ✅ DO

- Use `get_absolute_path()` for any user-provided or config paths
- Use standard directory functions (`get_runs_dir()`, `get_reports_dir()`, etc.)
- Use `setup_run_directory()` for creating run directories
- All paths should be absolute from repo root

### ❌ DON'T

- Use relative paths like `Path("runs/website")` or `Path("../output")`
- Use `Path(__file__).parent` for file operations
- Use `sys.path.insert()` - the package is properly installed
- Assume current working directory
- Use try/except for imports - let ImportError propagate

## Examples

### ✅ Correct

```python
from vibe_code_bench.core.paths import get_runs_dir, get_absolute_path
from vibe_code_bench.core.run_directory import setup_run_directory

# Create run directory
run_dir = setup_run_directory(subdir="website_generator")

# Save file in run directory
output_file = run_dir / "website" / "index.html"

# Resolve config path
config_path = get_absolute_path("config.json")
```

### ❌ Incorrect

```python
# DON'T: Relative paths
run_dir = Path("runs/website_generator")
output_file = Path("../output/index.html")

# DON'T: Using __file__
config_path = Path(__file__).parent / "config.json"

# DON'T: Assuming current directory
output_file = Path("output.json")
```

## Benefits

1. **Works from any directory**: Code can be run from any location
2. **Consistent structure**: All output is organized in one place
3. **Easy to find files**: Everything is in `data/` at repo root
4. **No path confusion**: Absolute paths eliminate relative path issues
5. **Git-friendly**: `data/` is in `.gitignore`, so output doesn't clutter the repo

## Migration Notes

If you encounter old code using relative paths:

1. Identify what type of file it is (report, log, etc.)
2. Use the appropriate standard directory function
3. Replace relative paths with absolute paths using `get_absolute_path()`
4. Remove any `sys.path.insert()` statements
5. Remove any `Path(__file__).parent` usage for file operations

