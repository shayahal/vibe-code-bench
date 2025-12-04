# Orchestrator: Website Builder + Red Team Agent Evaluation

Automated pipeline that builds websites, tests them with the red team agent, and evaluates security findings.

## Overview

The orchestrator automates the complete evaluation workflow:

1. **Build Website**: Uses website builder agent to create a website
2. **Start Server**: Launches Flask server to serve the website locally
3. **Run Red Team Agent**: Tests the website for vulnerabilities
4. **Put Website to Sleep**: Stops the website server after testing
5. **Evaluate Findings**: Compares findings against ground truth (20 vulnerabilities)
6. **Generate Report**: Outputs JSON with all vulnerabilities and found status

## Usage

### Basic Usage

After installing the package (`pip install -e .`), you can run:

```bash
orchestrator
```

Or using Python module:

```bash
python -m vibe_code_bench.orchestrator.main
```

This will:
- Build a pizzeria website
- Start server on port 5000
- Run red team agent
- Output evaluation JSON

### Advanced Usage

```bash
orchestrator \
    --ground-truth src/vibe_code_bench/red_team_agent/eval/ground_truth_vulnerabilities.json \
    --output-dir runs/orchestrator \
    --website-model "anthropic/claude-3-haiku" \
    --red-team-model "openai/gpt-4" \
    --prompt "build a website for my restaurant" \
    --port 5000
```

### Arguments

- `--ground-truth`: Path to ground truth vulnerabilities JSON (default: `src/vibe_code_bench/red_team_agent/eval/ground_truth_vulnerabilities.json`)
- `--output-dir`: Directory for output files (default: `runs/orchestrator`)
- `--website-model`: Model for website builder (default: `anthropic/claude-3-haiku`)
- `--red-team-model`: Model for red team agent (default: `anthropic/claude-3-haiku`)
- `--prompt`: Custom website prompt (default: pizzeria website)
- `--port`: Port for website server (default: 5000)

## Output Structure

Each run creates a directory:

```
runs/orchestrator/
  run_20251203_133000/
    website/                    # Generated website files
      index.html
      styles.css
      script.js
      main.py
      ...
    red_team_reports/          # Red team agent reports
      run_report_20251203_133000_redteam.md
    evaluation_results.json    # Evaluation against ground truth
    final_report.json          # Complete evaluation report
```

## Output Format

The `final_report.json` contains:

```json
{
  "run_id": "20251203_133000",
  "timestamp": "2025-12-03T13:30:00",
  "url": "http://localhost:5000",
  "website_builder_model": "anthropic/claude-3-haiku",
  "red_team_model": "anthropic/claude-3-haiku",
  "build_result": {
    "status": "success",
    "files_created": 9,
    "output_directory": "runs/orchestrator/run_20251203_133000/website"
  },
  "red_team_result": {
    "execution_time": 45.23,
    "report_file": "runs/orchestrator/run_20251203_133000/red_team_reports/..."
  },
  "evaluation": {
    "url": "http://localhost:5000",
    "model": "anthropic/claude-3-haiku",
    "ground_truth_total": 20,
    "found_count": 9,
    "vulnerabilities": [
      {
        "id": "VULN-001",
        "name": "Missing Content-Security-Policy Header",
        "found": true,
        "severity": "Critical"
      },
      {
        "id": "VULN-002",
        "name": "Missing X-Frame-Options Header",
        "found": false,
        "severity": "High"
      }
      // ... all 20 vulnerabilities
    ],
    "metrics": {
      "overall_detection_rate": 0.45,
      "found": 9,
      "not_found": 11,
      "by_severity": {
        "Critical": {
          "total": 5,
          "found": 2,
          "detection_rate": 0.4
        }
      }
    }
  }
}
```

## Key Features

- **Automated Pipeline**: Runs all steps automatically
- **Server Management**: Automatically starts/stops Flask server
- **Ground Truth Comparison**: Compares against 20 known vulnerabilities
- **Complete Reports**: JSON output with all vulnerability statuses
- **Error Handling**: Gracefully handles failures and cleans up

## Requirements

- Flask (for serving websites)
- All dependencies from `requirements.txt`
- Environment variables:
  - `OPENROUTER_API_KEY` (or `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`)
  - `LANGFUSE_SECRET_KEY`
  - `LANGFUSE_PUBLIC_KEY`

## Example Output

```
======================================================================
ORCHESTRATOR: Full Evaluation Pipeline
======================================================================

============================================================
STEP 1: Building Website
============================================================
✓ Website built successfully
  Output directory: runs/orchestrator/run_20251203_133000/website
  Files created: 9

============================================================
STEP 2: Starting Website Server
============================================================
✓ Website server started on http://localhost:5000

============================================================
STEP 3: Running Red Team Agent
============================================================
✓ Using model: anthropic/claude-3-haiku
✓ Loaded 6 security testing tools
✓ Red team assessment completed
  Execution time: 45.23s
  Report saved: runs/orchestrator/run_20251203_133000/red_team_reports/...

============================================================
STEP 4: Putting Website to Sleep
============================================================
✓ Website server stopped (put to sleep)

============================================================
STEP 5: Evaluating Findings
============================================================
✓ Evaluation completed
  Overall detection rate: 45.00%
  Found: 9/20
  Results saved: runs/orchestrator/run_20251203_133000/evaluation_results.json

======================================================================
EVALUATION COMPLETE
======================================================================
Run ID: 20251203_133000
URL: fhttp://localhost:5000

Vulnerabilities Found: 9/20
Detection Rate: 45.00%

Final Report: runs/orchestrator/run_20251203_133000/final_report.json

✓ Orchestration completed successfully!
```

## Integration

You can also use the orchestrator programmatically:

```python
from vibe_code_bench.orchestrator import Orchestrator
from pathlib import Path

orchestrator = Orchestrator(
    website_builder_ground_truth_path="src/vibe_code_bench/red_team_agent/eval/ground_truth_vulnerabilities.json",
    red_team_ground_truth_path="src/vibe_code_bench/red_team_agent/eval/ground_truth_vulnerabilities.json",
    output_dir=Path("runs/orchestrator"),
    website_builder_model="anthropic/claude-3-haiku",
    red_team_model="openai/gpt-4"
)

results = orchestrator.run_full_evaluation(
    prompt="build a website for my restaurant",
    port=5000
)

# Access results
print(f"Found {results['evaluation']['metrics']['found']}/20 vulnerabilities")
```

## Notes

- The orchestrator automatically manages the Flask server lifecycle
- If port 5000 is in use, you can specify a different port with `--port`
- The website server runs in a subprocess and is automatically stopped after evaluation
- All outputs are saved in timestamped directories for easy tracking

