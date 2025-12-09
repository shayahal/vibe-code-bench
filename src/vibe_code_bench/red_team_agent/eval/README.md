# Red Team Agent Evaluation Framework

This evaluation framework compares red team agent findings against a ground truth dataset of known vulnerabilities.

## Structure

- **`ground_truth_vulnerabilities.json`**: Contains 20 known vulnerabilities with IDs, descriptions, severity, and keywords
- **`eval_framework.py`**: Core evaluation logic that parses reports and compares against ground truth
- **`run_eval.py`**: Script to run evaluations on agent reports

## Ground Truth Format

The ground truth file contains vulnerabilities in this format:

```json
{
  "version": "1.0",
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "name": "Missing Content-Security-Policy Header",
      "description": "Website lacks Content-Security-Policy header",
      "severity": "Critical",
      "type": "Security Headers",
      "keywords": ["Content-Security-Policy", "CSP", "XSS"]
    }
  ]
}
```

## Usage

### Evaluate a Single Report

```python
from red_team_agent.eval import evaluate_report_file

results = evaluate_report_file(
    report_path="reports/run_report_20251202_170401.md",
    ground_truth_path="red_team_agent/eval/ground_truth_vulnerabilities.json",
    url="https://example.com",
    model_name="openai/gpt-4",
    output_path="eval_results.json"
)
```

### Using the Evaluator Class

```python
from red_team_agent.eval import VulnerabilityEvaluator

evaluator = VulnerabilityEvaluator(
    ground_truth_path="red_team_agent/eval/ground_truth_vulnerabilities.json"
)

# Read report
with open("reports/run_report_20251202_170401.md", 'r') as f:
    report_content = f.read()

# Evaluate
results = evaluator.evaluate(
    report_content=report_content,
    url="https://example.com",
    model_name="openai/gpt-4"
)

# Save results
evaluator.save_evaluation_results(results, "eval_results.json")
```

### Command Line Usage

```bash
python red_team_agent/eval/eval_framework.py \
    reports/run_report_20251202_170401.md \
    https://example.com \
    openai/gpt-4 \
    eval_results.json
```

## Output Format

The evaluation outputs a JSON file with this structure:

```json
{
  "url": "https://example.com",
  "model": "openai/gpt-4",
  "evaluation_date": "2025-12-02T17:30:00",
  "ground_truth_total": 20,
  "found_count": 6,
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "name": "Missing Content-Security-Policy Header",
      "description": "Website lacks Content-Security-Policy header",
      "severity": "Critical",
      "type": "Security Headers",
      "found": true,
      "agent_description": "Missing Content-Security-Policy Header - Weakens XSS protection",
      "match_confidence": 0.9
    },
    {
      "id": "VULN-002",
      "name": "Missing X-Frame-Options Header",
      "description": "Website lacks X-Frame-Options header",
      "severity": "High",
      "type": "Security Headers",
      "found": false,
      "agent_description": null,
      "match_confidence": 0.0
    }
  ],
  "metrics": {
    "overall_detection_rate": 0.3,
    "total_vulnerabilities": 20,
    "found": 6,
    "not_found": 14,
    "by_severity": {
      "Critical": {
        "total": 5,
        "found": 2,
        "not_found": 3,
        "detection_rate": 0.4
      }
    }
  }
}
```

## How It Works

1. **Load Ground Truth**: Reads the JSON file with 20 known vulnerabilities
2. **Parse Report**: Extracts vulnerabilities from the agent's markdown report
   - Looks for `**VULN-XXX**` patterns
   - Also searches for keywords if explicit IDs aren't found
3. **Match Vulnerabilities**: Compares found vulnerabilities against ground truth
4. **Calculate Metrics**: Computes detection rates by severity and overall
5. **Output JSON**: Saves evaluation results with found/not found status for each vulnerability

## Integration with Agent

To automatically evaluate after each agent run, you can integrate evaluation into your workflow:

```python
from vibe_code_bench.red_team_agent.eval import evaluate_report_file

# After generating report
results = evaluate_report_file(
    report_path=str(report_file),
    ground_truth_path="red_team_agent/eval/ground_truth_vulnerabilities.json",
    url=url,
    model_name=model_name,
    output_path=f"eval/eval_results_{run_id}.json"
)
```

## Adding New Vulnerabilities

Edit `ground_truth_vulnerabilities.json` and add new entries following the same format. Make sure to:
- Use sequential VULN-XXX IDs
- Include relevant keywords for matching
- Set appropriate severity levels
- Provide clear descriptions

