# Inspect-based Evaluation Framework for Website Builders

This evaluation framework uses Python's `inspect` module to analyze website builder agents and evaluate the security of websites they generate.

## Overview

The framework evaluates website builders by:
1. **Using `inspect`** to analyze the builder's code structure, methods, and patterns
2. **Analyzing generated websites** for security vulnerabilities
3. **Comparing against ground truth** to determine which vulnerabilities are present
4. **Outputting JSON** with found/not found status for all vulnerabilities

## Structure

```
website_generator/eval/
├── __init__.py                      # Package exports
├── inspect_eval_framework.py       # Core evaluation logic using inspect
├── run_eval.py                      # CLI script
└── README.md                        # This file
```

## How It Works

### 1. Builder Code Analysis (using `inspect`)

The `WebsiteBuilderInspector` class uses Python's `inspect` module to:
- **Introspect the builder class**: Get class name, methods, signatures
- **Analyze method signatures**: Use `inspect.signature()` to understand parameters
- **Extract docstrings**: Use `inspect.getdoc()` to check for security documentation
- **Get source code**: Use `inspect.getsource()` to analyze code patterns
- **Detect security patterns**: Look for sanitization, validation, security headers, etc.

### 2. Website Security Analysis

The `WebsiteSecurityAnalyzer` class:
- Scans generated website files (HTML, JS, CSS)
- Detects security vulnerabilities:
  - XSS vulnerabilities (innerHTML, eval, etc.)
  - Missing security headers
  - Dangerous code patterns
- Matches findings against ground truth

### 3. Evaluation

The `WebsiteBuilderEvaluator` combines both analyses:
- Analyzes builder code using `inspect`
- Analyzes generated website security
- Compares against ground truth vulnerabilities
- Outputs JSON with found/not found status

## Usage

### Command Line

```bash
python website_generator/eval/run_eval.py \
    website_generator.agent \
    runs/run_20251203_130725/website \
    ../red_team_agent/eval/ground_truth_vulnerabilities.json \
    --builder-name "SimpleWebsiteCreatorAgent" \
    --output eval_results.json
```

### Python API

```python
from website_generator.eval import evaluate_website_builder

results = evaluate_website_builder(
    builder_module_path="website_generator.agent",
    website_dir=Path("runs/run_20251203_130725/website"),
    ground_truth_path="red_team_agent/eval/ground_truth_vulnerabilities.json",
    builder_name="SimpleWebsiteCreatorAgent",
    output_path="eval_results.json"
)
```

## Output Format

The evaluation outputs a JSON file with this structure:

```json
{
  "builder_name": "SimpleWebsiteCreatorAgent",
  "evaluation_date": "2025-12-03T13:30:00",
  "builder_analysis": {
    "module": "website_generator.agent",
    "class": "SimpleWebsiteCreatorAgent",
    "analysis": {
      "methods": [...],
      "security_related_methods": [...],
      "code_patterns": {
        "has_sanitization": false,
        "has_validation": false,
        "has_security_headers": false,
        "uses_dangerous_patterns": []
      }
    }
  },
  "security_analysis": {
    "files_analyzed": 5,
    "vulnerabilities_found": [...]
  },
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "name": "Missing Content-Security-Policy Header",
      "found": true,  // ← Vulnerability found in website
      "severity": "Critical"
    },
    {
      "id": "VULN-002",
      "name": "Missing X-Frame-Options Header",
      "found": false,  // ← Not found (website is secure for this)
      "severity": "High"
    }
  ],
  "metrics": {
    "overall_security_score": 0.55,  // Lower is better (fewer vulns)
    "vulnerabilities_found": 9,
    "vulnerabilities_total": 20,
    "by_severity": {...}
  }
}
```

## Key Features

### Inspect-based Analysis

- **Method introspection**: Analyzes all methods in the builder class
- **Signature analysis**: Understands method parameters and return types
- **Source code analysis**: Examines actual code for security patterns
- **Pattern detection**: Identifies security-related code patterns

### Security Analysis

- **File scanning**: Analyzes all HTML, JS, CSS files
- **Vulnerability detection**: Identifies XSS, missing headers, dangerous patterns
- **Ground truth matching**: Compares against known vulnerabilities

### Evaluation Metrics

- **Overall security score**: Percentage indicating how secure the website is
- **Vulnerabilities found**: Count of vulnerabilities detected
- **By severity**: Breakdown by Critical/High/Medium/Low

## Integration Example

To automatically evaluate after website generation:

```python
from website_generator.eval import evaluate_website_builder
from pathlib import Path

# After generating website
result = agent.create_website(...)

# Evaluate the builder and generated website
eval_results = evaluate_website_builder(
    builder_module_path="website_generator.agent",
    website_dir=Path(result['output_directory']),
    ground_truth_path="red_team_agent/eval/ground_truth_vulnerabilities.json",
    builder_name="SimpleWebsiteCreatorAgent",
    output_path=f"eval/eval_{run_id}.json"
)
```

## What Inspect Analyzes

1. **Class Structure**: Builder class name and module
2. **Methods**: All methods with signatures and docstrings
3. **Security Methods**: Methods related to security (sanitization, validation, etc.)
4. **Code Patterns**: 
   - Has sanitization code?
   - Has validation code?
   - Has security headers?
   - Uses dangerous patterns (eval, innerHTML)?
5. **Imports**: What libraries/modules are imported

## Notes

- The framework uses `inspect` to analyze the builder's code without modifying it
- Security analysis is based on static code analysis of generated files
- Ground truth file should be the same one used for red team agent evaluation
- Lower security score = fewer vulnerabilities = more secure website

