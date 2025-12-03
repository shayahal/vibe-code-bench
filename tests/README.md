# Tests for Vibe Code Bench

Comprehensive test suite for evaluation frameworks and orchestrator.

## Test Structure

```
tests/
├── __init__.py
├── conftest.py                    # Shared fixtures
├── test_red_team_eval.py          # Red team agent evaluation tests
├── test_website_builder_eval.py   # Website builder evaluation tests
└── test_orchestrator.py           # Orchestrator tests
```

## Running Tests

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test File

```bash
pytest tests/test_red_team_eval.py -v
pytest tests/test_website_builder_eval.py -v
pytest tests/test_orchestrator.py -v
```

### Run with Coverage

```bash
pytest tests/ --cov=red_team_agent.eval --cov=website_generator.eval --cov=orchestrator --cov-report=html
```

### Run Specific Test

```bash
pytest tests/test_red_team_eval.py::TestVulnerabilityEvaluator::test_evaluate_with_findings -v
```

## Test Coverage

### Red Team Evaluation Framework (`test_red_team_eval.py`)

- ✅ VulnerabilityEvaluator initialization
- ✅ Extracting vulnerabilities from reports (with IDs and keywords)
- ✅ Evaluating reports against ground truth
- ✅ Calculating metrics
- ✅ Saving evaluation results
- ✅ evaluate_report_file function

### Website Builder Evaluation Framework (`test_website_builder_eval.py`)

- ✅ WebsiteBuilderInspector initialization
- ✅ Code pattern analysis using inspect
- ✅ WebsiteSecurityAnalyzer file scanning
- ✅ Security vulnerability detection
- ✅ Matching against ground truth
- ✅ WebsiteBuilderEvaluator complete evaluation
- ✅ Metrics calculation
- ✅ evaluate_website_builder function

### Orchestrator (`test_orchestrator.py`)

- ✅ WebsiteServer initialization and lifecycle
- ✅ Server start/stop functionality
- ✅ Orchestrator initialization
- ✅ Website building
- ✅ Red team agent execution
- ✅ Findings evaluation
- ✅ Full evaluation pipeline
- ✅ Error handling

## Test Fixtures

### Shared Fixtures (conftest.py)

- Project root path setup

### Red Team Eval Fixtures

- `sample_ground_truth`: Sample ground truth JSON file
- `sample_report_with_vulns`: Report with vulnerabilities
- `sample_report_no_vulns`: Report without vulnerabilities

### Website Builder Eval Fixtures

- `sample_ground_truth`: Sample ground truth JSON file
- `sample_website_dir`: Sample website directory with HTML/JS/CSS files

### Orchestrator Fixtures

- `sample_ground_truth`: Sample ground truth JSON file
- `sample_website_dir`: Sample website directory with Flask app

## Mocking

Tests use extensive mocking for:
- External API calls (LLM, LangFuse)
- File system operations
- HTTP requests
- Subprocess execution
- Module imports

## Notes

- All tests use temporary files/directories that are cleaned up automatically
- Tests are isolated and don't require actual API keys
- Mock objects are used to avoid external dependencies
- Tests verify both success and failure paths

