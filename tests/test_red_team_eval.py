"""
Tests for Red Team Agent Evaluation Framework.
"""

import pytest
import json
import tempfile
from pathlib import Path
from red_team_agent.eval.eval_framework import VulnerabilityEvaluator, evaluate_report_file


@pytest.fixture
def sample_ground_truth():
    """Create a sample ground truth file."""
    ground_truth = {
        "version": "1.0",
        "description": "Test ground truth",
        "vulnerabilities": [
            {
                "id": "VULN-001",
                "name": "Missing Content-Security-Policy Header",
                "description": "Website lacks CSP header",
                "severity": "Critical",
                "type": "Security Headers",
                "keywords": ["Content-Security-Policy", "CSP", "XSS"]
            },
            {
                "id": "VULN-002",
                "name": "Missing X-Frame-Options Header",
                "description": "Website lacks X-Frame-Options",
                "severity": "High",
                "type": "Security Headers",
                "keywords": ["X-Frame-Options", "clickjacking"]
            },
            {
                "id": "VULN-003",
                "name": "Reflected XSS Vulnerability",
                "description": "XSS vulnerability detected",
                "severity": "Critical",
                "type": "XSS",
                "keywords": ["XSS", "Cross-Site Scripting"]
            }
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(ground_truth, f)
        temp_path = f.name
    
    yield temp_path
    
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def sample_report_with_vulns():
    """Sample report with vulnerabilities found."""
    return """# Security Assessment Report

**Target:** https://example.com

## Vulnerabilities

- **VULN-001**: Missing Content-Security-Policy Header - Weakens XSS protection. **Fix:** Implement CSP header
- **VULN-002**: Missing X-Frame-Options Header - Susceptible to clickjacking. **Fix:** Add X-Frame-Options header

## Summary
Found 2 vulnerabilities.
"""


@pytest.fixture
def sample_report_no_vulns():
    """Sample report with no vulnerabilities."""
    return """# Security Assessment Report

**Target:** https://example.com

## Summary
No vulnerabilities detected.
"""


class TestVulnerabilityEvaluator:
    """Tests for VulnerabilityEvaluator class."""
    
    def test_init(self, sample_ground_truth):
        """Test evaluator initialization."""
        evaluator = VulnerabilityEvaluator(sample_ground_truth)
        assert evaluator.ground_truth_path == Path(sample_ground_truth)
        assert len(evaluator.ground_truth['vulnerabilities']) == 3
        assert len(evaluator.vuln_index) == 3
    
    def test_extract_vulnerabilities_with_ids(self, sample_ground_truth, sample_report_with_vulns):
        """Test extracting vulnerabilities with VULN-XXX IDs."""
        evaluator = VulnerabilityEvaluator(sample_ground_truth)
        found = evaluator.extract_vulnerabilities_from_report(sample_report_with_vulns)
        
        assert len(found) >= 2
        ids = [v['id'] for v in found]
        assert 'VULN-001' in ids
        assert 'VULN-002' in ids
    
    def test_extract_vulnerabilities_no_ids(self, sample_ground_truth):
        """Test extracting vulnerabilities by keywords when IDs not present."""
        report = """# Security Report
        
        Found missing Content-Security-Policy header. This weakens XSS protection.
        Also missing X-Frame-Options which makes the site vulnerable to clickjacking.
        """
        
        evaluator = VulnerabilityEvaluator(sample_ground_truth)
        found = evaluator.extract_vulnerabilities_from_report(report)
        
        # Should find vulnerabilities by keywords
        assert len(found) > 0
    
    def test_evaluate_with_findings(self, sample_ground_truth, sample_report_with_vulns):
        """Test evaluation with vulnerabilities found."""
        evaluator = VulnerabilityEvaluator(sample_ground_truth)
        results = evaluator.evaluate(
            report_content=sample_report_with_vulns,
            url="https://example.com",
            model_name="test-model"
        )
        
        assert results['url'] == "https://example.com"
        assert results['model'] == "test-model"
        assert results['ground_truth_total'] == 3
        assert len(results['vulnerabilities']) == 3
        
        # Check found vulnerabilities
        vuln_001 = next(v for v in results['vulnerabilities'] if v['id'] == 'VULN-001')
        assert vuln_001['found'] is True
        
        vuln_002 = next(v for v in results['vulnerabilities'] if v['id'] == 'VULN-002')
        assert vuln_002['found'] is True
        
        # Check metrics
        assert results['metrics']['found'] >= 2
        assert results['metrics']['overall_detection_rate'] > 0
    
    def test_evaluate_no_findings(self, sample_ground_truth, sample_report_no_vulns):
        """Test evaluation with no vulnerabilities found."""
        evaluator = VulnerabilityEvaluator(sample_ground_truth)
        results = evaluator.evaluate(
            report_content=sample_report_no_vulns,
            url="https://example.com",
            model_name="test-model"
        )
        
        assert results['found_count'] == 0
        assert results['metrics']['found'] == 0
        assert results['metrics']['overall_detection_rate'] == 0.0
    
    def test_save_evaluation_results(self, sample_ground_truth, sample_report_with_vulns, tmp_path):
        """Test saving evaluation results."""
        evaluator = VulnerabilityEvaluator(sample_ground_truth)
        results = evaluator.evaluate(
            report_content=sample_report_with_vulns,
            url="https://example.com",
            model_name="test-model"
        )
        
        output_path = tmp_path / "test_results.json"
        evaluator.save_evaluation_results(results, str(output_path))
        
        assert output_path.exists()
        
        # Verify JSON is valid
        with open(output_path, 'r') as f:
            saved_results = json.load(f)
        
        assert saved_results['url'] == "https://example.com"
        assert len(saved_results['vulnerabilities']) == 3


class TestEvaluateReportFile:
    """Tests for evaluate_report_file function."""
    
    def test_evaluate_report_file(self, sample_ground_truth, sample_report_with_vulns, tmp_path):
        """Test evaluate_report_file function."""
        report_file = tmp_path / "test_report.md"
        report_file.write_text(sample_report_with_vulns)
        
        output_file = tmp_path / "eval_results.json"
        
        results = evaluate_report_file(
            report_path=str(report_file),
            ground_truth_path=sample_ground_truth,
            url="https://example.com",
            model_name="test-model",
            output_path=str(output_file)
        )
        
        assert results['url'] == "https://example.com"
        assert output_file.exists()
        
        # Verify saved file
        with open(output_file, 'r') as f:
            saved = json.load(f)
        assert saved['url'] == "https://example.com"

