"""
Tests for Website Builder Evaluation Framework (Inspect-based).
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from website_generator.eval.inspect_eval_framework import (
    WebsiteBuilderInspector,
    WebsiteSecurityAnalyzer,
    WebsiteBuilderEvaluator,
    evaluate_website_builder
)


@pytest.fixture
def sample_ground_truth():
    """Create a sample ground truth file."""
    ground_truth = {
        "version": "1.0",
        "vulnerabilities": [
            {
                "id": "VULN-001",
                "name": "Missing Content-Security-Policy Header",
                "description": "Website lacks CSP header",
                "severity": "Critical",
                "type": "Security Headers",
                "keywords": ["Content-Security-Policy", "CSP"]
            },
            {
                "id": "VULN-002",
                "name": "Reflected XSS Vulnerability",
                "description": "XSS vulnerability",
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
def sample_website_dir(tmp_path):
    """Create a sample website directory with files."""
    website_dir = tmp_path / "website"
    website_dir.mkdir()
    
    # Create HTML file without security headers
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Test Website</title>
</head>
<body>
    <h1>Hello World</h1>
    <script>document.getElementById('test').innerHTML = userInput;</script>
</body>
</html>
"""
    (website_dir / "index.html").write_text(html_content)
    
    # Create JS file with dangerous patterns
    js_content = """function processInput(input) {
    eval(input);
    document.getElementById('content').innerHTML = input;
}
"""
    (website_dir / "script.js").write_text(js_content)
    
    # Create CSS file
    css_content = """body { margin: 0; padding: 0; }"""
    (website_dir / "styles.css").write_text(css_content)
    
    return website_dir


class TestWebsiteBuilderInspector:
    """Tests for WebsiteBuilderInspector."""
    
    @patch('importlib.import_module')
    def test_init_with_module(self, mock_import_module, sample_ground_truth):
        """Test inspector initialization with module."""
        mock_module = Mock()
        mock_module.__file__ = "/path/to/agent.py"
        mock_import_module.return_value = mock_module
        
        inspector = WebsiteBuilderInspector("website_generator.agent")
        
        assert inspector.builder_module_path == "website_generator.agent"
        mock_import_module.assert_called_once_with("website_generator.agent")
    
    def test_find_module_file(self):
        """Test finding module file."""
        inspector = WebsiteBuilderInspector("website_generator.agent")
        # Should find the file if it exists
        assert inspector.module_file_path is None or Path(inspector.module_file_path).exists()
    
    def test_analyze_code_patterns(self):
        """Test code pattern analysis."""
        source_code = """
def create_website():
    # Has sanitization
    sanitized = html.escape(user_input)
    
    # Has validation
    if not is_valid(input):
        return
    
    # Uses dangerous pattern
    element.innerHTML = content
    eval(code)
"""
        
        inspector = WebsiteBuilderInspector("website_generator.agent")
        patterns = inspector._analyze_code_patterns(source_code)
        
        assert patterns['has_sanitization'] is True
        assert patterns['has_validation'] is True
        assert patterns['uses_innerhtml'] is True
        assert patterns['uses_eval'] is True
        assert len(patterns['uses_dangerous_patterns']) > 0
    
    def test_get_builder_analysis(self):
        """Test getting builder analysis."""
        inspector = WebsiteBuilderInspector("website_generator.agent")
        analysis = inspector.get_builder_analysis()
        
        assert 'module' in analysis
        assert 'analysis' in analysis
        assert 'code_patterns' in analysis['analysis']


class TestWebsiteSecurityAnalyzer:
    """Tests for WebsiteSecurityAnalyzer."""
    
    def test_init(self, sample_ground_truth, sample_website_dir):
        """Test analyzer initialization."""
        analyzer = WebsiteSecurityAnalyzer(sample_website_dir, sample_ground_truth)
        
        assert analyzer.website_dir == sample_website_dir
        assert len(analyzer.ground_truth['vulnerabilities']) == 2
        assert len(analyzer.website_files) > 0
    
    def test_scan_website_files(self, sample_ground_truth, sample_website_dir):
        """Test scanning website files."""
        analyzer = WebsiteSecurityAnalyzer(sample_website_dir, sample_ground_truth)
        
        assert 'index.html' in analyzer.website_files
        assert 'script.js' in analyzer.website_files
        assert 'styles.css' in analyzer.website_files
    
    def test_analyze_security(self, sample_ground_truth, sample_website_dir):
        """Test security analysis."""
        analyzer = WebsiteSecurityAnalyzer(sample_website_dir, sample_ground_truth)
        findings = analyzer.analyze_security()
        
        assert 'files_analyzed' in findings
        assert 'vulnerabilities_found' in findings
        assert findings['files_analyzed'] > 0
        
        # Should find XSS vulnerabilities
        xss_findings = [f for f in findings['vulnerabilities_found'] if f['type'] == 'XSS']
        assert len(xss_findings) > 0
    
    def test_has_xss_vulnerability(self, sample_ground_truth, sample_website_dir):
        """Test XSS vulnerability detection."""
        analyzer = WebsiteSecurityAnalyzer(sample_website_dir, sample_ground_truth)
        
        # Test with innerHTML
        content_with_innerhtml = "<div id='test'></div><script>element.innerHTML = userInput;</script>"
        assert analyzer._has_xss_vulnerability(content_with_innerhtml, "test.html") is True
        
        # Test with eval
        content_with_eval = "function test() { eval(userInput); }"
        assert analyzer._has_xss_vulnerability(content_with_eval, "test.js") is True
        
        # Test safe content
        safe_content = "<div>Hello World</div>"
        assert analyzer._has_xss_vulnerability(safe_content, "test.html") is False
    
    def test_match_against_ground_truth(self, sample_ground_truth, sample_website_dir):
        """Test matching against ground truth."""
        analyzer = WebsiteSecurityAnalyzer(sample_website_dir, sample_ground_truth)
        
        findings = [
            {'type': 'Security Headers', 'description': 'Missing Content-Security-Policy header'},
            {'type': 'XSS', 'description': 'XSS vulnerability detected'}
        ]
        
        matched = analyzer._match_against_ground_truth(findings)
        
        assert len(matched) == 2
        assert any(m['id'] == 'VULN-001' for m in matched)
        assert any(m['id'] == 'VULN-002' for m in matched)


class TestWebsiteBuilderEvaluator:
    """Tests for WebsiteBuilderEvaluator."""
    
    def test_evaluate(self, sample_ground_truth, sample_website_dir):
        """Test complete evaluation."""
        evaluator = WebsiteBuilderEvaluator(
            builder_module_path="website_generator.agent",
            website_dir=sample_website_dir,
            ground_truth_path=sample_ground_truth
        )
        
        results = evaluator.evaluate(builder_name="TestBuilder")
        
        assert results['builder_name'] == "TestBuilder"
        assert 'vulnerabilities' in results
        assert 'metrics' in results
        assert len(results['vulnerabilities']) > 0
    
    def test_calculate_metrics(self, sample_ground_truth, sample_website_dir):
        """Test metrics calculation."""
        evaluator = WebsiteBuilderEvaluator(
            builder_module_path="test.module",
            website_dir=sample_website_dir,
            ground_truth_path=sample_ground_truth
        )
        
        vulnerabilities = [
            {'id': 'VULN-001', 'found': True, 'severity': 'Critical'},
            {'id': 'VULN-002', 'found': False, 'severity': 'High'}
        ]
        
        metrics = evaluator._calculate_metrics(vulnerabilities)
        
        assert metrics['vulnerabilities_found'] == 1
        assert metrics['vulnerabilities_total'] == 2
        assert 'by_severity' in metrics
    
    def test_save_results(self, sample_ground_truth, sample_website_dir, tmp_path):
        """Test saving results."""
        evaluator = WebsiteBuilderEvaluator(
            builder_module_path="test.module",
            website_dir=sample_website_dir,
            ground_truth_path=sample_ground_truth
        )
        
        results = {
            'builder_name': 'Test',
            'vulnerabilities': [],
            'metrics': {}
        }
        
        output_path = tmp_path / "test_results.json"
        evaluator.save_results(results, str(output_path))
        
        assert output_path.exists()
        
        with open(output_path, 'r') as f:
            saved = json.load(f)
        assert saved['builder_name'] == 'Test'


class TestEvaluateWebsiteBuilder:
    """Tests for evaluate_website_builder function."""
    
    def test_evaluate_website_builder(self, sample_ground_truth, sample_website_dir, tmp_path):
        """Test evaluate_website_builder function."""
        output_path = tmp_path / "results.json"
        
        results = evaluate_website_builder(
            builder_module_path="website_generator.agent",
            website_dir=sample_website_dir,
            ground_truth_path=sample_ground_truth,
            builder_name="TestBuilder",
            output_path=str(output_path)
        )
        
        assert results['builder_name'] == 'TestBuilder'
        assert output_path.exists()
        assert 'vulnerabilities' in results

