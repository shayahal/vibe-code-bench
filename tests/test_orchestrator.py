"""
Tests for Orchestrator.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
import requests
from orchestrator import Orchestrator, WebsiteServer


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
    """Create a sample website directory."""
    website_dir = tmp_path / "website"
    website_dir.mkdir()
    
    # Create main.py Flask app
    main_py = """from flask import Flask, send_file
app = Flask(__name__)

@app.route('/')
def index():
    return send_file('index.html')

if __name__ == '__main__':
    app.run(port=5000)
"""
    (website_dir / "main.py").write_text(main_py)
    
    # Create index.html
    (website_dir / "index.html").write_text("<html><body>Test</body></html>")
    
    return website_dir


class TestWebsiteServer:
    """Tests for WebsiteServer class."""
    
    def test_init(self, sample_website_dir):
        """Test server initialization."""
        server = WebsiteServer(sample_website_dir, port=5000)
        
        assert server.website_dir == sample_website_dir
        assert server.port == 5000
        assert server.url == "http://localhost:5000"
        assert server.process is None
    
    @patch('orchestrator.subprocess.Popen')
    @patch('orchestrator.requests.get')
    def test_start_success(self, mock_get, mock_popen, sample_website_dir):
        """Test successful server start."""
        mock_process = Mock()
        mock_popen.return_value = mock_process
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        server = WebsiteServer(sample_website_dir, port=5000)
        result = server.start(timeout=5)
        
        assert result is True
        assert server.process == mock_process
        mock_popen.assert_called_once()
    
    @patch('orchestrator.subprocess.Popen')
    @patch('orchestrator.requests.get')
    def test_start_timeout(self, mock_get, mock_popen, sample_website_dir):
        """Test server start timeout."""
        mock_process = Mock()
        mock_popen.return_value = mock_process
        
        # Simulate timeout by raising exception
        mock_get.side_effect = requests.exceptions.RequestException()
        
        server = WebsiteServer(sample_website_dir, port=5000)
        result = server.start(timeout=2)
        
        assert result is False
    
    def test_start_no_main_py(self, tmp_path):
        """Test start when main.py doesn't exist."""
        server = WebsiteServer(tmp_path, port=5000)
        result = server.start()
        
        assert result is False
    
    @patch('orchestrator.requests.get')
    def test_is_running(self, mock_get, sample_website_dir):
        """Test is_running check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        server = WebsiteServer(sample_website_dir, port=5000)
        assert server.is_running() is True
    
    @patch('orchestrator.requests.get')
    def test_is_running_false(self, mock_get, sample_website_dir):
        """Test is_running when server is down."""
        mock_get.side_effect = requests.exceptions.RequestException()
        
        server = WebsiteServer(sample_website_dir, port=5000)
        assert server.is_running() is False
    
    def test_stop(self, sample_website_dir):
        """Test server stop."""
        server = WebsiteServer(sample_website_dir, port=5000)
        server.process = Mock()
        server.process.wait.return_value = None
        
        server.stop()
        
        server.process.terminate.assert_called_once()
        server.process.wait.assert_called_once()


class TestOrchestrator:
    """Tests for Orchestrator class."""
    
    @patch('orchestrator.VulnerabilityEvaluator')
    def test_init(self, mock_evaluator_class, sample_ground_truth, tmp_path):
        """Test orchestrator initialization."""
        mock_evaluator = Mock()
        mock_evaluator_class.return_value = mock_evaluator
        
        orchestrator = Orchestrator(
            ground_truth_path=sample_ground_truth,
            output_dir=tmp_path,
            website_builder_model="test-model-1",
            red_team_model="test-model-2"
        )
        
        assert orchestrator.ground_truth_path == Path(sample_ground_truth)
        assert orchestrator.output_dir == tmp_path
        assert orchestrator.website_builder_model == "test-model-1"
        assert orchestrator.red_team_model == "test-model-2"
        assert orchestrator.evaluator == mock_evaluator
    
    @patch('orchestrator.SimpleWebsiteCreatorAgent')
    def test_build_website(self, mock_agent_class, sample_ground_truth, tmp_path):
        """Test website building."""
        mock_agent = Mock()
        mock_agent.create_website.return_value = {
            'status': 'success',
            'output_directory': str(tmp_path / "website"),
            'total_files': 5
        }
        mock_agent_class.return_value = mock_agent
        
        orchestrator = Orchestrator(
            ground_truth_path=sample_ground_truth,
            output_dir=tmp_path
        )
        
        result = orchestrator.build_website(prompt="test prompt")
        
        assert 'run_id' in result
        assert 'website_dir' in result
        assert result['result']['status'] == 'success'
        mock_agent.create_website.assert_called_once()
    
    @patch('orchestrator.SimpleWebsiteCreatorAgent')
    def test_build_website_error(self, mock_agent_class, sample_ground_truth, tmp_path):
        """Test website building with error."""
        mock_agent = Mock()
        mock_agent.create_website.return_value = {
            'status': 'error',
            'error': 'Build failed'
        }
        mock_agent_class.return_value = mock_agent
        
        orchestrator = Orchestrator(
            ground_truth_path=sample_ground_truth,
            output_dir=tmp_path
        )
        
        with pytest.raises(Exception, match="Website build failed"):
            orchestrator.build_website()
    
    @patch('orchestrator.initialize_langfuse')
    @patch('orchestrator.initialize_llm')
    @patch('orchestrator.create_and_run_agent')
    @patch('orchestrator.generate_run_report')
    @patch('orchestrator.save_report')
    @patch('orchestrator.get_all_tools')
    def test_run_red_team_agent(self, mock_get_tools, mock_save_report,
                                mock_generate_report, mock_run_agent,
                                mock_init_llm, mock_init_langfuse,
                                sample_ground_truth, tmp_path):
        """Test running red team agent."""
        # Setup mocks
        mock_langfuse_client = Mock()
        mock_langfuse_handler = Mock()
        mock_init_langfuse.return_value = (mock_langfuse_client, mock_langfuse_handler)
        
        mock_llm = Mock()
        mock_init_llm.return_value = mock_llm
        
        mock_get_tools.return_value = [Mock(), Mock()]
        
        mock_run_agent.return_value = ("output", 10.5, "trace-123")
        mock_generate_report.return_value = "# Report\nTest report"
        mock_save_report.return_value = tmp_path / "report.md"
        
        orchestrator = Orchestrator(
            ground_truth_path=sample_ground_truth,
            output_dir=tmp_path
        )
        
        result = orchestrator.run_red_team_agent("http://localhost:5000", "test-run")
        
        assert result['output'] == "output"
        assert result['execution_time'] == 10.5
        assert result['trace_id'] == "trace-123"
        mock_run_agent.assert_called_once()
    
    @patch('orchestrator.VulnerabilityEvaluator')
    def test_evaluate_findings(self, mock_evaluator_class, sample_ground_truth, tmp_path):
        """Test evaluating findings."""
        mock_evaluator = Mock()
        mock_evaluator.evaluate.return_value = {
            'url': 'http://localhost:5000',
            'model': 'test-model',
            'vulnerabilities': [],
            'metrics': {'found': 5, 'total_vulnerabilities': 20}
        }
        mock_evaluator.save_evaluation_results.return_value = None
        mock_evaluator_class.return_value = mock_evaluator
        
        orchestrator = Orchestrator(
            ground_truth_path=sample_ground_truth,
            output_dir=tmp_path
        )
        orchestrator.evaluator = mock_evaluator
        
        results = orchestrator.evaluate_findings(
            report_content="# Report\nTest",
            url="http://localhost:5000",
            run_id="test-run"
        )
        
        assert results['metrics']['found'] == 5
        mock_evaluator.evaluate.assert_called_once()
        mock_evaluator.save_evaluation_results.assert_called_once()
    
    @patch('orchestrator.Orchestrator.build_website')
    @patch('orchestrator.WebsiteServer')
    @patch('orchestrator.Orchestrator.run_red_team_agent')
    @patch('orchestrator.Orchestrator.evaluate_findings')
    def test_run_full_evaluation(self, mock_evaluate, mock_red_team,
                                 mock_server_class, mock_build,
                                 sample_ground_truth, tmp_path):
        """Test full evaluation pipeline."""
        # Setup mocks
        mock_build.return_value = {
            'run_id': 'test-run',
            'run_dir': tmp_path / 'test-run',
            'website_dir': tmp_path / 'test-run' / 'website',
            'result': {'status': 'success', 'total_files': 5}
        }
        
        mock_server = Mock()
        mock_server.start.return_value = True
        mock_server.url = "http://localhost:5000"
        mock_server_class.return_value = mock_server
        
        mock_red_team.return_value = {
            'output': 'test output',
            'report': '# Report\nTest',
            'report_file': tmp_path / 'report.md',
            'execution_time': 10.5,
            'trace_id': 'trace-123'
        }
        
        mock_evaluate.return_value = {
            'vulnerabilities': [
                {'id': 'VULN-001', 'found': True}
            ],
            'metrics': {'found': 1, 'total_vulnerabilities': 20}
        }
        
        orchestrator = Orchestrator(
            ground_truth_path=sample_ground_truth,
            output_dir=tmp_path
        )
        
        results = orchestrator.run_full_evaluation(prompt="test", port=5000)
        
        assert results['run_id'] == 'test-run'
        assert results['url'] == "http://localhost:5000"
        assert 'evaluation' in results
        
        # Verify server was stopped
        mock_server.stop.assert_called_once()
    
    @patch('orchestrator.Orchestrator.build_website')
    @patch('orchestrator.WebsiteServer')
    def test_run_full_evaluation_server_failure(self, mock_server_class, mock_build,
                                                 sample_ground_truth, tmp_path):
        """Test full evaluation when server fails to start."""
        mock_build.return_value = {
            'run_id': 'test-run',
            'run_dir': tmp_path / 'test-run',
            'website_dir': tmp_path / 'test-run' / 'website',
            'result': {'status': 'success', 'total_files': 5}
        }
        
        mock_server = Mock()
        mock_server.start.return_value = False
        mock_server_class.return_value = mock_server
        
        orchestrator = Orchestrator(
            ground_truth_path=sample_ground_truth,
            output_dir=tmp_path
        )
        
        with pytest.raises(Exception, match="Failed to start website server"):
            orchestrator.run_full_evaluation(port=5000)
        
        mock_server.stop.assert_called_once()

