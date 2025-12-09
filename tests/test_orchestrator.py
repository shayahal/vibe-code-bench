"""
Tests for Orchestrator.

Tests the CrewAI-based orchestrator workflow.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import requests
from vibe_code_bench.orchestrator.main import Orchestrator
from vibe_code_bench.core.server_manager import WebsiteServer


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
    
    @patch('vibe_code_bench.core.server_manager.subprocess.Popen')
    @patch('vibe_code_bench.core.server_manager.requests.get')
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
    
    @patch('vibe_code_bench.core.server_manager.subprocess.Popen')
    @patch('vibe_code_bench.core.server_manager.requests.get')
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
    
    @patch('vibe_code_bench.core.server_manager.requests.get')
    def test_is_running(self, mock_get, sample_website_dir):
        """Test is_running check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        server = WebsiteServer(sample_website_dir, port=5000)
        assert server.is_running() is True
    
    @patch('vibe_code_bench.core.server_manager.requests.get')
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
    
    def test_init(self, sample_ground_truth, tmp_path):
        """Test orchestrator initialization."""
        orchestrator = Orchestrator(
            website_builder_ground_truth_path=sample_ground_truth,
            red_team_ground_truth_path=sample_ground_truth,
            output_dir=tmp_path,
            website_builder_model="test-model-1",
            red_team_model="test-model-2"
        )
        
        assert orchestrator.website_builder_ground_truth_path == sample_ground_truth
        assert orchestrator.red_team_ground_truth_path == sample_ground_truth
        assert orchestrator.output_dir == tmp_path
        assert orchestrator.website_builder_model == "test-model-1"
        assert orchestrator.red_team_model == "test-model-2"
        assert orchestrator.crew is None  # Crew is created on demand
    
    @patch('vibe_code_bench.orchestrator.crew_setup.create_crew')
    def test_run_full_evaluation(
        self,
        mock_create_crew,
        sample_ground_truth,
        tmp_path
    ):
        """Test full evaluation pipeline with CrewAI."""
        # Setup
        run_dir = tmp_path / 'test-run'
        run_dir.mkdir()
        website_dir = run_dir / 'website'
        website_dir.mkdir()
        
        # Create final report that will be returned
        final_report = {
            'metadata': {
                'run_id': 'test-run',
                'url': 'http://localhost:5000'
            },
            'evaluation': {
                'summary': {
                    'total_vulnerabilities': 20,
                    'found_count': 1,
                    'overall_detection_rate': 0.05
                }
            }
        }
        
        # Mock CrewAI crew wrapper
        # We need to capture the context and update it in kickoff
        captured_context = None
        
        def create_crew_side_effect(context, enable_observability):
            nonlocal captured_context
            captured_context = context
            mock_crew = Mock()
            
            def kickoff():
                # Update context as executor would
                captured_context.build_result = {
                    'result': {'status': 'success', 'total_files': 5}
                }
                captured_context.website_dir = website_dir
                captured_context.static_analysis_result = {
                    'summary': {'total_vulnerabilities': 2}
                }
                captured_context.url = 'http://localhost:5000'
                captured_context.red_team_result = {
                    'output': 'test output',
                    'report': '# Report\nTest',
                    'execution_time': 10.5,
                    'trace_id': 'trace-123'
                }
                captured_context.final_report = final_report
                captured_context.run_json = run_dir / 'run.json'
                captured_context.report_md = run_dir / 'report.md'
                return {
                    'website_builder': 'Website built. Files: 5',
                    'static_analysis': 'Static analysis completed. Found 2 vulnerabilities.',
                    'server_start': 'Server started at http://localhost:5000',
                    'red_team': 'Red team assessment completed in 10.5s',
                    'server_stop': 'Server stopped successfully',
                    'final_report': 'Final report generated'
                }
            
            mock_crew.kickoff = kickoff
            return mock_crew
        
        mock_create_crew.side_effect = create_crew_side_effect
        
        orchestrator = Orchestrator(
            website_builder_ground_truth_path=sample_ground_truth,
            red_team_ground_truth_path=sample_ground_truth,
            output_dir=tmp_path
        )
        
        # Run evaluation
        results = orchestrator.run_full_evaluation(prompt="test", port=5000)
        
        # Verify results
        assert results is not None
        assert 'metadata' in results
        assert results['metadata']['url'] == 'http://localhost:5000'
        
        # Verify crew was created and executed
        mock_create_crew.assert_called_once()
        mock_crew.kickoff.assert_called_once()
    
    @patch('vibe_code_bench.orchestrator.crew_setup.create_crew')
    def test_run_full_evaluation_server_failure(
        self,
        mock_create_crew,
        sample_ground_truth,
        tmp_path
    ):
        """Test full evaluation when server fails to start."""
        # Mock CrewAI crew wrapper to raise exception
        def create_crew_side_effect(context, enable_observability):
            mock_crew = Mock()
            mock_crew.kickoff.side_effect = Exception("Failed to start website server")
            return mock_crew
        
        mock_create_crew.side_effect = create_crew_side_effect
        
        orchestrator = Orchestrator(
            website_builder_ground_truth_path=sample_ground_truth,
            red_team_ground_truth_path=sample_ground_truth,
            output_dir=tmp_path
        )
        
        with pytest.raises(Exception, match="Failed to start website server"):
            orchestrator.run_full_evaluation(port=5000)
    
    @patch('vibe_code_bench.orchestrator.crew_setup.create_crew')
    def test_run_full_evaluation_no_ground_truth(
        self,
        mock_create_crew,
        tmp_path
    ):
        """Test full evaluation without ground truth files."""
        run_dir = tmp_path / 'test-run'
        run_dir.mkdir()
        website_dir = run_dir / 'website'
        website_dir.mkdir()
        
        # Create final report
        final_report = {
            'metadata': {
                'run_id': 'test-run',
                'url': 'http://localhost:5000'
            },
            'evaluation': {
                'summary': {
                    'total_vulnerabilities': 0,
                    'found_count': 0,
                    'overall_detection_rate': 0.0
                }
            }
        }
        
        # Mock CrewAI crew wrapper
        captured_context = None
        
        def create_crew_side_effect(context, enable_observability):
            nonlocal captured_context
            captured_context = context
            mock_crew = Mock()
            
            def kickoff():
                # Update context as executor would (no evaluations since no ground truth)
                captured_context.build_result = {
                    'result': {'status': 'success', 'total_files': 3}
                }
                captured_context.website_dir = website_dir
                captured_context.static_analysis_result = {
                    'summary': {'total_vulnerabilities': 0}
                }
                captured_context.url = 'http://localhost:5000'
                captured_context.red_team_result = {
                    'output': 'test output',
                    'report': '# Report\nTest',
                    'execution_time': 5.0,
                    'trace_id': 'trace-456'
                }
                captured_context.final_report = final_report
                captured_context.run_json = run_dir / 'run.json'
                captured_context.report_md = run_dir / 'report.md'
                return {
                    'website_builder': 'Website built. Files: 3',
                    'static_analysis': 'Static analysis completed. Found 0 vulnerabilities.',
                    'server_start': 'Server started at http://localhost:5000',
                    'red_team': 'Red team assessment completed in 5.0s',
                    'server_stop': 'Server stopped successfully',
                    'final_report': 'Final report generated'
                }
            
            mock_crew.kickoff = kickoff
            return mock_crew
        
        mock_create_crew.side_effect = create_crew_side_effect
        
        orchestrator = Orchestrator(
            website_builder_ground_truth_path=None,
            red_team_ground_truth_path=None,
            output_dir=tmp_path
        )
        
        # Should work without ground truth (evaluations will be skipped)
        results = orchestrator.run_full_evaluation(prompt="test", port=5000)
        
        assert results is not None
        assert 'metadata' in results
        mock_create_crew.assert_called_once()
