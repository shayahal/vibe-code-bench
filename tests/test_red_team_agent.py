"""
Comprehensive test suite for RedTeamAgent.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime
import json
from urllib.parse import urlparse, parse_qs

from red_team_agent import RedTeamAgent


class TestRedTeamAgentInitialization:
    """Test RedTeamAgent initialization."""
    
    def test_init_with_api_key(self, mock_openai_api_key):
        """Test initialization with API key."""
        with patch('red_team_agent.ChatOpenAI') as mock_llm_class:
            agent = RedTeamAgent(
                target_url="http://example.com",
                api_key=mock_openai_api_key
            )
            assert agent.target_url == "http://example.com"
            assert agent.api_key == mock_openai_api_key
            mock_llm_class.assert_called_once()
    
    def test_init_with_env_api_key(self, mock_openai_api_key):
        """Test initialization using environment variable."""
        with patch('red_team_agent.ChatOpenAI') as mock_llm_class:
            with patch.dict('os.environ', {'OPENAI_API_KEY': mock_openai_api_key}):
                agent = RedTeamAgent(target_url="http://example.com")
                assert agent.api_key == mock_openai_api_key
                mock_llm_class.assert_called_once()
    
    def test_init_without_api_key(self):
        """Test initialization fails without API key."""
        with patch.dict('os.environ', {}, clear=True):
            with pytest.raises(ValueError, match="OpenAI API key required"):
                RedTeamAgent(target_url="http://example.com")
    
    def test_init_with_custom_headers(self, mock_openai_api_key):
        """Test initialization with custom headers."""
        with patch('red_team_agent.ChatOpenAI'):
            custom_headers = {"User-Agent": "CustomAgent/1.0", "X-Custom": "value"}
            agent = RedTeamAgent(
                target_url="http://example.com",
                api_key=mock_openai_api_key,
                headers=custom_headers
            )
            assert agent.headers == custom_headers
    
    def test_init_with_custom_cookies(self, mock_openai_api_key):
        """Test initialization with custom cookies."""
        with patch('red_team_agent.ChatOpenAI'):
            custom_cookies = {"session": "abc123", "token": "xyz789"}
            agent = RedTeamAgent(
                target_url="http://example.com",
                api_key=mock_openai_api_key,
                cookies=custom_cookies
            )
            assert agent.cookies == custom_cookies
    
    def test_init_default_headers(self, mock_openai_api_key):
        """Test default headers are set."""
        with patch('red_team_agent.ChatOpenAI'):
            agent = RedTeamAgent(
                target_url="http://example.com",
                api_key=mock_openai_api_key
            )
            assert "User-Agent" in agent.headers
            assert agent.headers["User-Agent"] == "RedTeamAgent/1.0"
    
    def test_init_model_parameters(self, mock_openai_api_key):
        """Test model parameters are passed correctly."""
        with patch('red_team_agent.ChatOpenAI') as mock_llm_class:
            agent = RedTeamAgent(
                target_url="http://example.com",
                api_key=mock_openai_api_key,
                model_name="gpt-3.5-turbo",
                temperature=0.5
            )
            mock_llm_class.assert_called_once_with(
                model="gpt-3.5-turbo",
                temperature=0.5,
                api_key=mock_openai_api_key
            )


class TestRedTeamAgentTools:
    """Test RedTeamAgent tool creation and functionality."""
    
    @pytest.fixture
    def agent(self, mock_openai_api_key):
        """Create a RedTeamAgent instance for testing."""
        with patch('red_team_agent.ChatOpenAI'):
            with patch('red_team_agent.create_agent'):
                return RedTeamAgent(
                    target_url="http://example.com",
                    api_key=mock_openai_api_key
                )
    
    def test_create_tools_returns_list(self, agent):
        """Test that _create_tools returns a list."""
        tools = agent._create_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0
    
    def test_tools_have_required_attributes(self, agent):
        """Test that tools have required attributes."""
        tools = agent._create_tools()
        tool_names = [tool.name for tool in tools]
        
        assert "fetch_page" in tool_names
        assert "craft_xss_payload" in tool_names
        assert "craft_sql_injection_payload" in tool_names
        assert "test_xss" in tool_names
        assert "test_sql_injection" in tool_names
        assert "test_form_submission" in tool_names
        assert "analyze_response_security" in tool_names
        assert "generate_report" in tool_names
    
    def test_fetch_page_tool(self, agent, sample_html_page, mock_session):
        """Test fetch_page tool functionality."""
        agent.session = mock_session
        mock_session.get.return_value.text = sample_html_page
        
        tools = agent._create_tools()
        fetch_tool = next(t for t in tools if t.name == "fetch_page")
        
        result = fetch_tool.func("http://example.com")
        
        assert "url" in result
        assert "status_code" in result
        assert "forms" in result
        assert "links" in result
        assert result["has_forms"] is True
        assert len(result["forms"]) == 1
    
    def test_fetch_page_tool_error_handling(self, agent, mock_session):
        """Test fetch_page tool error handling."""
        agent.session = mock_session
        mock_session.get.side_effect = Exception("Connection error")
        
        tools = agent._create_tools()
        fetch_tool = next(t for t in tools if t.name == "fetch_page")
        
        result = fetch_tool.func("http://example.com")
        
        assert "error" in result
        assert result["url"] == "http://example.com"
    
    def test_craft_xss_payload_basic(self, agent):
        """Test crafting basic XSS payload."""
        tools = agent._create_tools()
        craft_tool = next(t for t in tools if t.name == "craft_xss_payload")
        
        payload = craft_tool.func("basic")
        assert "<script>" in payload
        assert "alert" in payload
    
    def test_craft_xss_payload_types(self, agent):
        """Test different XSS payload types."""
        tools = agent._create_tools()
        craft_tool = next(t for t in tools if t.name == "craft_xss_payload")
        
        payload_types = ["basic", "event", "svg", "img", "body", "input", "iframe", "encoded"]
        for payload_type in payload_types:
            payload = craft_tool.func(payload_type)
            assert isinstance(payload, str)
            assert len(payload) > 0
    
    def test_craft_xss_payload_invalid_type(self, agent):
        """Test XSS payload with invalid type defaults to basic."""
        tools = agent._create_tools()
        craft_tool = next(t for t in tools if t.name == "craft_xss_payload")
        
        payload = craft_tool.func("invalid_type")
        assert "<script>" in payload  # Should default to basic
    
    def test_craft_sql_injection_payload_basic(self, agent):
        """Test crafting basic SQL injection payload."""
        tools = agent._create_tools()
        craft_tool = next(t for t in tools if t.name == "craft_sql_injection_payload")
        
        payload = craft_tool.func("basic")
        assert "'" in payload or '"' in payload
        assert "OR" in payload.upper() or "1" in payload
    
    def test_craft_sql_injection_payload_types(self, agent):
        """Test different SQL injection payload types."""
        tools = agent._create_tools()
        craft_tool = next(t for t in tools if t.name == "craft_sql_injection_payload")
        
        payload_types = ["basic", "union", "boolean", "time", "comment", "double", "concat"]
        for payload_type in payload_types:
            payload = craft_tool.func(payload_type)
            assert isinstance(payload, str)
            assert len(payload) > 0
    
    def test_test_xss_tool_vulnerable(self, agent, sample_html_with_xss, mock_session):
        """Test XSS testing tool detects vulnerability."""
        agent.session = mock_session
        agent.test_results = []
        mock_session.get.return_value.text = sample_html_with_xss
        mock_session.get.return_value.status_code = 200
        
        tools = agent._create_tools()
        test_tool = next(t for t in tools if t.name == "test_xss")
        
        payload = "<script>alert('XSS')</script>"
        result = test_tool.func("http://example.com?q=test", "q", payload)
        
        assert result["is_vulnerable"] is True
        assert result["severity"] == "HIGH"
        assert len(agent.test_results) == 1
    
    def test_test_xss_tool_safe(self, agent, sample_html_page, mock_session):
        """Test XSS testing tool correctly identifies safe pages."""
        agent.session = mock_session
        agent.test_results = []
        mock_session.get.return_value.text = sample_html_page
        mock_session.get.return_value.status_code = 200
        
        tools = agent._create_tools()
        test_tool = next(t for t in tools if t.name == "test_xss")
        
        payload = "<script>alert('XSS')</script>"
        result = test_tool.func("http://example.com?q=test", "q", payload)
        
        assert result["is_vulnerable"] is False
        assert "severity" not in result
    
    def test_test_sql_injection_tool_with_error(self, agent, sample_html_with_sql_error, mock_session):
        """Test SQL injection tool detects SQL errors."""
        agent.session = mock_session
        agent.test_results = []
        mock_session.get.return_value.text = sample_html_with_sql_error
        mock_session.get.return_value.status_code = 200
        
        tools = agent._create_tools()
        test_tool = next(t for t in tools if t.name == "test_sql_injection")
        
        payload = "' OR '1'='1"
        result = test_tool.func("http://example.com?q=test", "q", payload)
        
        assert result["has_sql_error"] is True
        assert result["is_vulnerable"] is True
        assert result["severity"] == "CRITICAL"
    
    def test_test_sql_injection_tool_time_based(self, agent, mock_session):
        """Test SQL injection tool detects time-based attacks."""
        agent.session = mock_session
        agent.test_results = []
        
        # Mock delayed response
        import time
        original_time = time.time
        
        def delayed_get(*args, **kwargs):
            time.sleep(0.01)  # Small delay for testing
            response = Mock()
            response.text = "Normal response"
            response.status_code = 200
            return response
        
        mock_session.get.side_effect = delayed_get
        
        tools = agent._create_tools()
        test_tool = next(t for t in tools if t.name == "test_sql_injection")
        
        payload = "'; WAITFOR DELAY '00:00:05'--"
        # Note: This test may need adjustment based on actual implementation
        result = test_tool.func("http://example.com?q=test", "q", payload)
        
        assert "is_vulnerable" in result
        assert "response_time" in result
    
    def test_test_form_submission_post(self, agent, mock_session):
        """Test form submission tool with POST method."""
        agent.session = mock_session
        agent.test_results = []
        mock_session.post.return_value.status_code = 200
        
        tools = agent._create_tools()
        test_tool = next(t for t in tools if t.name == "test_form_submission")
        
        form_data = {"username": "test", "password": "pass"}
        result = test_tool.func("http://example.com/submit", "POST", form_data)
        
        assert result["form_action"] == "http://example.com/submit"
        assert result["method"] == "POST"
        assert result["status_code"] == 200
        mock_session.post.assert_called_once()
    
    def test_test_form_submission_get(self, agent, mock_session):
        """Test form submission tool with GET method."""
        agent.session = mock_session
        agent.test_results = []
        mock_session.get.return_value.status_code = 200
        
        tools = agent._create_tools()
        test_tool = next(t for t in tools if t.name == "test_form_submission")
        
        form_data = {"search": "query"}
        result = test_tool.func("http://example.com/search", "GET", form_data)
        
        assert result["method"] == "GET"
        mock_session.get.assert_called_once()
    
    def test_analyze_response_security_finds_issues(self, agent):
        """Test response security analysis finds issues."""
        tools = agent._create_tools()
        analyze_tool = next(t for t in tools if t.name == "analyze_response_security")
        
        response_text = "Email: test@example.com\nAPI Key: abc123xyz789"
        result = analyze_tool.func(response_text)
        
        assert result["has_issues"] is True
        assert len(result["issues"]) > 0
    
    def test_analyze_response_security_no_issues(self, agent):
        """Test response security analysis with no issues."""
        tools = agent._create_tools()
        analyze_tool = next(t for t in tools if t.name == "analyze_response_security")
        
        response_text = "This is a normal response with no sensitive data."
        result = analyze_tool.func(response_text)
        
        assert result["has_issues"] is False
        assert len(result["issues"]) == 0
    
    def test_generate_report(self, agent, sample_test_results):
        """Test report generation."""
        agent.test_results = sample_test_results
        
        tools = agent._create_tools()
        report_tool = next(t for t in tools if t.name == "generate_report")
        
        report = report_tool.func()
        
        assert isinstance(report, str)
        assert "Web Security Red-Teaming Report" in report
        assert "Target URL" in report
        assert "Vulnerabilities found" in report
        assert "Critical vulnerabilities" in report


class TestRedTeamAgentMethods:
    """Test RedTeamAgent public methods."""
    
    @pytest.fixture
    def agent(self, mock_openai_api_key):
        """Create a RedTeamAgent instance for testing."""
        with patch('red_team_agent.ChatOpenAI'):
            with patch('red_team_agent.create_agent') as mock_create:
                mock_agent = MagicMock()
                mock_create.return_value = mock_agent
                agent = RedTeamAgent(
                    target_url="http://example.com",
                    api_key=mock_openai_api_key
                )
                agent.agent = mock_agent
                return agent
    
    def test_get_results_empty(self, agent):
        """Test get_results with no tests run."""
        results = agent.get_results()
        assert isinstance(results, list)
        assert len(results) == 0
    
    def test_get_results_with_data(self, agent, sample_test_results):
        """Test get_results returns test results."""
        agent.test_results = sample_test_results
        results = agent.get_results()
        assert results == sample_test_results
        assert len(results) == 2
    
    def test_run_test_suite_default_scenarios(self, agent):
        """Test run_test_suite with default scenarios."""
        mock_response = MagicMock()
        mock_response.content = "Test report content"
        agent.agent.invoke.return_value = {"messages": [MagicMock(content="Report")]}
        
        report = agent.run_test_suite()
        
        assert isinstance(report, str)
        assert agent.agent.invoke.call_count > 0
    
    def test_run_test_suite_custom_scenarios(self, agent):
        """Test run_test_suite with custom scenarios."""
        custom_scenarios = [
            "Test scenario 1",
            "Test scenario 2"
        ]
        agent.agent.invoke.return_value = {"messages": [MagicMock(content="Report")]}
        
        report = agent.run_test_suite(test_scenarios=custom_scenarios)
        
        assert isinstance(report, str)
        # Should be called for each scenario plus report generation
        assert agent.agent.invoke.call_count == len(custom_scenarios) + 1
    
    def test_run_test_suite_error_handling(self, agent):
        """Test run_test_suite handles errors gracefully."""
        agent.agent.invoke.side_effect = Exception("Test error")
        
        # Should not raise exception
        report = agent.run_test_suite(test_scenarios=["Test"])
        
        # Should fall back to manual report
        assert isinstance(report, str)
    
    def test_test_single_url_xss(self, agent):
        """Test test_single_url with XSS test type."""
        agent.agent.invoke.return_value = {"output": "XSS test result"}
        
        result = agent.test_single_url("http://example.com?q=test", test_type="xss")
        
        assert result is not None
        agent.agent.invoke.assert_called()
    
    def test_test_single_url_sql(self, agent):
        """Test test_single_url with SQL test type."""
        agent.agent.invoke.return_value = {"output": "SQL test result"}
        
        result = agent.test_single_url("http://example.com?q=test", test_type="sql")
        
        assert result is not None
        agent.agent.invoke.assert_called()
    
    def test_test_single_url_both(self, agent):
        """Test test_single_url with both test types."""
        agent.agent.invoke.return_value = {"output": "Test result"}
        
        result = agent.test_single_url("http://example.com?q=test", test_type="both")
        
        assert result is not None
        # Should be called twice (once for XSS, once for SQL)
        assert agent.agent.invoke.call_count == 2


class TestRedTeamAgentEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.fixture
    def agent(self, mock_openai_api_key):
        """Create a RedTeamAgent instance for testing."""
        with patch('red_team_agent.ChatOpenAI'):
            with patch('red_team_agent.create_agent'):
                return RedTeamAgent(
                    target_url="http://example.com",
                    api_key=mock_openai_api_key
                )
    
    def test_empty_url_handling(self, agent, mock_session):
        """Test handling of empty URLs."""
        agent.session = mock_session
        mock_session.get.side_effect = Exception("Invalid URL")
        
        tools = agent._create_tools()
        fetch_tool = next(t for t in tools if t.name == "fetch_page")
        
        result = fetch_tool.func("")
        assert "error" in result
    
    def test_malformed_url_handling(self, agent, mock_session):
        """Test handling of malformed URLs."""
        agent.session = mock_session
        mock_session.get.side_effect = Exception("Invalid URL")
        
        tools = agent._create_tools()
        test_tool = next(t for t in tools if t.name == "test_xss")
        
        result = test_tool.func("not-a-url", "param", "payload")
        assert "error" in result
    
    def test_timeout_handling(self, agent, mock_session):
        """Test handling of request timeouts."""
        agent.session = mock_session
        import requests
        mock_session.get.side_effect = requests.Timeout("Request timed out")
        
        tools = agent._create_tools()
        fetch_tool = next(t for t in tools if t.name == "fetch_page")
        
        result = fetch_tool.func("http://example.com")
        assert "error" in result
    
    def test_network_error_handling(self, agent, mock_session):
        """Test handling of network errors."""
        agent.session = mock_session
        import requests
        mock_session.get.side_effect = requests.ConnectionError("Connection failed")
        
        tools = agent._create_tools()
        fetch_tool = next(t for t in tools if t.name == "fetch_page")
        
        result = fetch_tool.func("http://example.com")
        assert "error" in result
    
    def test_empty_form_data(self, agent, mock_session):
        """Test form submission with empty data."""
        agent.session = mock_session
        agent.test_results = []
        mock_session.post.return_value.status_code = 200
        
        tools = agent._create_tools()
        test_tool = next(t for t in tools if t.name == "test_form_submission")
        
        result = test_tool.func("http://example.com/submit", "POST", {})
        
        assert result["status_code"] == 200
    
    def test_special_characters_in_payload(self, agent):
        """Test handling of special characters in payloads."""
        tools = agent._create_tools()
        craft_tool = next(t for t in tools if t.name == "craft_xss_payload")
        
        payload = craft_tool.func("basic")
        # Should handle special characters
        assert isinstance(payload, str)
    
    def test_unicode_in_response(self, agent, mock_session):
        """Test handling of unicode characters in responses."""
        agent.session = mock_session
        mock_session.get.return_value.text = "Test with unicode: 测试 🚀"
        mock_session.get.return_value.status_code = 200
        
        tools = agent._create_tools()
        analyze_tool = next(t for t in tools if t.name == "analyze_response_security")
        
        result = analyze_tool.func("Test with unicode: 测试 🚀")
        assert isinstance(result, dict)

