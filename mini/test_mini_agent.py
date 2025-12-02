"""
Tests for Mini Red Team Agent

Tests cover:
- Browse tool functionality
- Tools registry
- Report generator
- Main agent (with mocks)
"""

import pytest
import os
from unittest.mock import Mock, patch, MagicMock, call
from pathlib import Path
import sys

# Add mini directory to path for imports
mini_dir = Path(__file__).parent
sys.path.insert(0, str(mini_dir))

from tools.browse_tool import browse_url, get_browse_tool
from tools import get_tool, get_all_tools, AVAILABLE_TOOLS, TOOLS_REGISTRY
from report_generator import (
    get_report_generation_prompt,
    generate_run_report,
    AGENT_SYSTEM_PROMPT
)


class TestBrowseTool:
    """Tests for the browse_url tool."""
    
    @patch('tools.browse_tool.requests.get')
    @patch('tools.browse_tool.BeautifulSoup')
    def test_browse_url_success(self, mock_soup, mock_get):
        """Test successful URL browsing."""
        # Mock HTTP response
        mock_response = Mock()
        mock_response.text = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <h1>First Line</h1>
                <p>Second Line</p>
                <div>Third Line</div>
                <script>console.log('ignore');</script>
            </body>
        </html>
        """
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        # Mock BeautifulSoup
        mock_soup_instance = MagicMock()
        mock_soup_instance.get_text.return_value = "First Line\nSecond Line\nThird Line\nFourth Line"
        # Mock soup(["script", "style"]) call - returns empty list (no scripts/styles to remove)
        # When soup is called with a list, it returns a ResultSet that can be iterated
        # Configure the instance to return empty list when called
        mock_soup_instance.__call__ = MagicMock(return_value=[])
        mock_soup.return_value = mock_soup_instance
        
        result = browse_url("https://example.com")
        
        assert "https://example.com" in result
        assert "First 3 lines" in result
        mock_get.assert_called_once()
        mock_soup.assert_called_once()
    
    @patch('tools.browse_tool.requests.get')
    def test_browse_url_http_error(self, mock_get):
        """Test handling of HTTP errors."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = Exception("404 Not Found")
        mock_get.return_value = mock_response
        
        result = browse_url("https://example.com/notfound")
        
        assert "Error browsing" in result
        assert "404 Not Found" in result
    
    @patch('tools.browse_tool.requests.get')
    def test_browse_url_network_error(self, mock_get):
        """Test handling of network errors."""
        mock_get.side_effect = Exception("Connection timeout")
        
        result = browse_url("https://example.com")
        
        assert "Error browsing" in result
        assert "Connection timeout" in result
    
    @patch('tools.browse_tool.requests.get')
    @patch('tools.browse_tool.BeautifulSoup')
    def test_browse_url_less_than_3_lines(self, mock_soup, mock_get):
        """Test URL with less than 3 lines of content."""
        mock_response = Mock()
        mock_response.text = "<html><body><p>Only one line</p></body></html>"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        mock_soup_instance = MagicMock()
        mock_soup_instance.get_text.return_value = "Only one line"
        # Mock soup(["script", "style"]) call - returns empty list
        mock_soup_instance.__call__ = MagicMock(return_value=[])
        mock_soup.return_value = mock_soup_instance
        
        result = browse_url("https://example.com")
        
        assert "Only one line" in result
    
    def test_get_browse_tool(self):
        """Test that get_browse_tool returns a StructuredTool."""
        tool = get_browse_tool()
        
        assert tool is not None
        assert tool.name == "browse_url"
        assert callable(tool.func)
        
        # Test that the tool can be invoked
        with patch('tools.browse_tool.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = "<html><body>Test</body></html>"
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response
            
            with patch('tools.browse_tool.BeautifulSoup') as mock_soup:
                mock_soup_instance = MagicMock()
                mock_soup_instance.get_text.return_value = "Test\nLine\nContent"
                # Mock soup(["script", "style"]) call - returns empty list
                mock_soup_instance.__call__ = MagicMock(return_value=[])
                mock_soup.return_value = mock_soup_instance
                
                result = tool.invoke({"url": "https://example.com"})
                assert "https://example.com" in result


class TestToolsRegistry:
    """Tests for the tools registry."""
    
    def test_available_tools(self):
        """Test that AVAILABLE_TOOLS contains expected tools."""
        assert "browse_url" in AVAILABLE_TOOLS
        assert len(AVAILABLE_TOOLS) >= 1
    
    def test_get_tool_success(self):
        """Test getting a tool from the registry."""
        tool = get_tool("browse_url")
        
        assert tool is not None
        assert tool.name == "browse_url"
    
    def test_get_tool_not_found(self):
        """Test getting a non-existent tool raises KeyError."""
        with pytest.raises(KeyError) as exc_info:
            get_tool("nonexistent_tool")
        
        assert "not found in registry" in str(exc_info.value)
        assert "browse_url" in str(exc_info.value)  # Should mention available tools
    
    def test_get_all_tools(self):
        """Test getting all tools from registry."""
        tools = get_all_tools()
        
        assert len(tools) == len(AVAILABLE_TOOLS)
        # Check that all tools have names and are StructuredTool instances
        assert all(hasattr(tool, 'name') for tool in tools)
        assert "browse_url" in [tool.name for tool in tools]
    
    def test_tools_registry_structure(self):
        """Test that TOOLS_REGISTRY has correct structure."""
        assert isinstance(TOOLS_REGISTRY, dict)
        assert "browse_url" in TOOLS_REGISTRY
        assert callable(TOOLS_REGISTRY["browse_url"])


class TestReportGenerator:
    """Tests for the report generator."""
    
    def test_agent_system_prompt(self):
        """Test that AGENT_SYSTEM_PROMPT is defined."""
        assert AGENT_SYSTEM_PROMPT is not None
        assert isinstance(AGENT_SYSTEM_PROMPT, str)
        # The prompt is now for a security red team agent
        assert "security" in AGENT_SYSTEM_PROMPT.lower() or "red team" in AGENT_SYSTEM_PROMPT.lower()
        assert "browse_url" in AGENT_SYSTEM_PROMPT
    
    def test_get_report_generation_prompt(self):
        """Test report generation prompt creation."""
        url = "https://example.com"
        output = "Test output"
        execution_time = 1.5
        
        prompt = get_report_generation_prompt(url, output, execution_time)
        
        assert url in prompt
        assert output in prompt
        assert "1.50" in prompt  # Formatted execution time
        assert "claude-3-haiku" in prompt
        assert "Executive Summary" in prompt
        assert "Tools Used" in prompt
        assert "Cost Analysis" in prompt
    
    @patch('report_generator.datetime')
    def test_generate_run_report_success(self, mock_datetime):
        """Test successful report generation."""
        # Mock datetime
        mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T00:00:00"
        mock_datetime.now.return_value.strftime.return_value = "2024-01-01 00:00:00"
        
        # Mock LLM
        mock_llm = Mock()
        mock_response = Mock()
        mock_response.content = "Generated report content"
        mock_llm.invoke.return_value = mock_response
        
        # Mock LangFuse client
        mock_langfuse_client = Mock()
        
        # Mock LangFuse handler
        mock_handler = Mock()
        mock_handler.get_trace_id = Mock(return_value="test-trace-id")
        
        # Mock environment variable
        with patch.dict(os.environ, {'LANGFUSE_HOST': 'https://test.langfuse.com'}):
            report = generate_run_report(
                llm=mock_llm,
                langfuse_client=mock_langfuse_client,
                url="https://example.com",
                output="Test output",
                execution_time=1.5,
                langfuse_handler=mock_handler
            )
        
        assert "# Agent Run Report" in report
        assert "https://example.com" in report
        assert "1.50 seconds" in report
        assert "claude-3-haiku" in report
        assert "Generated report content" in report
        mock_llm.invoke.assert_called_once()
    
    @patch('report_generator.datetime')
    def test_generate_run_report_fallback(self, mock_datetime):
        """Test report generation fallback on error."""
        # Mock datetime
        mock_datetime.now.return_value.strftime.return_value = "2024-01-01 00:00:00"
        
        # Mock LLM that raises an error
        mock_llm = Mock()
        mock_llm.invoke.side_effect = Exception("LLM error")
        
        # Mock LangFuse client
        mock_langfuse_client = Mock()
        
        # Mock LangFuse handler
        mock_handler = Mock()
        
        report = generate_run_report(
            llm=mock_llm,
            langfuse_client=mock_langfuse_client,
            url="https://example.com",
            output="Test output",
            execution_time=1.5,
            langfuse_handler=mock_handler
        )
        
        # Should return fallback report
        assert "# Agent Run Report" in report
        assert "https://example.com" in report
        assert "1.50 seconds" in report
        assert "LLM error" in report
    
    @patch('report_generator.datetime')
    def test_generate_run_report_no_trace_id(self, mock_datetime):
        """Test report generation when trace ID is not available."""
        mock_datetime.now.return_value.isoformat.return_value = "2024-01-01T00:00:00"
        mock_datetime.now.return_value.strftime.return_value = "2024-01-01 00:00:00"
        
        mock_llm = Mock()
        mock_response = Mock()
        mock_response.content = "Report content"
        mock_llm.invoke.return_value = mock_response
        
        mock_langfuse_client = Mock()
        mock_handler = Mock()
        # Handler doesn't have last_trace_id or get_trace_id attributes
        # Make sure hasattr returns False for both
        type(mock_handler).last_trace_id = None
        if hasattr(mock_handler, 'get_trace_id'):
            delattr(mock_handler, 'get_trace_id')
        
        with patch.dict(os.environ, {'LANGFUSE_HOST': 'https://test.langfuse.com'}):
            report = generate_run_report(
                llm=mock_llm,
                langfuse_client=mock_langfuse_client,
                url="https://example.com",
                output="Test output",
                execution_time=2.0,
                langfuse_handler=mock_handler
            )
        
        # Trace ID should be None or "Available in LangFuse dashboard"
        assert "Available in LangFuse dashboard" in report or "Trace ID" in report


class TestMiniRedTeamAgent:
    """Tests for the main mini red team agent."""
    
    @patch('mini_red_team_agent.Langfuse')
    @patch('mini_red_team_agent.LangfuseCallbackHandler')
    @patch('mini_red_team_agent.ChatAnthropic')
    @patch('langchain.agents.create_agent')
    @patch('report_generator.generate_run_report')
    @patch.dict(os.environ, {
        'ANTHROPIC_API_KEY': 'test-key',
        'LANGFUSE_SECRET_KEY': 'test-secret',
        'LANGFUSE_PUBLIC_KEY': 'test-public',
        'LANGFUSE_HOST': 'https://test.langfuse.com'
    })
    def test_main_success(self, mock_generate_report, mock_create_agent, 
                          mock_chat_anthropic, mock_handler_class, mock_langfuse):
        """Test successful main execution."""
        # Mock LangFuse
        mock_langfuse_instance = Mock()
        mock_langfuse.return_value = mock_langfuse_instance
        
        # Mock LangFuse handler
        mock_handler_instance = Mock()
        mock_handler_class.return_value = mock_handler_instance
        
        # Mock LLM
        mock_llm_instance = Mock()
        mock_chat_anthropic.return_value = mock_llm_instance
        
        # Mock agent - use MagicMock to handle all method calls
        mock_agent_instance = MagicMock()
        # The result needs to be a dict with "messages" key as per the code
        mock_message = MagicMock()
        mock_message.content = "Test output"
        mock_result = {"messages": [mock_message]}
        # Make sure invoke returns the mock result immediately without making real calls
        mock_agent_instance.invoke = MagicMock(return_value=mock_result)
        mock_create_agent.return_value = mock_agent_instance
        
        # Mock report generation
        mock_generate_report.return_value = "# Test Report\nContent"
        
        # Mock time.sleep and time.time to speed up tests
        # time.time is called multiple times, so we need to provide enough values
        time_values = [0.0, 1.5, 1.5, 1.5, 1.5]  # start_time, end_time, and any other calls
        with patch('mini_red_team_agent.time.sleep'):
            with patch('mini_red_team_agent.time.time', side_effect=time_values):
                with patch('mini_red_team_agent.sys.argv', ['mini_red_team_agent.py', '--url', 'https://example.com']):
                    with patch('mini_red_team_agent.Path') as mock_path_class:
                        # Create a proper mock for Path that supports division
                        mock_report_dir = MagicMock()
                        mock_report_file = MagicMock()
                        mock_report_file.write_text = Mock()
                        mock_report_dir.__truediv__ = Mock(return_value=mock_report_file)
                        mock_report_dir.mkdir = Mock()
                        mock_path_class.return_value = mock_report_dir
                        
                        # Mock handler attributes that might be accessed
                        mock_handler_instance.langfuse = Mock()
                        mock_handler_instance.langfuse.flush = Mock()
                        mock_handler_instance.last_trace_id = None
                        
                        # Import here to avoid import-time issues
                        import importlib
                        import mini_red_team_agent
                        importlib.reload(mini_red_team_agent)
                        mini_red_team_agent.main()
        
        # Verify agent was created and invoked
        mock_create_agent.assert_called_once()
        mock_agent_instance.invoke.assert_called_once()
        mock_generate_report.assert_called_once()
    
    @patch('mini_red_team_agent.os.getenv')
    def test_main_missing_env_vars(self, mock_getenv):
        """Test main with missing environment variables."""
        # Make getenv return None for LangFuse keys
        def getenv_side_effect(key, default=None):
            if key in ['LANGFUSE_SECRET_KEY', 'LANGFUSE_PUBLIC_KEY']:
                return None
            # For other keys, use actual env or default
            return os.environ.get(key, default)
        mock_getenv.side_effect = getenv_side_effect
        
        with patch('mini_red_team_agent.sys.argv', ['mini_red_team_agent.py', '--url', 'https://example.com']):
            with patch('mini_red_team_agent.sys.exit') as mock_exit:
                import importlib
                import mini_red_team_agent
                importlib.reload(mini_red_team_agent)
                try:
                    mini_red_team_agent.main()
                except SystemExit:
                    pass  # Expected
                # Should exit because LangFuse credentials are missing
                assert mock_exit.called, "sys.exit should have been called due to missing LangFuse credentials"
    
    @patch('mini_red_team_agent.os.getenv')
    @patch('mini_red_team_agent.Langfuse')
    @patch('mini_red_team_agent.LangfuseCallbackHandler')
    def test_main_missing_api_key(self, mock_handler_class, mock_langfuse, mock_getenv):
        """Test main with missing API key."""
        # Make getenv return values for LangFuse but None for API key
        def getenv_side_effect(key, default=None):
            if key == 'ANTHROPIC_API_KEY':
                return None
            elif key == 'LANGFUSE_SECRET_KEY':
                return 'test-secret'
            elif key == 'LANGFUSE_PUBLIC_KEY':
                return 'test-public'
            elif key == 'LANGFUSE_HOST':
                return 'https://cloud.langfuse.com'
            # For other keys, use actual env or default
            return os.environ.get(key, default)
        mock_getenv.side_effect = getenv_side_effect
        
        mock_langfuse_instance = Mock()
        mock_langfuse.return_value = mock_langfuse_instance
        
        mock_handler_instance = Mock()
        mock_handler_class.return_value = mock_handler_instance
        
        with patch('mini_red_team_agent.sys.argv', ['mini_red_team_agent.py', '--url', 'https://example.com']):
            with patch('mini_red_team_agent.sys.exit') as mock_exit:
                import importlib
                import mini_red_team_agent
                importlib.reload(mini_red_team_agent)
                try:
                    mini_red_team_agent.main()
                except SystemExit:
                    pass  # Expected
                # Should exit because API key is missing
                assert mock_exit.called, "sys.exit should have been called due to missing API key"
    
    @patch('mini_red_team_agent.Langfuse')
    @patch('mini_red_team_agent.LangfuseCallbackHandler')
    @patch('mini_red_team_agent.ChatAnthropic')
    @patch('langchain.agents.create_agent')
    @patch('tools.browse_url')
    @patch('report_generator.generate_run_report')
    @patch.dict(os.environ, {
        'ANTHROPIC_API_KEY': 'test-key',
        'LANGFUSE_SECRET_KEY': 'test-secret',
        'LANGFUSE_PUBLIC_KEY': 'test-public'
    })
    def test_main_agent_error_fallback(self, mock_generate_report, mock_browse_url,
                                        mock_create_agent, mock_chat_anthropic,
                                        mock_handler_class, mock_langfuse):
        """Test main with agent error triggering fallback."""
        # Mock LangFuse
        mock_langfuse_instance = Mock()
        mock_langfuse.return_value = mock_langfuse_instance
        
        # Mock LangFuse handler
        mock_handler_instance = Mock()
        mock_handler_class.return_value = mock_handler_instance
        
        # Mock LLM
        mock_llm_instance = Mock()
        mock_chat_anthropic.return_value = mock_llm_instance
        
        # Mock agent that raises error - use MagicMock to handle all method calls
        mock_agent_instance = MagicMock()
        # Make sure invoke raises the exception immediately without making real calls
        mock_agent_instance.invoke = MagicMock(side_effect=Exception("Agent error"))
        mock_create_agent.return_value = mock_agent_instance
        
        # Mock fallback tool
        mock_browse_url.return_value = "Fallback output"
        
        # Mock report generation
        mock_generate_report.return_value = "# Test Report"
        
        # Mock handler attributes that might be accessed
        mock_handler_instance.langfuse = Mock()
        mock_handler_instance.langfuse.flush = Mock()
        mock_handler_instance.last_trace_id = None
        
        # time.time is called multiple times, so we need to provide enough values
        time_values = [0.0, 1.0, 1.0, 1.0, 1.0]  # start_time, end_time, and any other calls
        with patch('mini_red_team_agent.time.sleep'):
            with patch('mini_red_team_agent.time.time', side_effect=time_values):
                with patch('mini_red_team_agent.sys.argv', ['mini_red_team_agent.py', '--url', 'https://example.com']):
                    with patch('mini_red_team_agent.Path') as mock_path_class:
                        # Create a proper mock for Path that supports division
                        mock_report_dir = MagicMock()
                        mock_report_file = MagicMock()
                        mock_report_file.write_text = Mock()
                        mock_report_dir.__truediv__ = Mock(return_value=mock_report_file)
                        mock_report_dir.mkdir = Mock()
                        mock_path_class.return_value = mock_report_dir
                        
                        import importlib
                        import mini_red_team_agent
                        importlib.reload(mini_red_team_agent)
                        mini_red_team_agent.main()
        
        # Verify fallback was called
        mock_browse_url.assert_called_once_with("https://example.com")
        mock_generate_report.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

