"""
Pytest configuration and shared fixtures for agent tests.
"""

import os
import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any
import json
from datetime import datetime
from langchain.tools import Tool

# Set test environment variables
os.environ["OPENAI_API_KEY"] = "test-api-key-12345"


@pytest.fixture
def mock_openai_api_key():
    """Mock OpenAI API key for testing."""
    return "test-api-key-12345"


@pytest.fixture
def mock_llm():
    """Mock LangChain LLM for testing."""
    mock = MagicMock()
    mock.model_name = "gpt-4"
    mock.temperature = 0.7
    return mock


@pytest.fixture
def sample_html_page():
    """Sample HTML page for testing."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page</title>
    </head>
    <body>
        <h1>Welcome</h1>
        <form action="/submit" method="POST">
            <input type="text" name="username" value="test">
            <input type="password" name="password" value="">
            <textarea name="comment"></textarea>
            <button type="submit">Submit</button>
        </form>
        <a href="/page1">Link 1</a>
        <a href="/page2">Link 2</a>
        <p>Some content here</p>
    </body>
    </html>
    """


@pytest.fixture
def sample_html_with_xss():
    """Sample HTML page with XSS vulnerability."""
    return """
    <!DOCTYPE html>
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: <script>alert('XSS')</script></p>
    </body>
    </html>
    """


@pytest.fixture
def sample_html_with_sql_error():
    """Sample HTML page with SQL error."""
    return """
    <!DOCTYPE html>
    <html>
    <body>
        <h1>Error</h1>
        <p>Warning: mysql_fetch_array() expects parameter 1 to be resource</p>
    </body>
    </html>
    """


@pytest.fixture
def mock_http_response():
    """Mock HTTP response for testing."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "<html><body>Test</body></html>"
    mock_response.headers = {"Content-Type": "text/html"}
    mock_response.cookies = {}
    return mock_response


@pytest.fixture
def mock_session():
    """Mock requests session."""
    session = MagicMock()
    response = Mock()
    response.status_code = 200
    response.text = "<html><body>Test</body></html>"
    response.headers = {"Content-Type": "text/html"}
    response.cookies = {}
    session.get.return_value = response
    session.post.return_value = response
    session.headers = {}
    session.cookies = {}
    return session


@pytest.fixture
def sample_test_results():
    """Sample test results for testing."""
    return [
        {
            "url": "http://example.com/test?param=value",
            "parameter": "param",
            "payload": "<script>alert('XSS')</script>",
            "status_code": 200,
            "is_vulnerable": True,
            "severity": "HIGH",
            "issue": "XSS vulnerability detected",
            "timestamp": datetime.now().isoformat()
        },
        {
            "url": "http://example.com/search?q=test",
            "parameter": "q",
            "payload": "' OR '1'='1",
            "status_code": 200,
            "is_vulnerable": False,
            "timestamp": datetime.now().isoformat()
        }
    ]


@pytest.fixture
def mock_agent_executor():
    """Mock agent executor for testing."""
    from unittest.mock import AsyncMock
    executor = MagicMock()
    executor.invoke = MagicMock(return_value={"output": "Test result"})
    executor.ainvoke = AsyncMock(return_value={"output": "Test result"})
    return executor


@pytest.fixture
def sample_task_metadata():
    """Sample task metadata."""
    return {
        "priority": "high",
        "category": "security",
        "tags": ["xss", "testing"]
    }


@pytest.fixture
def sample_tools():
    """Create sample tools for testing."""
    def dummy_tool_func(input: str) -> str:
        return f"Result: {input}"
    
    return [
        Tool(
            name="dummy_tool",
            func=dummy_tool_func,
            description="A dummy tool for testing"
        )
    ]


@pytest.fixture(autouse=True)
def reset_env():
    """Reset environment variables before each test."""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)

