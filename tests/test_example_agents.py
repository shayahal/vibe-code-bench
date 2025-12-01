"""
Comprehensive test suite for example agents.
"""

import pytest
import json
from unittest.mock import Mock, MagicMock, patch

from example_agents import (
    calculator,
    text_analyzer,
    data_formatter,
    MATH_AGENT_CONFIG,
    ANALYSIS_AGENT_CONFIG,
    GENERAL_AGENT_CONFIG,
    setup_example_agents
)


class TestCalculatorTool:
    """Test calculator tool functionality."""
    
    def test_calculator_addition(self):
        """Test addition."""
        result = calculator("2 + 2")
        assert result == "4"
    
    def test_calculator_subtraction(self):
        """Test subtraction."""
        result = calculator("10 - 3")
        assert result == "7"
    
    def test_calculator_multiplication(self):
        """Test multiplication."""
        result = calculator("5 * 4")
        assert result == "20"
    
    def test_calculator_division(self):
        """Test division."""
        result = calculator("20 / 4")
        assert result == "5.0"
    
    def test_calculator_complex_expression(self):
        """Test complex expression."""
        result = calculator("(2 + 3) * 4")
        assert result == "20"
    
    def test_calculator_decimal(self):
        """Test decimal numbers."""
        result = calculator("3.5 + 2.5")
        assert result == "6.0"
    
    def test_calculator_invalid_characters(self):
        """Test with invalid characters."""
        result = calculator("import os; os.system('rm -rf /')")
        assert "Error" in result
    
    def test_calculator_invalid_expression(self):
        """Test invalid expression."""
        result = calculator("2 +")
        assert "Error" in result
    
    def test_calculator_empty_string(self):
        """Test empty string."""
        result = calculator("")
        assert isinstance(result, str)
    
    def test_calculator_whitespace(self):
        """Test expression with whitespace."""
        result = calculator("  2  +  2  ")
        assert result == "4"


class TestTextAnalyzerTool:
    """Test text analyzer tool functionality."""
    
    def test_text_analyzer_basic(self):
        """Test basic text analysis."""
        text = "The quick brown fox jumps over the lazy dog."
        result = text_analyzer(text)
        
        data = json.loads(result)
        assert data["word_count"] == 9
        assert data["character_count"] == len(text)
        assert data["sentence_count"] == 1
    
    def test_text_analyzer_multiple_sentences(self):
        """Test text with multiple sentences."""
        text = "First sentence. Second sentence! Third sentence?"
        result = text_analyzer(text)
        
        data = json.loads(result)
        assert data["sentence_count"] == 3
    
    def test_text_analyzer_empty_text(self):
        """Test empty text."""
        result = text_analyzer("")
        data = json.loads(result)
        assert data["word_count"] == 0
        assert data["character_count"] == 0
        assert data["sentence_count"] == 0
        assert data["average_word_length"] == 0
    
    def test_text_analyzer_single_word(self):
        """Test single word."""
        result = text_analyzer("Hello")
        data = json.loads(result)
        assert data["word_count"] == 1
        assert data["average_word_length"] == 5.0
    
    def test_text_analyzer_average_word_length(self):
        """Test average word length calculation."""
        text = "a bb ccc"
        result = text_analyzer(text)
        data = json.loads(result)
        # (1 + 2 + 3) / 3 = 2.0
        assert data["average_word_length"] == 2.0
    
    def test_text_analyzer_unicode(self):
        """Test text with unicode characters."""
        text = "Hello 世界 🚀"
        result = text_analyzer(text)
        data = json.loads(result)
        assert data["character_count"] == len(text)


class TestDataFormatterTool:
    """Test data formatter tool functionality."""
    
    def test_data_formatter_json(self):
        """Test JSON formatting."""
        data = '{"name": "test", "value": 123}'
        result = data_formatter(data, "json")
        
        # Should be pretty-printed JSON
        parsed = json.loads(result)
        assert parsed["name"] == "test"
        assert parsed["value"] == 123
    
    def test_data_formatter_list(self):
        """Test list formatting."""
        data = "apple, banana, cherry"
        result = data_formatter(data, "list")
        
        assert "- apple" in result
        assert "- banana" in result
        assert "- cherry" in result
    
    def test_data_formatter_invalid_json(self):
        """Test invalid JSON."""
        data = "not valid json"
        result = data_formatter(data, "json")
        assert "Error" in result
    
    def test_data_formatter_unknown_format(self):
        """Test unknown format."""
        data = "some data"
        result = data_formatter(data, "unknown")
        assert "Unknown format" in result
    
    def test_data_formatter_empty_list(self):
        """Test empty list."""
        result = data_formatter("", "list")
        assert isinstance(result, str)
    
    def test_data_formatter_complex_json(self):
        """Test complex JSON structure."""
        data = '{"users": [{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]}'
        result = data_formatter(data, "json")
        
        parsed = json.loads(result)
        assert len(parsed["users"]) == 2
        assert parsed["users"][0]["name"] == "Alice"


class TestAgentConfigurations:
    """Test agent configuration structures."""
    
    def test_math_agent_config(self):
        """Test math agent configuration."""
        assert MATH_AGENT_CONFIG["name"] == "math_agent"
        assert "system_prompt" in MATH_AGENT_CONFIG
        assert "tools" in MATH_AGENT_CONFIG
        assert "description" in MATH_AGENT_CONFIG
        assert calculator in MATH_AGENT_CONFIG["tools"]
    
    def test_analysis_agent_config(self):
        """Test analysis agent configuration."""
        assert ANALYSIS_AGENT_CONFIG["name"] == "analysis_agent"
        assert "system_prompt" in ANALYSIS_AGENT_CONFIG
        assert "tools" in ANALYSIS_AGENT_CONFIG
        assert text_analyzer in ANALYSIS_AGENT_CONFIG["tools"]
        assert data_formatter in ANALYSIS_AGENT_CONFIG["tools"]
    
    def test_general_agent_config(self):
        """Test general agent configuration."""
        assert GENERAL_AGENT_CONFIG["name"] == "general_agent"
        assert "system_prompt" in GENERAL_AGENT_CONFIG
        assert "tools" in GENERAL_AGENT_CONFIG
        # Should have all tools
        assert calculator in GENERAL_AGENT_CONFIG["tools"]
        assert text_analyzer in GENERAL_AGENT_CONFIG["tools"]
        assert data_formatter in GENERAL_AGENT_CONFIG["tools"]


class TestSetupExampleAgents:
    """Test setup_example_agents function."""
    
    @pytest.fixture
    def mock_orchestrator(self):
        """Create mock orchestrator."""
        orchestrator = MagicMock()
        orchestrator.register_agent = MagicMock()
        return orchestrator
    
    def test_setup_example_agents_registers_all(self, mock_orchestrator):
        """Test that all agents are registered."""
        setup_example_agents(mock_orchestrator)
        
        # Should register 3 agents
        assert mock_orchestrator.register_agent.call_count == 3
    
    def test_setup_example_agents_math_agent(self, mock_orchestrator):
        """Test math agent registration."""
        setup_example_agents(mock_orchestrator)
        
        calls = mock_orchestrator.register_agent.call_args_list
        math_call = next((c for c in calls if c[1]["name"] == "math_agent"), None)
        assert math_call is not None
        assert calculator in math_call[1]["tools"]
    
    def test_setup_example_agents_analysis_agent(self, mock_orchestrator):
        """Test analysis agent registration."""
        setup_example_agents(mock_orchestrator)
        
        calls = mock_orchestrator.register_agent.call_args_list
        analysis_call = next((c for c in calls if c[1]["name"] == "analysis_agent"), None)
        assert analysis_call is not None
        assert text_analyzer in analysis_call[1]["tools"]
    
    def test_setup_example_agents_general_agent(self, mock_orchestrator):
        """Test general agent registration."""
        setup_example_agents(mock_orchestrator)
        
        calls = mock_orchestrator.register_agent.call_args_list
        general_call = next((c for c in calls if c[1]["name"] == "general_agent"), None)
        assert general_call is not None
        assert calculator in general_call[1]["tools"]


class TestToolIntegration:
    """Test tool integration and edge cases."""
    
    def test_calculator_with_whitespace_only(self):
        """Test calculator with whitespace-only input."""
        result = calculator("   ")
        assert isinstance(result, str)
    
    def test_text_analyzer_with_special_characters(self):
        """Test text analyzer with special characters."""
        text = "Hello! @#$%^&*() World?"
        result = text_analyzer(text)
        data = json.loads(result)
        assert data["word_count"] == 2
    
    def test_data_formatter_with_whitespace_in_list(self):
        """Test data formatter with whitespace in list."""
        data = "  apple  ,  banana  ,  cherry  "
        result = data_formatter(data, "list")
        assert "- apple" in result
        assert "- banana" in result
    
    def test_calculator_division_by_zero(self):
        """Test calculator division by zero."""
        result = calculator("10 / 0")
        assert "Error" in result
    
    def test_text_analyzer_only_punctuation(self):
        """Test text analyzer with only punctuation."""
        result = text_analyzer("...!!!???")
        data = json.loads(result)
        assert data["word_count"] == 0
        assert data["sentence_count"] == 3
    
    def test_data_formatter_nested_json(self):
        """Test data formatter with nested JSON."""
        data = '{"level1": {"level2": {"level3": "value"}}}'
        result = data_formatter(data, "json")
        parsed = json.loads(result)
        assert parsed["level1"]["level2"]["level3"] == "value"

