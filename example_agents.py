"""
Example agents for the LangChain Orchestrator.

This module provides example agent configurations that can be used
with the orchestrator.
"""

from langchain.tools import Tool
from langchain.agents import tool
from typing import Optional
import json


# Example tools for different agent types

@tool
def calculator(expression: str) -> str:
    """Evaluate a mathematical expression safely."""
    try:
        # Simple safe evaluation - in production, use a proper math parser
        allowed_chars = set('0123456789+-*/()., ')
        if all(c in allowed_chars for c in expression):
            result = eval(expression)
            return str(result)
        else:
            return "Error: Invalid characters in expression"
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def text_analyzer(text: str) -> str:
    """Analyze text and return basic statistics."""
    words = text.split()
    chars = len(text)
    sentences = text.count('.') + text.count('!') + text.count('?')
    
    return json.dumps({
        "word_count": len(words),
        "character_count": chars,
        "sentence_count": sentences,
        "average_word_length": sum(len(w) for w in words) / len(words) if words else 0
    })


@tool
def data_formatter(data: str, format_type: str = "json") -> str:
    """Format data in different formats."""
    try:
        if format_type.lower() == "json":
            # Try to parse and pretty print
            parsed = json.loads(data)
            return json.dumps(parsed, indent=2)
        elif format_type.lower() == "list":
            items = data.split(',')
            return '\n'.join(f"- {item.strip()}" for item in items)
        else:
            return f"Unknown format: {format_type}"
    except Exception as e:
        return f"Error formatting: {str(e)}"


# Agent configurations

MATH_AGENT_CONFIG = {
    "name": "math_agent",
    "system_prompt": """You are a helpful math assistant. You can solve mathematical problems,
    evaluate expressions, and explain mathematical concepts. Always show your work
    and provide clear explanations.""",
    "tools": [calculator],
    "description": "Specialized in mathematical calculations and problem solving"
}

ANALYSIS_AGENT_CONFIG = {
    "name": "analysis_agent",
    "system_prompt": """You are a text analysis expert. You analyze text for various metrics,
    extract insights, and provide summaries. Be thorough and accurate in your analysis.""",
    "tools": [text_analyzer, data_formatter],
    "description": "Specialized in text analysis and data processing"
}

GENERAL_AGENT_CONFIG = {
    "name": "general_agent",
    "system_prompt": """You are a helpful AI assistant. You can help with a wide variety
    of tasks including answering questions, providing explanations, and assisting with
    general problem-solving. Be clear, concise, and helpful.""",
    "tools": [calculator, text_analyzer, data_formatter],
    "description": "General purpose assistant for various tasks"
}


def setup_example_agents(orchestrator) -> None:
    """
    Setup example agents on an orchestrator instance.
    
    Args:
        orchestrator: LangChainOrchestrator instance
    """
    
    # Register math agent
    orchestrator.register_agent(
        name=MATH_AGENT_CONFIG["name"],
        tools=MATH_AGENT_CONFIG["tools"],
        system_prompt=MATH_AGENT_CONFIG["system_prompt"],
        description=MATH_AGENT_CONFIG["description"]
    )
    
    # Register analysis agent
    orchestrator.register_agent(
        name=ANALYSIS_AGENT_CONFIG["name"],
        tools=ANALYSIS_AGENT_CONFIG["tools"],
        system_prompt=ANALYSIS_AGENT_CONFIG["system_prompt"],
        description=ANALYSIS_AGENT_CONFIG["description"]
    )
    
    # Register general agent
    orchestrator.register_agent(
        name=GENERAL_AGENT_CONFIG["name"],
        tools=GENERAL_AGENT_CONFIG["tools"],
        system_prompt=GENERAL_AGENT_CONFIG["system_prompt"],
        description=GENERAL_AGENT_CONFIG["description"]
    )

