"""
CrewAI Agent Definitions

Defines all CrewAI agents for the orchestrator workflow.
"""

from typing import Optional
from crewai import Agent
from langchain_anthropic import ChatAnthropic
import os

from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


def _create_anthropic_llm(
    model_name: str = "claude-3-haiku-20240307",
    temperature: float = 0.7,
    max_tokens: Optional[int] = None
) -> ChatAnthropic:
    """
    Create Anthropic LLM instance for CrewAI agent.
    
    Args:
        model_name: Anthropic model name (e.g., "claude-3-haiku-20240307")
        temperature: Temperature setting
        max_tokens: Max tokens for response
        
    Returns:
        ChatAnthropic LLM instance
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not found in environment variables")
    
    return ChatAnthropic(
        model=model_name,
        temperature=temperature,
        max_tokens=max_tokens or 4096,
        api_key=api_key
    )


def create_website_builder_agent(
    model_name: str = "claude-3-haiku-20240307"
) -> Agent:
    """
    Create Website Builder agent.
    
    Args:
        model_name: Anthropic model name (e.g., "claude-3-haiku-20240307")
        
    Returns:
        CrewAI Agent for website building
    """
    llm = _create_anthropic_llm(model_name, temperature=0.7, max_tokens=8192)
    
    return Agent(
        role='Website Builder',
        goal='Generate complete, functional website code from prompts including HTML, CSS, JavaScript, and Flask backend',
        backstory="""You are an expert web developer specializing in creating secure, modern, 
        functional websites. You excel at generating complete, production-ready code that 
        includes all necessary files: HTML pages, CSS styling, JavaScript functionality, 
        and Flask backend with proper routing. You always ensure the code is well-structured, 
        follows best practices, and includes a main.py Flask server file.""",
        llm=llm,
        verbose=True,
        allow_delegation=False
    )


def create_static_analysis_agent(
    model_name: str = "claude-3-haiku-20240307"
) -> Agent:
    """
    Create Static Analysis agent.
    
    Args:
        model_name: Anthropic model name (e.g., "claude-3-haiku-20240307")
        
    Returns:
        CrewAI Agent for static code analysis
    """
    llm = _create_anthropic_llm(model_name, temperature=0.3, max_tokens=4096)
    
    return Agent(
        role='Static Code Analyst',
        goal='Perform comprehensive static code analysis to identify security vulnerabilities and code quality issues',
        backstory="""You are a security expert specializing in static code analysis. 
        You use tools like Bandit, Semgrep, and npm audit to identify vulnerabilities 
        in codebases. You analyze code for security issues, dependency vulnerabilities, 
        and code quality problems. You provide detailed reports with severity classifications.""",
        llm=llm,
        verbose=True,
        allow_delegation=False
    )


def create_red_team_agent(
    model_name: str = "claude-3-haiku-20240307"
) -> Agent:
    """
    Create Red Team agent.
    
    Args:
        model_name: Anthropic model name (e.g., "claude-3-haiku-20240307")
        
    Returns:
        CrewAI Agent for security testing
    """
    llm = _create_anthropic_llm(model_name, temperature=0.7, max_tokens=4096)
    
    # Note: Tools are not passed to the CrewAI agent because we execute the red_team_node
    # function directly, which uses the tools internally. The agent is only used for
    # observability/tracking purposes.
    
    return Agent(
        role='Security Tester (Red Team)',
        goal='Perform comprehensive security testing on web applications to identify vulnerabilities including XSS, SQL injection, authentication flaws, and security header issues',
        backstory="""You are an experienced penetration tester and security researcher. 
        You specialize in finding vulnerabilities in web applications through automated 
        and manual testing techniques. You use a variety of security testing tools to 
        identify XSS vulnerabilities, SQL injection flaws, authentication weaknesses, 
        and security header misconfigurations. You provide detailed security assessment 
        reports with actionable findings.""",
        llm=llm,
        # Tools are not passed here - they're used directly in red_team_node execution
        verbose=True,
        allow_delegation=False
    )


def create_website_builder_evaluator_agent(
    model_name: str = "claude-3-haiku-20240307"
) -> Agent:
    """
    Create Website Builder Evaluator agent.
    
    Args:
        model_name: Anthropic model name (e.g., "claude-3-haiku-20240307")
        
    Returns:
        CrewAI Agent for evaluating website builder results
    """
    llm = _create_anthropic_llm(model_name, temperature=0.3, max_tokens=4096)
    
    return Agent(
        role='Website Quality Evaluator',
        goal='Evaluate website builder output against ground truth criteria to assess quality, completeness, and correctness',
        backstory="""You are a quality assurance expert specializing in evaluating 
        AI-generated code. You compare generated websites against ground truth 
        specifications, checking for completeness, correctness, functionality, and 
        adherence to requirements. You provide detailed evaluation reports with metrics 
        and scores.""",
        llm=llm,
        verbose=True,
        allow_delegation=False
    )


def create_red_team_evaluator_agent(
    model_name: str = "claude-3-haiku-20240307"
) -> Agent:
    """
    Create Red Team Evaluator agent.
    
    Args:
        model_name: Anthropic model name (e.g., "claude-3-haiku-20240307")
        
    Returns:
        CrewAI Agent for evaluating red team findings
    """
    llm = _create_anthropic_llm(model_name, temperature=0.3, max_tokens=4096)
    
    return Agent(
        role='Security Findings Evaluator',
        goal='Evaluate red team security findings against ground truth vulnerabilities to assess detection accuracy and completeness',
        backstory="""You are a security evaluation expert. You compare security testing 
        findings against known ground truth vulnerabilities to assess how well the red 
        team agent performed. You calculate detection rates, identify false positives 
        and false negatives, and provide comprehensive evaluation metrics.""",
        llm=llm,
        verbose=True,
        allow_delegation=False
    )


def create_final_report_agent(
    model_name: str = "claude-3-haiku-20240307"
) -> Agent:
    """
    Create Final Report Generator agent.
    
    Args:
        model_name: Anthropic model name (e.g., "claude-3-haiku-20240307")
        
    Returns:
        CrewAI Agent for generating final reports
    """
    llm = _create_anthropic_llm(model_name, temperature=0.5, max_tokens=8192)
    
    return Agent(
        role='Report Generator',
        goal='Generate comprehensive final reports that consolidate all evaluation results, findings, and metrics into clear, actionable documentation',
        backstory="""You are an expert technical writer specializing in security and 
        quality assessment reports. You excel at synthesizing complex evaluation data 
        from multiple sources into clear, comprehensive reports. You create well-structured 
        markdown and JSON reports that include all relevant metrics, findings, and 
        recommendations.""",
        llm=llm,
        verbose=True,
        allow_delegation=False
    )


# Server manager doesn't need an agent - it's a utility function
# We'll handle it directly in tasks

