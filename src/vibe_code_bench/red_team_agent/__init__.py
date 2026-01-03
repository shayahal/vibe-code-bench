"""Red Team Agent - LLM-powered security vulnerability scanner.

This module provides an intelligent security scanning agent that:
- Takes a URL as input
- Orchestrates multiple security tools (nuclei, sqlmap, dalfox, wapiti, nikto)
- Uses LLM for intelligent tool selection and analysis
- Traces all operations to Langfuse for observability
- Never fails silently - all errors are raised

Usage:
    from vibe_code_bench.red_team_agent import scan, RedTeamAgent
    
    # Simple one-liner
    report = scan("https://example.com")
    print(f"Found {report.total_findings} vulnerabilities")
    
    # With more control
    agent = RedTeamAgent()
    report = agent.scan("https://example.com")
    agent.save_report(report)
    agent.cleanup()

Environment Variables:
    Required (one of):
        OPENAI_API_KEY - For GPT-4 (recommended)
        ANTHROPIC_API_KEY - For Claude
        OPENROUTER_API_KEY - For OpenRouter
    
    Optional:
        LANGFUSE_PUBLIC_KEY - For tracing
        LANGFUSE_SECRET_KEY - For tracing
        LANGFUSE_HOST - Custom Langfuse host (default: cloud.langfuse.com)

External Tools (optional, enhance scanning):
    - nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    - sqlmap: pip install sqlmap
    - dalfox: go install github.com/hahwul/dalfox/v2@latest
    - wapiti: pip install wapiti3
    - nikto: brew install nikto (macOS) or apt-get install nikto (Linux)
"""

from vibe_code_bench.red_team_agent.agent import RedTeamAgent, scan
from vibe_code_bench.red_team_agent.models import (
    ScanReport,
    VulnerabilityFinding,
    ToolResult,
    Severity,
)
from vibe_code_bench.red_team_agent.exceptions import (
    RedTeamError,
    ConfigurationError,
    ToolNotAvailableError,
    ToolExecutionError,
    AgentError,
    ScanError,
    ValidationError,
)

__all__ = [
    # Main API
    "RedTeamAgent",
    "scan",
    # Models
    "ScanReport",
    "VulnerabilityFinding",
    "ToolResult",
    "Severity",
    # Exceptions
    "RedTeamError",
    "ConfigurationError",
    "ToolNotAvailableError",
    "ToolExecutionError",
    "AgentError",
    "ScanError",
    "ValidationError",
]

__version__ = "2.0.0"
