"""Custom exceptions for the red team agent.

NO SILENT FAILURES - all errors must be raised and propagated.
"""


class RedTeamError(Exception):
    """Base exception for all red team agent errors."""

    def __init__(self, message: str, context: dict | None = None):
        self.message = message
        self.context = context or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.context:
            return f"{self.message} | Context: {self.context}"
        return self.message


class ConfigurationError(RedTeamError):
    """Raised when configuration is missing or invalid.
    
    Examples:
        - Missing API keys (OPENAI_API_KEY, LANGFUSE_SECRET_KEY)
        - Invalid configuration values
    """
    pass


class ToolNotAvailableError(RedTeamError):
    """Raised when a required tool is not available.
    
    Examples:
        - nuclei not installed
        - sqlmap not in PATH
    """
    
    def __init__(self, tool_name: str, install_hint: str | None = None):
        self.tool_name = tool_name
        self.install_hint = install_hint
        message = f"Tool '{tool_name}' is not available"
        if install_hint:
            message += f". Install with: {install_hint}"
        super().__init__(message, {"tool": tool_name})


class ToolExecutionError(RedTeamError):
    """Raised when a tool fails during execution.
    
    Examples:
        - Tool process returns non-zero exit code
        - Tool timeout
        - Tool output parsing failure
    """
    
    def __init__(self, tool_name: str, message: str, stderr: str | None = None):
        self.tool_name = tool_name
        self.stderr = stderr
        context = {"tool": tool_name}
        if stderr:
            context["stderr"] = stderr[:500]  # Truncate long stderr
        super().__init__(f"{tool_name}: {message}", context)


class AgentError(RedTeamError):
    """Raised when the LangGraph agent fails.
    
    Examples:
        - LLM API error
        - Agent loop exceeded max iterations
        - Invalid agent state
    """
    pass


class ScanError(RedTeamError):
    """Raised when a scan operation fails.
    
    Examples:
        - Target URL unreachable
        - Invalid URL format
        - Network timeout
    """
    
    def __init__(self, url: str, message: str):
        self.url = url
        super().__init__(message, {"url": url})


class ValidationError(RedTeamError):
    """Raised when input validation fails.
    
    Examples:
        - Invalid URL format
        - Missing required parameters
    """
    pass
