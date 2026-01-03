"""Base class for security scanning tools."""

import shutil
import time
from abc import ABC, abstractmethod
from typing import Any

from vibe_code_bench.red_team_agent.models import VulnerabilityFinding, ToolResult
from vibe_code_bench.red_team_agent.exceptions import ToolNotAvailableError, ToolExecutionError
from vibe_code_bench.red_team_agent.observability import get_logger


class BaseTool(ABC):
    """Base class for all security scanning tools.
    
    All tools must implement:
    - name: Tool identifier
    - check_available(): Check if tool is installed
    - _scan_impl(): Actual scanning logic
    """
    
    name: str = "base"
    install_hint: str = ""
    
    def __init__(self, required: bool = False):
        """Initialize tool.
        
        Args:
            required: If True, raise error if tool not available.
                     If False, tool is optional and will be skipped if not available.
        """
        self.logger = get_logger(f"vibe_code_bench.red_team_agent.tools.{self.name}")
        self.required = required
        self._available: bool | None = None
    
    @property
    def available(self) -> bool:
        """Check if tool is available (cached)."""
        if self._available is None:
            self._available = self.check_available()
            if self._available:
                self.logger.debug(f"Tool '{self.name}' is available")
            else:
                self.logger.debug(f"Tool '{self.name}' is not available")
        return self._available
    
    @abstractmethod
    def check_available(self) -> bool:
        """Check if the tool is installed and available.
        
        Returns:
            True if available, False otherwise
        """
        pass
    
    @abstractmethod
    def _scan_impl(self, url: str, **kwargs) -> list[VulnerabilityFinding]:
        """Implementation of the actual scanning logic.
        
        Args:
            url: Target URL to scan
            **kwargs: Tool-specific options
            
        Returns:
            List of vulnerability findings
            
        Raises:
            ToolExecutionError: If scan fails
        """
        pass
    
    def scan(self, url: str, **kwargs) -> ToolResult:
        """Run the tool against a target URL.
        
        Args:
            url: Target URL to scan
            **kwargs: Tool-specific options
            
        Returns:
            ToolResult with findings
            
        Raises:
            ToolNotAvailableError: If required tool is not available
            ToolExecutionError: If scan fails
        """
        # Check availability
        if not self.available:
            if self.required:
                raise ToolNotAvailableError(self.name, self.install_hint)
            else:
                self.logger.info(f"Tool '{self.name}' not available, skipping")
                return ToolResult(
                    tool_name=self.name,
                    target_url=url,
                    success=False,
                    error_message=f"Tool not available. {self.install_hint}",
                )
        
        self.logger.info(f"[SCAN] {self.name} | Starting | url={url}")
        start_time = time.time()
        
        try:
            findings = self._scan_impl(url, **kwargs)
            execution_time = (time.time() - start_time) * 1000
            
            self.logger.info(
                f"[SCAN] {self.name} | Complete | findings={len(findings)} | time={execution_time:.0f}ms"
            )
            
            return ToolResult(
                tool_name=self.name,
                target_url=url,
                success=True,
                findings=findings,
                execution_time_ms=execution_time,
            )
            
        except ToolExecutionError:
            # Re-raise tool execution errors
            raise
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            self.logger.error(f"[SCAN] {self.name} | Error | {e}")
            raise ToolExecutionError(self.name, str(e)) from e
    
    def _check_command_available(self, command: str) -> bool:
        """Check if a command is available in PATH.
        
        Args:
            command: Command name to check
            
        Returns:
            True if command is available
        """
        return shutil.which(command) is not None
    
    def _ensure_go_bin_in_path(self) -> None:
        """Ensure Go bin directory is in PATH for Go-based tools."""
        import os
        path = os.environ.get("PATH", "")
        go_bin = os.path.expanduser("~/go/bin")
        if os.path.exists(go_bin) and go_bin not in path:
            os.environ["PATH"] = f"{path}:{go_bin}"


class ToolRegistry:
    """Registry of available security tools."""
    
    _tools: dict[str, BaseTool] = {}
    
    @classmethod
    def register(cls, tool: BaseTool) -> None:
        """Register a tool."""
        cls._tools[tool.name] = tool
    
    @classmethod
    def get(cls, name: str) -> BaseTool | None:
        """Get a tool by name."""
        return cls._tools.get(name)
    
    @classmethod
    def get_available_tools(cls) -> list[BaseTool]:
        """Get all available tools."""
        return [t for t in cls._tools.values() if t.available]
    
    @classmethod
    def get_all_tools(cls) -> list[BaseTool]:
        """Get all registered tools."""
        return list(cls._tools.values())
    
    @classmethod
    def list_available(cls) -> list[str]:
        """List names of available tools."""
        return [t.name for t in cls._tools.values() if t.available]
    
    @classmethod
    def list_unavailable(cls) -> list[str]:
        """List names of unavailable tools."""
        return [t.name for t in cls._tools.values() if not t.available]
