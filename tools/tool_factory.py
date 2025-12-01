"""
Red Team Tool Factory

This module provides the base factory class for creating red team security testing tools.
The factory manages shared dependencies (session, test results, logging) across all tools.
"""

import shutil
import subprocess
import logging
from typing import Dict, Any, Optional, List, Callable
import requests

logger = logging.getLogger(__name__)


class RedTeamToolFactory:
    """
    Factory class for creating red team security testing tools with shared dependencies.
    
    This factory pattern allows all tools to share:
    - HTTP session for consistent request handling
    - Test results storage for centralized reporting
    - Logging trail for audit purposes
    - Headers and cookies for authenticated sessions
    """
    
    def __init__(
        self,
        session: requests.Session,
        test_results: List[Dict[str, Any]],
        target_url: str,
        headers: Dict[str, str],
        cookies: Dict[str, str],
        log_trail: Optional[Callable] = None
    ):
        """
        Initialize the tool factory with shared dependencies.
        
        Args:
            session: Requests session for HTTP operations
            test_results: List to append test results to
            target_url: Target URL for testing
            headers: HTTP headers to use
            cookies: Cookies to use
            log_trail: Optional logging function
        """
        self.session = session
        self.test_results = test_results
        self.target_url = target_url
        self.headers = headers
        self.cookies = cookies
        self.log_trail = log_trail or (lambda *args, **kwargs: None)
    
    def _check_tool_available(self, tool_name: str) -> bool:
        """Check if a command-line tool is available in PATH."""
        return shutil.which(tool_name) is not None
    
    def _run_command(self, cmd: List[str], timeout: int = 20, capture_output: bool = True) -> subprocess.CompletedProcess:
        """
        Run a command and return the result.
        
        Args:
            cmd: Command to run as list of strings
            timeout: Timeout in seconds
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            CompletedProcess object with result
        """
        try:
            return subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                check=False
            )
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(cmd)}")
            raise
        except Exception as e:
            logger.error(f"Error running command {' '.join(cmd)}: {str(e)}")
            raise

