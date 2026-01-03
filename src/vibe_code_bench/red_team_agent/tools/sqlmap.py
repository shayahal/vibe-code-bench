"""SQLMap SQL injection scanner wrapper.

SQLMap is an automatic SQL injection and database takeover tool.
Install: pip install sqlmap
"""

import subprocess
import tempfile
from pathlib import Path

from vibe_code_bench.red_team_agent.tools.base import BaseTool
from vibe_code_bench.red_team_agent.models import (
    VulnerabilityFinding,
    Severity,
    get_owasp_category,
)
from vibe_code_bench.red_team_agent.exceptions import ToolExecutionError


class SQLMapTool(BaseTool):
    """SQLMap SQL injection scanner."""
    
    name = "sqlmap"
    install_hint = "pip install sqlmap"
    
    def __init__(self, required: bool = False, timeout: int = 300):
        """Initialize SQLMap tool.
        
        Args:
            required: If True, raise error if not available
            timeout: Scan timeout in seconds
        """
        super().__init__(required=required)
        self.timeout = timeout
    
    def check_available(self) -> bool:
        """Check if sqlmap is installed."""
        return self._check_command_available("sqlmap")
    
    def _scan_impl(self, url: str, **kwargs) -> list[VulnerabilityFinding]:
        """Run SQLMap scan.
        
        Args:
            url: Target URL (should contain parameters to test)
            data: POST data if testing POST request
            level: Scan level (1-5, default 3)
            risk: Risk level (1-3, default 2)
            
        Returns:
            List of findings
        """
        findings = []
        
        # Create temp directory for output
        with tempfile.TemporaryDirectory() as output_dir:
            # Build command
            cmd = [
                "sqlmap",
                "-u", url,
                "--batch",  # Non-interactive mode
                "--level", str(kwargs.get("level", 3)),
                "--risk", str(kwargs.get("risk", 2)),
                "--output-dir", output_dir,
            ]
            
            # Add POST data if provided
            data = kwargs.get("data")
            if data:
                cmd.extend(["--data", data])
            
            # Limit scan time
            cmd.extend(["--timeout", str(min(30, self.timeout // 10))])
            
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                
                output = result.stdout.lower()
                
                # Check for SQL injection indicators
                injection_indicators = [
                    "parameter.*is vulnerable",
                    "sqlmap identified the following injection",
                    "injectable",
                    "sql injection",
                ]
                
                found_sqli = any(indicator in output for indicator in injection_indicators)
                
                if found_sqli:
                    # Extract more details from output
                    details = self._extract_sqli_details(result.stdout)
                    
                    finding = VulnerabilityFinding(
                        vulnerability_type="SQL Injection",
                        severity=Severity.CRITICAL,
                        url=url,
                        description="SQL injection vulnerability confirmed by SQLMap",
                        proof_of_concept=details.get("poc", result.stdout[:500]),
                        remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
                        cwe_id=89,
                        owasp_category=get_owasp_category("SQL Injection"),
                        tool=self.name,
                        raw_output={
                            "stdout": result.stdout[:2000],
                            "return_code": result.returncode,
                            "injection_type": details.get("type", "unknown"),
                        },
                    )
                    findings.append(finding)
                
                return findings
                
            except subprocess.TimeoutExpired:
                raise ToolExecutionError(self.name, f"Scan timed out after {self.timeout}s")
            except subprocess.CalledProcessError as e:
                raise ToolExecutionError(self.name, f"Process error: {e}", e.stderr)
    
    def _extract_sqli_details(self, output: str) -> dict:
        """Extract SQL injection details from SQLMap output."""
        details = {}
        
        # Try to extract injection type
        output_lower = output.lower()
        if "boolean-based blind" in output_lower:
            details["type"] = "boolean-based blind"
        elif "time-based blind" in output_lower:
            details["type"] = "time-based blind"
        elif "error-based" in output_lower:
            details["type"] = "error-based"
        elif "union" in output_lower:
            details["type"] = "UNION-based"
        elif "stacked queries" in output_lower:
            details["type"] = "stacked queries"
        
        # Try to extract proof of concept
        lines = output.split("\n")
        for i, line in enumerate(lines):
            if "payload:" in line.lower():
                details["poc"] = line.strip()
                break
        
        return details
    
    def scan_form(
        self,
        url: str,
        form_data: dict[str, str] | None = None,
        method: str = "GET"
    ) -> list[VulnerabilityFinding]:
        """Scan a form for SQL injection.
        
        Args:
            url: Form action URL
            form_data: Form field names and sample values
            method: HTTP method (GET or POST)
            
        Returns:
            List of findings
        """
        # Build URL with parameters for GET
        if method.upper() == "GET" and form_data:
            params = "&".join(f"{k}={v}" for k, v in form_data.items())
            full_url = f"{url}?{params}" if "?" not in url else f"{url}&{params}"
            return self._scan_impl(full_url)
        
        # POST request
        elif method.upper() == "POST" and form_data:
            data = "&".join(f"{k}={v}" for k, v in form_data.items())
            return self._scan_impl(url, data=data)
        
        # No form data, just scan URL
        return self._scan_impl(url)
