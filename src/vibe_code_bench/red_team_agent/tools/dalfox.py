"""DalFox XSS scanner wrapper.

DalFox is a powerful XSS scanning and parameter analysis tool.
Install: go install github.com/hahwul/dalfox/v2@latest
"""

import json
import subprocess

from vibe_code_bench.red_team_agent.tools.base import BaseTool
from vibe_code_bench.red_team_agent.models import (
    VulnerabilityFinding,
    Severity,
    get_owasp_category,
)
from vibe_code_bench.red_team_agent.exceptions import ToolExecutionError


class DalFoxTool(BaseTool):
    """DalFox XSS scanner."""
    
    name = "dalfox"
    install_hint = "go install github.com/hahwul/dalfox/v2@latest"
    
    def __init__(self, required: bool = False, timeout: int = 120):
        """Initialize DalFox tool.
        
        Args:
            required: If True, raise error if not available
            timeout: Scan timeout in seconds
        """
        super().__init__(required=required)
        self.timeout = timeout
        self._ensure_go_bin_in_path()
    
    def check_available(self) -> bool:
        """Check if dalfox is installed."""
        return self._check_command_available("dalfox")
    
    def _scan_impl(self, url: str, **kwargs) -> list[VulnerabilityFinding]:
        """Run DalFox XSS scan.
        
        Args:
            url: Target URL
            method: HTTP method (GET or POST)
            data: POST data if method is POST
            
        Returns:
            List of findings
        """
        findings = []
        
        # Build command
        cmd = [
            "dalfox",
            "url", url,
            "--format", "json",
            "--silence",
            "--no-color",
        ]
        
        # Add method and data if POST
        method = kwargs.get("method", "GET").upper()
        if method == "POST":
            data = kwargs.get("data")
            if data:
                cmd.extend(["--data", data])
        
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            
            # Parse JSON output
            if result.stdout:
                try:
                    # DalFox may output multiple JSON objects
                    for line in result.stdout.strip().split("\n"):
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            finding = self._parse_dalfox_result(data, url)
                            if finding:
                                findings.append(finding)
                        except json.JSONDecodeError:
                            # Try parsing the entire output as JSON
                            pass
                    
                    # Try parsing entire output as single JSON
                    if not findings:
                        try:
                            data = json.loads(result.stdout)
                            if isinstance(data, dict):
                                finding = self._parse_dalfox_result(data, url)
                                if finding:
                                    findings.append(finding)
                            elif isinstance(data, list):
                                for item in data:
                                    finding = self._parse_dalfox_result(item, url)
                                    if finding:
                                        findings.append(finding)
                        except json.JSONDecodeError:
                            pass
                
                except Exception as e:
                    self.logger.debug(f"Error parsing dalfox output: {e}")
            
            # Check stderr for findings too
            if not findings and "found reflected" in result.stdout.lower():
                # Basic XSS found but couldn't parse JSON
                findings.append(VulnerabilityFinding(
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    severity=Severity.HIGH,
                    url=url,
                    description="XSS vulnerability detected by DalFox",
                    proof_of_concept=result.stdout[:500],
                    remediation="Sanitize and encode all user input before rendering. Implement Content Security Policy.",
                    cwe_id=79,
                    owasp_category=get_owasp_category("XSS"),
                    tool=self.name,
                    raw_output={"stdout": result.stdout[:1000]},
                ))
            
            return findings
            
        except subprocess.TimeoutExpired:
            raise ToolExecutionError(self.name, f"Scan timed out after {self.timeout}s")
        except subprocess.CalledProcessError as e:
            raise ToolExecutionError(self.name, f"Process error: {e}", e.stderr)
    
    def _parse_dalfox_result(self, data: dict, default_url: str) -> VulnerabilityFinding | None:
        """Parse a DalFox JSON result into a VulnerabilityFinding."""
        try:
            # DalFox output structure varies
            if not data:
                return None
            
            # Check if this is a finding
            poc = data.get("poc", data.get("PoC", ""))
            if not poc:
                # Check for data array
                if "data" in data and isinstance(data["data"], list):
                    for item in data["data"]:
                        poc = item.get("poc", item.get("PoC", ""))
                        if poc:
                            break
            
            if not poc:
                return None
            
            # Determine XSS type
            xss_type = "Reflected XSS"
            if "dom" in str(data).lower():
                xss_type = "DOM-based XSS"
            elif "stored" in str(data).lower():
                xss_type = "Stored XSS"
            
            return VulnerabilityFinding(
                vulnerability_type="Cross-Site Scripting (XSS)",
                severity=Severity.HIGH,
                url=data.get("url", default_url),
                description=f"{xss_type} vulnerability detected by DalFox",
                proof_of_concept=poc[:500],
                remediation="Sanitize and encode all user input before rendering. Implement Content Security Policy.",
                cwe_id=79,
                owasp_category=get_owasp_category("XSS"),
                tool=self.name,
                raw_output=data,
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse dalfox result: {e}")
            return None
