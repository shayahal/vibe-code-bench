"""Wapiti web vulnerability scanner wrapper.

Wapiti is a comprehensive web application vulnerability scanner.
Install: pip install wapiti3
"""

import json
import subprocess
import tempfile
from pathlib import Path

from vibe_code_bench.red_team_agent.tools.base import BaseTool
from vibe_code_bench.red_team_agent.models import (
    VulnerabilityFinding,
    Severity,
    get_owasp_category,
    get_cwe_id,
)
from vibe_code_bench.red_team_agent.exceptions import ToolExecutionError


class WapitiTool(BaseTool):
    """Wapiti web vulnerability scanner."""
    
    name = "wapiti"
    install_hint = "pip install wapiti3"
    
    def __init__(self, required: bool = False, timeout: int = 600):
        """Initialize Wapiti tool.
        
        Args:
            required: If True, raise error if not available
            timeout: Scan timeout in seconds (default 10 min as wapiti can be slow)
        """
        super().__init__(required=required)
        self.timeout = timeout
    
    def check_available(self) -> bool:
        """Check if wapiti is installed.
        
        Note: wapiti3 package installs as 'wapiti' command.
        """
        return self._check_command_available("wapiti")
    
    def _scan_impl(self, url: str, **kwargs) -> list[VulnerabilityFinding]:
        """Run Wapiti scan.
        
        Args:
            url: Target URL
            modules: List of modules to run (e.g., ["sql", "xss", "file"])
            
        Returns:
            List of findings
        """
        findings = []
        
        # Create temp directory for output
        with tempfile.TemporaryDirectory() as output_dir:
            output_path = Path(output_dir)
            
            # Build command
            cmd = [
                "wapiti",
                "-u", url,
                "-f", "json",
                "-o", str(output_path),
                "--flush-session",
            ]
            
            # Add specific modules if provided
            modules = kwargs.get("modules")
            if modules:
                cmd.extend(["-m", ",".join(modules)])
            
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                
                # Find the JSON output file
                json_files = list(output_path.glob("*.json"))
                if not json_files:
                    # Try alternative naming patterns
                    json_files = list(output_path.glob("**/*.json"))
                
                for json_file in json_files:
                    try:
                        with open(json_file) as f:
                            data = json.load(f)
                        
                        # Parse Wapiti output
                        vulnerabilities = data.get("vulnerabilities", {})
                        for vuln_type, vuln_list in vulnerabilities.items():
                            if isinstance(vuln_list, list):
                                for vuln in vuln_list:
                                    finding = self._parse_wapiti_vuln(vuln_type, vuln, url)
                                    if finding:
                                        findings.append(finding)
                        
                        # Also check anomalies
                        anomalies = data.get("anomalies", {})
                        for anom_type, anom_list in anomalies.items():
                            if isinstance(anom_list, list):
                                for anom in anom_list:
                                    finding = self._parse_wapiti_vuln(anom_type, anom, url, is_anomaly=True)
                                    if finding:
                                        findings.append(finding)
                        
                    except (json.JSONDecodeError, KeyError) as e:
                        self.logger.debug(f"Error parsing wapiti output: {e}")
                
                return findings
                
            except subprocess.TimeoutExpired:
                raise ToolExecutionError(self.name, f"Scan timed out after {self.timeout}s")
            except subprocess.CalledProcessError as e:
                raise ToolExecutionError(self.name, f"Process error: {e}", e.stderr)
    
    def _parse_wapiti_vuln(
        self,
        vuln_type: str,
        vuln: dict,
        default_url: str,
        is_anomaly: bool = False
    ) -> VulnerabilityFinding | None:
        """Parse a Wapiti vulnerability into a VulnerabilityFinding."""
        try:
            # Map Wapiti vulnerability types to our types
            type_mapping = {
                "SQL Injection": "SQL Injection",
                "Blind SQL Injection": "SQL Injection",
                "Cross Site Scripting": "Cross-Site Scripting (XSS)",
                "XSS": "Cross-Site Scripting (XSS)",
                "CRLF Injection": "CRLF Injection",
                "Commands execution": "Command Injection",
                "File Handling": "Path Traversal",
                "Htaccess Bypass": "Security Misconfiguration",
                "Backup file": "Information Disclosure",
                "Open Redirect": "Open Redirect",
                "XXE": "XML External Entity",
                "SSRF": "Server-Side Request Forgery (SSRF)",
            }
            
            mapped_type = type_mapping.get(vuln_type, vuln_type)
            
            # Determine severity
            severity_str = vuln.get("level", "2")
            severity_map = {
                "1": Severity.LOW,
                "2": Severity.MEDIUM,
                "3": Severity.HIGH,
                "4": Severity.CRITICAL,
            }
            severity = severity_map.get(str(severity_str), Severity.MEDIUM)
            if is_anomaly:
                severity = Severity.INFO
            
            # Get URL
            affected_url = vuln.get("path", vuln.get("url", default_url))
            
            return VulnerabilityFinding(
                vulnerability_type=mapped_type,
                severity=severity,
                url=affected_url,
                description=vuln.get("info", f"Wapiti detected: {mapped_type}"),
                proof_of_concept=vuln.get("parameter", ""),
                remediation=vuln.get("solution", "Review and fix the identified vulnerability"),
                cwe_id=get_cwe_id(mapped_type),
                owasp_category=get_owasp_category(mapped_type),
                tool=self.name,
                raw_output=vuln,
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse wapiti result: {e}")
            return None
