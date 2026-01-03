"""Nikto web server scanner wrapper.

Nikto is a web server scanner for security issues.
Install: brew install nikto (macOS) or apt-get install nikto (Linux)
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
)
from vibe_code_bench.red_team_agent.exceptions import ToolExecutionError


class NiktoTool(BaseTool):
    """Nikto web server scanner."""
    
    name = "nikto"
    install_hint = "brew install nikto (macOS) or apt-get install nikto (Linux)"
    
    def __init__(self, required: bool = False, timeout: int = 300):
        """Initialize Nikto tool.
        
        Args:
            required: If True, raise error if not available
            timeout: Scan timeout in seconds
        """
        super().__init__(required=required)
        self.timeout = timeout
    
    def check_available(self) -> bool:
        """Check if nikto is installed."""
        return self._check_command_available("nikto")
    
    def _scan_impl(self, url: str, **kwargs) -> list[VulnerabilityFinding]:
        """Run Nikto scan.
        
        Args:
            url: Target URL
            tuning: Nikto tuning options
            
        Returns:
            List of findings
        """
        findings = []
        
        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = Path(f.name)
        
        try:
            # Build command
            cmd = [
                "nikto",
                "-h", url,
                "-Format", "json",
                "-output", str(output_file),
                "-nointeractive",
            ]
            
            # Add tuning if provided
            tuning = kwargs.get("tuning")
            if tuning:
                cmd.extend(["-Tuning", tuning])
            
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            
            # Parse JSON output
            if output_file.exists() and output_file.stat().st_size > 0:
                try:
                    with open(output_file) as f:
                        data = json.load(f)
                    
                    # Nikto JSON structure
                    if isinstance(data, dict):
                        vulnerabilities = data.get("vulnerabilities", [])
                        for vuln in vulnerabilities:
                            finding = self._parse_nikto_vuln(vuln, url)
                            if finding:
                                findings.append(finding)
                        
                        # Also check host items
                        host = data.get("host", {})
                        items = host.get("items", [])
                        for item in items:
                            finding = self._parse_nikto_item(item, url)
                            if finding:
                                findings.append(finding)
                    
                    elif isinstance(data, list):
                        for item in data:
                            finding = self._parse_nikto_vuln(item, url)
                            if finding:
                                findings.append(finding)
                
                except json.JSONDecodeError as e:
                    self.logger.debug(f"Error parsing nikto JSON: {e}")
            
            # Fallback: parse text output
            if not findings and result.stdout:
                findings = self._parse_nikto_text(result.stdout, url)
            
            return findings
            
        except subprocess.TimeoutExpired:
            raise ToolExecutionError(self.name, f"Scan timed out after {self.timeout}s")
        except subprocess.CalledProcessError as e:
            raise ToolExecutionError(self.name, f"Process error: {e}", e.stderr)
        finally:
            # Cleanup
            if output_file.exists():
                output_file.unlink()
    
    def _parse_nikto_vuln(self, vuln: dict, default_url: str) -> VulnerabilityFinding | None:
        """Parse a Nikto vulnerability into a VulnerabilityFinding."""
        try:
            vuln_id = vuln.get("id", vuln.get("OSVDB", ""))
            method = vuln.get("method", "")
            uri = vuln.get("url", vuln.get("uri", ""))
            description = vuln.get("msg", vuln.get("description", ""))
            
            if not description:
                return None
            
            # Determine vulnerability type from description
            vuln_type = self._classify_nikto_vuln(description)
            
            # Build full URL
            affected_url = f"{default_url.rstrip('/')}{uri}" if uri else default_url
            
            return VulnerabilityFinding(
                vulnerability_type=vuln_type,
                severity=Severity.MEDIUM,
                url=affected_url,
                description=description,
                proof_of_concept=f"OSVDB: {vuln_id}" if vuln_id else "",
                remediation="Review server configuration and update software",
                owasp_category=get_owasp_category(vuln_type),
                tool=self.name,
                raw_output=vuln,
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse nikto vuln: {e}")
            return None
    
    def _parse_nikto_item(self, item: dict, default_url: str) -> VulnerabilityFinding | None:
        """Parse a Nikto host item into a VulnerabilityFinding."""
        try:
            description = item.get("description", "")
            uri = item.get("uri", "")
            osvdb = item.get("osvdbid", "")
            
            if not description:
                return None
            
            vuln_type = self._classify_nikto_vuln(description)
            affected_url = f"{default_url.rstrip('/')}{uri}" if uri else default_url
            
            return VulnerabilityFinding(
                vulnerability_type=vuln_type,
                severity=Severity.MEDIUM,
                url=affected_url,
                description=description,
                proof_of_concept=f"OSVDB: {osvdb}" if osvdb else "",
                remediation="Review server configuration and update software",
                owasp_category=get_owasp_category(vuln_type),
                tool=self.name,
                raw_output=item,
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse nikto item: {e}")
            return None
    
    def _parse_nikto_text(self, output: str, default_url: str) -> list[VulnerabilityFinding]:
        """Parse Nikto text output as fallback."""
        findings = []
        
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            
            # Look for finding lines (usually start with +)
            if line.startswith("+"):
                line = line[1:].strip()
                
                vuln_type = self._classify_nikto_vuln(line)
                
                findings.append(VulnerabilityFinding(
                    vulnerability_type=vuln_type,
                    severity=Severity.MEDIUM,
                    url=default_url,
                    description=line,
                    proof_of_concept="",
                    remediation="Review server configuration",
                    owasp_category=get_owasp_category(vuln_type),
                    tool=self.name,
                    raw_output={"text": line},
                ))
        
        return findings
    
    def _classify_nikto_vuln(self, description: str) -> str:
        """Classify Nikto finding into vulnerability type."""
        desc_lower = description.lower()
        
        if "xss" in desc_lower or "cross-site scripting" in desc_lower:
            return "Cross-Site Scripting (XSS)"
        elif "sql" in desc_lower:
            return "SQL Injection"
        elif "directory" in desc_lower or "listing" in desc_lower:
            return "Information Disclosure"
        elif "backup" in desc_lower:
            return "Information Disclosure"
        elif "header" in desc_lower:
            return "Security Misconfiguration"
        elif "outdated" in desc_lower or "version" in desc_lower:
            return "Security Misconfiguration"
        elif "ssl" in desc_lower or "tls" in desc_lower or "https" in desc_lower:
            return "Weak Cryptography"
        else:
            return "Security Misconfiguration"
