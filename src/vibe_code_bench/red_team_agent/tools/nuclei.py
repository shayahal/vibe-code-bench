"""Nuclei vulnerability scanner wrapper.

Nuclei is a fast vulnerability scanner with extensive template library.
Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
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


class NucleiTool(BaseTool):
    """Nuclei vulnerability scanner."""
    
    name = "nuclei"
    install_hint = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    
    def __init__(self, required: bool = False, timeout: int = 300):
        """Initialize Nuclei tool.
        
        Args:
            required: If True, raise error if not available
            timeout: Scan timeout in seconds
        """
        super().__init__(required=required)
        self.timeout = timeout
        self._ensure_go_bin_in_path()
    
    def check_available(self) -> bool:
        """Check if nuclei is installed."""
        return self._check_command_available("nuclei")
    
    def _scan_impl(self, url: str, **kwargs) -> list[VulnerabilityFinding]:
        """Run nuclei scan.
        
        Args:
            url: Target URL
            severity: Optional severity filter (e.g., "critical,high")
            templates: Optional list of template paths
            
        Returns:
            List of findings
        """
        findings = []
        
        # Create temp file for output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = Path(f.name)
        
        try:
            # Build command
            cmd = [
                "nuclei",
                "-u", url,
                "-json-export", str(output_file),
                "-silent",
                "-no-color",
            ]
            
            # Optional severity filter
            severity = kwargs.get("severity")
            if severity:
                cmd.extend(["-severity", severity])
            
            # Optional templates
            templates = kwargs.get("templates")
            if templates:
                for template in templates:
                    cmd.extend(["-t", template])
            
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            
            # Run nuclei
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            
            # Parse output file
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            finding = self._parse_nuclei_result(data, url)
                            if finding:
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue
            
            # Also parse stdout for results
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        finding = self._parse_nuclei_result(data, url)
                        if finding:
                            # Avoid duplicates
                            if not any(f.url == finding.url and f.vulnerability_type == finding.vulnerability_type for f in findings):
                                findings.append(finding)
                    except json.JSONDecodeError:
                        continue
            
            return findings
            
        except subprocess.TimeoutExpired:
            raise ToolExecutionError(self.name, f"Scan timed out after {self.timeout}s")
        except subprocess.CalledProcessError as e:
            raise ToolExecutionError(self.name, f"Process error: {e}", e.stderr)
        finally:
            # Cleanup
            if output_file.exists():
                output_file.unlink()
    
    def _parse_nuclei_result(self, data: dict, default_url: str) -> VulnerabilityFinding | None:
        """Parse a nuclei JSON result into a VulnerabilityFinding."""
        try:
            info = data.get("info", {})
            
            # Get severity
            severity_str = info.get("severity", "info").lower()
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(severity_str, Severity.INFO)
            
            # Get vulnerability type from template name
            vuln_type = info.get("name", "Unknown Vulnerability")
            
            # Get affected URL
            affected_url = data.get("matched-at", data.get("host", default_url))
            
            # Get description
            description = info.get("description", "")
            if not description:
                description = f"Nuclei detected: {vuln_type}"
            
            # Get CWE
            classification = info.get("classification", {})
            cwe_ids = classification.get("cwe-id", [])
            cwe_id = None
            if cwe_ids and isinstance(cwe_ids, list) and len(cwe_ids) > 0:
                try:
                    cwe_id = int(str(cwe_ids[0]).replace("CWE-", ""))
                except (ValueError, TypeError):
                    pass
            
            # Get remediation
            remediation = info.get("remediation", "")
            if not remediation:
                remediation = "Review and fix the identified vulnerability"
            
            return VulnerabilityFinding(
                vulnerability_type=vuln_type,
                severity=severity,
                url=affected_url,
                description=description,
                proof_of_concept=data.get("matcher-name", ""),
                remediation=remediation,
                cwe_id=cwe_id,
                owasp_category=get_owasp_category(vuln_type),
                tool=self.name,
                raw_output=data,
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse nuclei result: {e}")
            return None
