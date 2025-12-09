"""Integration with external security tools (nuclei, dalfox, sqlmap, etc.)."""

import json
import logging
import subprocess
import shutil
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

from vibe_code_bench.red_team_agent.models import VulnerabilityFinding, SecurityTestResult
from vibe_code_bench.red_team_agent.utils import classify_severity, get_owasp_category
from vibe_code_bench.red_team_agent.logging_config import get_logger

logger = get_logger(__name__)


class ToolIntegration:
    """Integration with external security scanning tools."""

    def __init__(self):
        """Initialize tool integration."""
        self.logger = get_logger(f"{__name__}.ToolIntegration")
        self.available_tools = self._check_available_tools()

    def _check_available_tools(self) -> Dict[str, bool]:
        """
        Check which external tools are available.

        Returns:
            Dictionary mapping tool names to availability
        """
        tools = {
            "nuclei": False,
            "dalfox": False,
            "sqlmap": False,
            "wapiti3": False,
            "nikto": False,
        }

        for tool_name in tools.keys():
            if shutil.which(tool_name):
                tools[tool_name] = True
                self.logger.info(f"[SETUP] {tool_name} is available")
            else:
                self.logger.debug(f"[SETUP] {tool_name} is not available")

        return tools

    def run_nuclei(self, urls: List[str], output_file: Optional[Path] = None) -> List[SecurityTestResult]:
        """
        Run nuclei vulnerability scanner on URLs.

        Args:
            urls: List of URLs to scan
            output_file: Optional output file path

        Returns:
            List of SecurityTestResult objects
        """
        if not self.available_tools.get("nuclei", False):
            self.logger.warning("[TOOL] nuclei not available, skipping")
            return []

        self.logger.info(f"[TOOL] nuclei - Scanning {len(urls)} URLs - Started")

        results = []
        start_time = 0

        try:
            # Create temporary output file
            if output_file is None:
                import tempfile
                output_file = Path(tempfile.mktemp(suffix=".json"))

            # Run nuclei
            cmd = [
                "nuclei",
                "-u", ",".join(urls),
                "-json",
                "-o", str(output_file),
                "-silent",
            ]

            start_time = time.time()
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            # Parse nuclei JSON output
            if output_file.exists():
                with open(output_file, "r") as f:
                    for line in f:
                        if line.strip():
                            try:
                                nuclei_result = json.loads(line)
                                finding = VulnerabilityFinding(
                                    vulnerability_type=nuclei_result.get("info", {}).get("name", "Unknown"),
                                    severity=nuclei_result.get("info", {}).get("severity", "info").capitalize(),
                                    affected_url=nuclei_result.get("matched-at", ""),
                                    description=nuclei_result.get("info", {}).get("description", ""),
                                    proof_of_concept=nuclei_result.get("matched-at", ""),
                                    remediation="Review and fix the identified vulnerability",
                                    cwe_id=nuclei_result.get("info", {}).get("classification", {}).get("cwe-id", [None])[0],
                                    owasp_category=get_owasp_category(nuclei_result.get("info", {}).get("name", "")),
                                    test_type="nuclei",
                                    additional_info=nuclei_result,
                                )

                                result = SecurityTestResult(
                                    test_type="nuclei",
                                    target_url=nuclei_result.get("matched-at", ""),
                                    status="vulnerable",
                                    findings=[finding],
                                )
                                results.append(result)

                                self.logger.warning(
                                    f"[FINDING] {finding.vulnerability_type} - {finding.severity} - {finding.affected_url}"
                                )
                            except json.JSONDecodeError:
                                continue

            execution_time = time.time() - start_time
            self.logger.info(f"[TOOL] nuclei - Completed - Findings: {len(results)} - Time: {execution_time:.2f}s")

        except subprocess.TimeoutExpired:
            self.logger.error("[ERROR] nuclei scan timed out")
        except Exception as e:
            self.logger.error(f"[ERROR] nuclei scan failed: {e}")

        return results

    def run_dalfox(self, urls: List[str]) -> List[SecurityTestResult]:
        """
        Run dalfox XSS scanner on URLs.

        Args:
            urls: List of URLs to scan

        Returns:
            List of SecurityTestResult objects
        """
        if not self.available_tools.get("dalfox", False):
            self.logger.warning("[TOOL] dalfox not available, skipping")
            return []

        self.logger.info(f"[TOOL] dalfox - Scanning {len(urls)} URLs - Started")

        results = []

        for url in urls:
            try:
                cmd = ["dalfox", "url", url, "--format", "json"]

                process = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                # Parse dalfox output
                if process.stdout:
                    try:
                        dalfox_result = json.loads(process.stdout)
                        if dalfox_result.get("data"):
                            for finding_data in dalfox_result["data"]:
                                finding = VulnerabilityFinding(
                                    vulnerability_type="XSS",
                                    severity=classify_severity("XSS"),
                                    affected_url=finding_data.get("url", url),
                                    description=f"XSS vulnerability found: {finding_data.get('poc', '')}",
                                    proof_of_concept=finding_data.get("poc", ""),
                                    remediation="Sanitize and validate all user input, use Content Security Policy",
                                    cwe_id=79,
                                    owasp_category=get_owasp_category("XSS"),
                                    test_type="dalfox",
                                    additional_info=finding_data,
                                )

                                result = SecurityTestResult(
                                    test_type="dalfox",
                                    target_url=url,
                                    status="vulnerable",
                                    findings=[finding],
                                )
                                results.append(result)

                                self.logger.warning(
                                    f"[FINDING] XSS - {classify_severity('XSS')} - {url}"
                                )
                    except json.JSONDecodeError:
                        pass

            except subprocess.TimeoutExpired:
                self.logger.warning(f"[TOOL] dalfox scan timed out for {url}")
            except Exception as e:
                self.logger.error(f"[ERROR] dalfox scan failed for {url}: {e}")

        self.logger.info(f"[TOOL] dalfox - Completed - Findings: {len(results)}")

        return results

    def run_sqlmap(self, form_info: Dict[str, Any]) -> Optional[SecurityTestResult]:
        """
        Run sqlmap on a form for deep SQL injection testing.

        Args:
            form_info: Form information dictionary

        Returns:
            SecurityTestResult if vulnerability found, None otherwise
        """
        if not self.available_tools.get("sqlmap", False):
            self.logger.warning("[TOOL] sqlmap not available, skipping")
            return None

        url = form_info.get("url", "")
        action = form_info.get("action", "")
        method = form_info.get("method", "get").lower()
        fields = form_info.get("fields", [])

        self.logger.info(f"[TOOL] sqlmap - Testing {url} - Started")

        try:
            # Build sqlmap command
            form_url = urljoin(url, action) if action else url

            cmd = ["sqlmap", "-u", form_url, "--batch", "--level", "3", "--risk", "2"]

            if method == "post":
                # Build POST data
                data_parts = []
                for field in fields:
                    field_name = field.get("name", "")
                    if field_name:
                        data_parts.append(f"{field_name}=test")
                if data_parts:
                    cmd.extend(["--data", "&".join(data_parts)])

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse sqlmap output
            if "sqlmap identified the following injection point" in process.stdout.lower():
                finding = VulnerabilityFinding(
                    vulnerability_type="SQL Injection",
                    severity="Critical",
                    affected_url=form_url,
                    description="SQL injection vulnerability confirmed by sqlmap",
                    proof_of_concept=process.stdout[:500],
                    remediation="Use parameterized queries or prepared statements",
                    cwe_id=89,
                    owasp_category=get_owasp_category("SQL Injection"),
                    test_type="sqlmap",
                )

                result = SecurityTestResult(
                    test_type="sqlmap",
                    target_url=form_url,
                    status="vulnerable",
                    findings=[finding],
                )

                self.logger.warning(f"[FINDING] SQL Injection - Critical - {form_url}")
                return result

        except subprocess.TimeoutExpired:
            self.logger.warning(f"[TOOL] sqlmap scan timed out for {url}")
        except Exception as e:
            self.logger.error(f"[ERROR] sqlmap scan failed: {e}")

        return None

    def run_wapiti3(self, base_url: str, output_file: Optional[Path] = None) -> List[SecurityTestResult]:
        """
        Run wapiti3 comprehensive web application scanner.

        Args:
            base_url: Base URL to scan
            output_file: Optional output file path

        Returns:
            List of SecurityTestResult objects
        """
        if not self.available_tools.get("wapiti3", False):
            self.logger.warning("[TOOL] wapiti3 not available, skipping")
            return []

        self.logger.info(f"[TOOL] wapiti3 - Scanning {base_url} - Started")

        results = []

        try:
            # Create temporary output file
            if output_file is None:
                import tempfile
                output_file = Path(tempfile.mktemp(suffix=".json"))

            cmd = [
                "wapiti",
                "-u", base_url,
                "-f", "json",
                "-o", str(output_file.parent),
            ]

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )

            # Parse wapiti3 JSON output
            json_file = output_file.parent / f"{base_url.replace('://', '_').replace('/', '_')}.json"
            if json_file.exists():
                with open(json_file, "r") as f:
                    wapiti_data = json.load(f)
                    vulnerabilities = wapiti_data.get("vulnerabilities", [])

                    for vuln in vulnerabilities:
                        finding = VulnerabilityFinding(
                            vulnerability_type=vuln.get("name", "Unknown"),
                            severity=vuln.get("severity", "info").capitalize(),
                            affected_url=vuln.get("url", base_url),
                            description=vuln.get("description", ""),
                            proof_of_concept=vuln.get("parameter", ""),
                            remediation="Review and fix the identified vulnerability",
                            cwe_id=vuln.get("cwe", None),
                            owasp_category=get_owasp_category(vuln.get("name", "")),
                            test_type="wapiti3",
                            additional_info=vuln,
                        )

                        result = SecurityTestResult(
                            test_type="wapiti3",
                            target_url=vuln.get("url", base_url),
                            status="vulnerable",
                            findings=[finding],
                        )
                        results.append(result)

                        self.logger.warning(
                            f"[FINDING] {finding.vulnerability_type} - {finding.severity} - {finding.affected_url}"
                        )

            self.logger.info(f"[TOOL] wapiti3 - Completed - Findings: {len(results)}")

        except subprocess.TimeoutExpired:
            self.logger.error("[ERROR] wapiti3 scan timed out")
        except Exception as e:
            self.logger.error(f"[ERROR] wapiti3 scan failed: {e}")

        return results

    def run_nikto(self, base_url: str) -> List[SecurityTestResult]:
        """
        Run nikto web server scanner.

        Args:
            base_url: Base URL to scan

        Returns:
            List of SecurityTestResult objects
        """
        if not self.available_tools.get("nikto", False):
            self.logger.warning("[TOOL] nikto not available, skipping")
            return []

        self.logger.info(f"[TOOL] nikto - Scanning {base_url} - Started")

        results = []

        try:
            cmd = ["nikto", "-h", base_url, "-Format", "json", "-output", "-"]

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Parse nikto JSON output
            if process.stdout:
                try:
                    nikto_data = json.loads(process.stdout)
                    for item in nikto_data:
                        finding = VulnerabilityFinding(
                            vulnerability_type=item.get("OSVDB", {}).get("title", "Server Vulnerability"),
                            severity="Medium",
                            affected_url=base_url,
                            description=item.get("description", ""),
                            proof_of_concept=item.get("uri", ""),
                            remediation="Review and fix server configuration",
                            test_type="nikto",
                            additional_info=item,
                        )

                        result = SecurityTestResult(
                            test_type="nikto",
                            target_url=base_url,
                            status="vulnerable",
                            findings=[finding],
                        )
                        results.append(result)

                        self.logger.warning(
                            f"[FINDING] {finding.vulnerability_type} - Medium - {base_url}"
                        )
                except json.JSONDecodeError:
                    pass

            self.logger.info(f"[TOOL] nikto - Completed - Findings: {len(results)}")

        except subprocess.TimeoutExpired:
            self.logger.error("[ERROR] nikto scan timed out")
        except Exception as e:
            self.logger.error(f"[ERROR] nikto scan failed: {e}")

        return results
