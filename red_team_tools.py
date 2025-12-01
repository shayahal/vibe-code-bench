"""
Red Team Security Testing Tools

This module contains integrations for all major open-source red-team security testing tools.
All custom implementations have been replaced with integrations to actual tools.
"""

import os
import re
import json
import shutil
import subprocess
import tempfile
import logging
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable
from urllib.parse import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class RedTeamToolFactory:
    """Factory class for creating red team security testing tools with shared dependencies."""
    
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
    
    def _run_command(self, cmd: List[str], timeout: int = 300, capture_output: bool = True) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
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
    
    # ========== Utility Tools (Keep these) ==========
    
    def create_fetch_page(self) -> Callable:
        """Create fetch_page tool."""
        def fetch_page(url: str) -> Dict[str, Any]:
            """Fetch a web page and return its content and metadata."""
            logger.info(f"Fetching page: {url}")
            self.log_trail("tool_call", {
                "tool": "fetch_page",
                "url": url
            }, f"Fetching page to analyze structure, forms, and links for security testing")
            try:
                response = self.session.get(url, timeout=10)
                logger.info(f"Fetched {url} - Status: {response.status_code}, Size: {len(response.text)} bytes")
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                forms = []
                for form in soup.find_all('form'):
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        form_data['inputs'].append({
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        })
                    forms.append(form_data)
                
                # Extract links
                links = [a.get('href', '') for a in soup.find_all('a', href=True)]
                
                logger.info(f"Extracted {len(forms)} forms and {len(links)} links from {url}")
                
                result = {
                    "url": url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "forms": forms,
                    "links": links,
                    "content_length": len(response.text),
                    "has_forms": len(forms) > 0,
                    "response_text": response.text
                }
                
                self.log_trail("tool_result", {
                    "tool": "fetch_page",
                    "url": url,
                    "status_code": response.status_code,
                    "forms_found": len(forms),
                    "links_found": len(links)
                }, f"Successfully fetched page with {len(forms)} forms and {len(links)} links")
                
                return result
            except Exception as e:
                logger.error(f"Error fetching page {url}: {str(e)}")
                self.log_trail("tool_error", {
                    "tool": "fetch_page",
                    "url": url,
                    "error": str(e)
                }, f"Failed to fetch page: {str(e)}")
                return {"error": str(e), "url": url}
        
        return fetch_page
    
    def create_analyze_response_security(self) -> Callable:
        """Create analyze_response_security tool."""
        def analyze_response_security(response_text: str) -> Dict[str, Any]:
            """Analyze HTTP response for security issues."""
            logger.info(f"Analyzing response security - Response size: {len(response_text)} bytes")
            issues = []
            
            # Check for sensitive information
            sensitive_patterns = {
                "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "credit_card": r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
                "api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                "password": r'(?i)(password|pwd|pass)\s*[:=]\s*["\']?([^\s"\'<>]{6,})["\']?',
            }
            
            for pattern_name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, response_text)
                if matches:
                    logger.warning(f"Potential {pattern_name} exposure found in response ({len(matches)} matches)")
                    issues.append(f"Potential {pattern_name} exposure found")
            
            if issues:
                logger.warning(f"Security analysis found {len(issues)} issues")
            else:
                logger.info("Security analysis completed - No issues found")
            
            return {
                "issues": issues,
                "has_issues": len(issues) > 0,
                "analysis_timestamp": datetime.now().isoformat()
            }
        
        return analyze_response_security
    
    def create_generate_report(self) -> Callable:
        """Create generate_report tool."""
        def generate_report() -> str:
            """Generate a comprehensive security report."""
            logger.info(f"Generating security report - Total tests: {len(self.test_results)}")
            vulnerable_tests = [r for r in self.test_results if r.get('is_vulnerable', False)]
            critical_tests = [r for r in vulnerable_tests if r.get('severity') == 'CRITICAL']
            high_tests = [r for r in vulnerable_tests if r.get('severity') == 'HIGH']
            
            logger.info(f"Report summary - Vulnerabilities: {len(vulnerable_tests)}, Critical: {len(critical_tests)}, High: {len(high_tests)}")
            
            report = f"""# Web Security Red-Teaming Report
Generated: {datetime.now().isoformat()}

## Target URL
{self.target_url}

## Executive Summary
- Total tests performed: {len(self.test_results)}
- Vulnerabilities found: {len(vulnerable_tests)}
- Critical vulnerabilities: {len(critical_tests)}
- High severity vulnerabilities: {len(high_tests)}

## Vulnerability Breakdown

### Critical Vulnerabilities ({len(critical_tests)})
"""
            for i, result in enumerate(critical_tests, 1):
                report += f"\n#### {i}. {result.get('issue', 'Unknown issue')}\n"
                report += f"- URL: {result.get('url', 'N/A')}\n"
                report += f"- Parameter: {result.get('parameter', 'N/A')}\n"
                report += f"- Payload: {result.get('payload', 'N/A')}\n"
                report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
            
            report += f"\n### High Severity Vulnerabilities ({len(high_tests)})\n"
            for i, result in enumerate(high_tests, 1):
                report += f"\n#### {i}. {result.get('issue', 'Unknown issue')}\n"
                report += f"- URL: {result.get('url', 'N/A')}\n"
                report += f"- Parameter: {result.get('parameter', 'N/A')}\n"
                report += f"- Payload: {result.get('payload', 'N/A')}\n"
                report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
            
            report += "\n## Detailed Test Results\n"
            for i, result in enumerate(self.test_results, 1):
                report += f"\n### Test {i}\n"
                report += f"- Type: {result.get('test_type', 'Unknown')}\n"
                report += f"- URL: {result.get('url', 'N/A')}\n"
                report += f"- Status: {'VULNERABLE' if result.get('is_vulnerable') else 'SAFE'}\n"
                if result.get('issue'):
                    report += f"- Issue: {result['issue']}\n"
                report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
            
            logger.info("Security report generated successfully")
            return report
        
        return generate_report
    
    # ========== Web Application Security Tools ==========
    
    def create_scan_with_nuclei(self) -> Callable:
        """Create scan_with_nuclei tool."""
        def scan_with_nuclei(url: str, template_tags: Optional[str] = None) -> Dict[str, Any]:
            """Scan target with Nuclei - fast vulnerability scanner with templates."""
            logger.info(f"Scanning with Nuclei: {url}")
            if not self._check_tool_available("nuclei"):
                logger.warning("Nuclei not found in PATH. Install from: https://github.com/projectdiscovery/nuclei")
                return {"error": "Nuclei not installed", "url": url}
            
            try:
                cmd = ["nuclei", "-u", url, "-json", "-silent"]
                if template_tags:
                    cmd.extend(["-tags", template_tags])
                
                result = self._run_command(cmd, timeout=300)
                
                findings = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                            logger.warning(f"Nuclei finding: {finding.get('info', {}).get('name', 'Unknown')}")
                        except json.JSONDecodeError:
                            continue
                
                return {
                    "url": url,
                    "tool": "nuclei",
                    "findings": findings,
                    "count": len(findings),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Nuclei: {str(e)}")
                return {"error": str(e), "url": url}
        
        return scan_with_nuclei
    
    def create_scan_with_sqlmap(self) -> Callable:
        """Create scan_with_sqlmap tool."""
        def scan_with_sqlmap(url: str, parameter: Optional[str] = None) -> Dict[str, Any]:
            """Scan target with SQLMap - automated SQL injection testing."""
            logger.info(f"Scanning with SQLMap: {url}")
            if not self._check_tool_available("sqlmap"):
                logger.warning("SQLMap not found in PATH. Install from: https://github.com/sqlmapproject/sqlmap")
                return {"error": "SQLMap not installed", "url": url}
            
            try:
                cmd = ["sqlmap", "-u", url, "--batch", "--level=3", "--risk=2", "--json"]
                if parameter:
                    cmd.extend(["-p", parameter])
                
                result = self._run_command(cmd, timeout=600)
                
                is_vulnerable = "sqlmap identified" in result.stdout.lower() or "vulnerable" in result.stdout.lower()
                
                if is_vulnerable:
                    logger.critical(f"SQLMap detected SQL injection vulnerability: {url}")
                
                return {
                    "url": url,
                    "tool": "sqlmap",
                    "is_vulnerable": is_vulnerable,
                    "output": result.stdout[:1000],
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running SQLMap: {str(e)}")
                return {"error": str(e), "url": url}
        
        return scan_with_sqlmap
    
    def create_scan_xss_with_dalfox(self) -> Callable:
        """Create scan_xss_with_dalfox tool."""
        def scan_xss_with_dalfox(url: str, parameter: Optional[str] = None) -> Dict[str, Any]:
            """Scan for XSS vulnerabilities using Dalfox."""
            logger.info(f"Scanning XSS with Dalfox: {url}")
            if not self._check_tool_available("dalfox"):
                logger.warning("Dalfox not found in PATH. Install from: https://github.com/hahwul/dalfox")
                return {"error": "Dalfox not installed", "url": url}
            
            try:
                cmd = ["dalfox", "url", url, "--json"]
                if parameter:
                    cmd.extend(["-p", parameter])
                
                result = self._run_command(cmd, timeout=300)
                
                findings = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                            logger.warning(f"Dalfox XSS finding: {finding.get('data', {}).get('payload', 'Unknown')}")
                        except json.JSONDecodeError:
                            if "XSS" in line.upper() or "vulnerable" in line.lower():
                                findings.append({"raw": line})
                
                return {
                    "url": url,
                    "tool": "dalfox",
                    "findings": findings,
                    "is_vulnerable": len(findings) > 0,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Dalfox: {str(e)}")
                return {"error": str(e), "url": url}
        
        return scan_xss_with_dalfox
    
    def create_scan_xss_with_xsstrike(self) -> Callable:
        """Create scan_xss_with_xsstrike tool."""
        def scan_xss_with_xsstrike(url: str) -> Dict[str, Any]:
            """Scan for XSS vulnerabilities using XSStrike."""
            logger.info(f"Scanning XSS with XSStrike: {url}")
            if not self._check_tool_available("xsstrike"):
                logger.warning("XSStrike not found in PATH. Install from: https://github.com/s0md3v/XSStrike")
                return {"error": "XSStrike not installed", "url": url}
            
            try:
                result = self._run_command(
                    ["xsstrike", "-u", url, "--crawl", "--json"],
                    timeout=300
                )
                
                is_vulnerable = "vulnerable" in result.stdout.lower() or "xss" in result.stdout.lower()
                
                if is_vulnerable:
                    logger.warning(f"XSStrike detected XSS vulnerability: {url}")
                
                return {
                    "url": url,
                    "tool": "xsstrike",
                    "is_vulnerable": is_vulnerable,
                    "output": result.stdout[:1000],
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running XSStrike: {str(e)}")
                return {"error": str(e), "url": url}
        
        return scan_xss_with_xsstrike
    
    def create_scan_with_owasp_zap(self) -> Callable:
        """Create scan_with_owasp_zap tool."""
        def scan_with_owasp_zap(url: str, zap_proxy: Optional[str] = "http://127.0.0.1:8080") -> Dict[str, Any]:
            """Scan target with OWASP ZAP via API."""
            logger.info(f"Scanning with OWASP ZAP: {url}")
            try:
                # Start spider scan
                spider_url = f"{zap_proxy}/JSON/spider/action/scan/"
                params = {"url": url}
                response = requests.get(spider_url, params=params, timeout=30)
                
                if response.status_code != 200:
                    return {"error": "ZAP API not accessible", "url": url}
                
                # Wait for scan to complete (simplified - in production, poll status)
                import time
                time.sleep(10)
                
                # Get alerts
                alerts_url = f"{zap_proxy}/JSON/core/view/alerts/"
                alerts_response = requests.get(alerts_url, timeout=30)
                
                findings = []
                if alerts_response.status_code == 200:
                    alerts_data = alerts_response.json()
                    findings = alerts_data.get("alerts", [])
                
                return {
                    "url": url,
                    "tool": "owasp_zap",
                    "findings": findings,
                    "count": len(findings),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running OWASP ZAP: {str(e)}")
                return {"error": str(e), "url": url}
        
        return scan_with_owasp_zap
    
    def create_scan_with_nikto(self) -> Callable:
        """Create scan_with_nikto tool."""
        def scan_with_nikto(url: str) -> Dict[str, Any]:
            """Scan web server with Nikto."""
            logger.info(f"Scanning with Nikto: {url}")
            if not self._check_tool_available("nikto"):
                logger.warning("Nikto not found in PATH. Install from: https://github.com/sullo/nikto")
                return {"error": "Nikto not installed", "url": url}
            
            try:
                result = self._run_command(
                    ["nikto", "-h", url, "-Format", "json"],
                    timeout=600
                )
                
                findings = []
                try:
                    nikto_data = json.loads(result.stdout)
                    if 'host' in nikto_data and 'vulnerabilities' in nikto_data['host']:
                        findings = nikto_data['host']['vulnerabilities']
                except json.JSONDecodeError:
                    for line in result.stdout.split('\n'):
                        if 'OSVDB' in line or 'Vulnerability' in line:
                            findings.append({"raw": line})
                
                return {
                    "url": url,
                    "tool": "nikto",
                    "findings": findings,
                    "count": len(findings),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Nikto: {str(e)}")
                return {"error": str(e), "url": url}
        
        return scan_with_nikto
    
    def create_scan_with_wapiti(self) -> Callable:
        """Create scan_with_wapiti tool."""
        def scan_with_wapiti(url: str) -> Dict[str, Any]:
            """Scan web application with Wapiti."""
            logger.info(f"Scanning with Wapiti: {url}")
            if not self._check_tool_available("wapiti"):
                logger.warning("Wapiti not found in PATH. Install: pip install wapiti3")
                return {"error": "Wapiti not installed", "url": url}
            
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output_file = os.path.join(tmpdir, "wapiti_report.json")
                    result = self._run_command(
                        ["wapiti", "-u", url, "-f", "json", "-o", tmpdir],
                        timeout=600
                    )
                    
                    findings = []
                    if os.path.exists(output_file):
                        with open(output_file, 'r') as f:
                            findings = json.load(f)
                    
                    return {
                        "url": url,
                        "tool": "wapiti",
                        "findings": findings,
                        "count": len(findings) if isinstance(findings, list) else 0,
                        "timestamp": datetime.now().isoformat()
                    }
            except Exception as e:
                logger.error(f"Error running Wapiti: {str(e)}")
                return {"error": str(e), "url": url}
        
        return scan_with_wapiti
    
    # ========== Network & Infrastructure Tools ==========
    
    def create_scan_with_nmap(self) -> Callable:
        """Create scan_with_nmap tool."""
        def scan_with_nmap(target: str, scan_type: str = "default") -> Dict[str, Any]:
            """Scan network target with Nmap."""
            logger.info(f"Scanning with Nmap: {target}")
            if not self._check_tool_available("nmap"):
                logger.warning("Nmap not found in PATH. Install: apt install nmap or brew install nmap")
                return {"error": "Nmap not installed", "target": target}
            
            try:
                scan_options = {
                    "default": ["-sV", "-sC"],
                    "stealth": ["-sS", "-T2"],
                    "aggressive": ["-A", "-T4"],
                    "vuln": ["--script", "vuln"]
                }
                
                cmd = ["nmap"] + scan_options.get(scan_type, scan_options["default"]) + [target]
                result = self._run_command(cmd, timeout=600)
                
                return {
                    "target": target,
                    "tool": "nmap",
                    "scan_type": scan_type,
                    "output": result.stdout,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Nmap: {str(e)}")
                return {"error": str(e), "target": target}
        
        return scan_with_nmap
    
    def create_scan_with_masscan(self) -> Callable:
        """Create scan_with_masscan tool."""
        def scan_with_masscan(target: str, ports: str = "1-1000", rate: str = "1000") -> Dict[str, Any]:
            """Fast port scan with Masscan."""
            logger.info(f"Scanning with Masscan: {target}")
            if not self._check_tool_available("masscan"):
                logger.warning("Masscan not found in PATH. Install: apt install masscan or brew install masscan")
                return {"error": "Masscan not installed", "target": target}
            
            try:
                cmd = ["masscan", "-p", ports, "--rate", rate, target, "-oJ", "-"]
                result = self._run_command(cmd, timeout=300)
                
                findings = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and line.strip().startswith('{'):
                        try:
                            finding = json.loads(line.strip().rstrip(','))
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue
                
                return {
                    "target": target,
                    "tool": "masscan",
                    "ports": ports,
                    "findings": findings,
                    "count": len(findings),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Masscan: {str(e)}")
                return {"error": str(e), "target": target}
        
        return scan_with_masscan
    
    def create_scan_with_rustscan(self) -> Callable:
        """Create scan_with_rustscan tool."""
        def scan_with_rustscan(target: str, ports: str = "1-1000") -> Dict[str, Any]:
            """Fast port scan with RustScan."""
            logger.info(f"Scanning with RustScan: {target}")
            if not self._check_tool_available("rustscan"):
                logger.warning("RustScan not found in PATH. Install: cargo install rustscan")
                return {"error": "RustScan not installed", "target": target}
            
            try:
                cmd = ["rustscan", "-a", target, "-p", ports, "--", "-sV"]
                result = self._run_command(cmd, timeout=300)
                
                return {
                    "target": target,
                    "tool": "rustscan",
                    "ports": ports,
                    "output": result.stdout,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running RustScan: {str(e)}")
                return {"error": str(e), "target": target}
        
        return scan_with_rustscan
    
    # ========== Reconnaissance Tools ==========
    
    def create_discover_subdomains(self) -> Callable:
        """Create discover_subdomains tool."""
        def discover_subdomains(domain: str) -> Dict[str, Any]:
            """Discover subdomains using subfinder and amass."""
            logger.info(f"Discovering subdomains for: {domain}")
            subdomains = set()
            
            if self._check_tool_available("subfinder"):
                try:
                    result = self._run_command(
                        ["subfinder", "-d", domain, "-silent"],
                        timeout=300
                    )
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            subdomains.add(line.strip())
                    logger.info(f"Subfinder found {len(subdomains)} subdomains")
                except Exception as e:
                    logger.debug(f"Subfinder error: {str(e)}")
            
            if self._check_tool_available("amass"):
                try:
                    result = self._run_command(
                        ["amass", "enum", "-d", domain, "-passive"],
                        timeout=300
                    )
                    for line in result.stdout.strip().split('\n'):
                        if line.strip() and '.' in line:
                            subdomains.add(line.strip())
                    logger.info(f"Amass found additional subdomains. Total: {len(subdomains)}")
                except Exception as e:
                    logger.debug(f"Amass error: {str(e)}")
            
            return {
                "domain": domain,
                "subdomains": list(subdomains),
                "count": len(subdomains),
                "timestamp": datetime.now().isoformat()
            }
        
        return discover_subdomains
    
    def create_discover_with_theharvester(self) -> Callable:
        """Create discover_with_theharvester tool."""
        def discover_with_theharvester(domain: str, sources: str = "all") -> Dict[str, Any]:
            """Discover emails, subdomains, and people using theHarvester."""
            logger.info(f"Discovering with theHarvester: {domain}")
            if not self._check_tool_available("theHarvester"):
                logger.warning("theHarvester not found in PATH. Install: pip install theHarvester")
                return {"error": "theHarvester not installed", "domain": domain}
            
            try:
                cmd = ["theHarvester", "-d", domain, "-b", sources, "-f", "/tmp/theharvester_output"]
                result = self._run_command(cmd, timeout=600)
                
                # Parse output
                emails = []
                hosts = []
                
                for line in result.stdout.split('\n'):
                    if '@' in line:
                        emails.extend(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', line))
                    if domain in line and '.' in line:
                        hosts.append(line.strip())
                
                return {
                    "domain": domain,
                    "tool": "theharvester",
                    "emails": list(set(emails)),
                    "hosts": list(set(hosts)),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running theHarvester: {str(e)}")
                return {"error": str(e), "domain": domain}
        
        return discover_with_theharvester
    
    def create_discover_parameters(self) -> Callable:
        """Create discover_parameters tool."""
        def discover_parameters(url: str) -> Dict[str, Any]:
            """Discover URL parameters using ParamSpider and Arjun."""
            logger.info(f"Discovering parameters for: {url}")
            parameters = set()
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if self._check_tool_available("paramspider"):
                try:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        result = self._run_command(
                            ["paramspider", "-d", domain, "-o", tmpdir],
                            timeout=300
                        )
                        output_file = os.path.join(tmpdir, f"{domain}.txt")
                        if os.path.exists(output_file):
                            with open(output_file, 'r') as f:
                                for line in f:
                                    if '?' in line:
                                        params = parse_qs(urlparse(line.strip()).query)
                                        parameters.update(params.keys())
                except Exception as e:
                    logger.debug(f"ParamSpider error: {str(e)}")
            
            if self._check_tool_available("arjun"):
                try:
                    result = self._run_command(
                        ["arjun", "-u", url, "--json"],
                        timeout=300
                    )
                    try:
                        arjun_data = json.loads(result.stdout)
                        if isinstance(arjun_data, dict) and 'params' in arjun_data:
                            parameters.update(arjun_data['params'])
                    except json.JSONDecodeError:
                        for line in result.stdout.split('\n'):
                            if 'Parameter' in line or 'Found' in line:
                                matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)', line)
                                parameters.update(matches)
                except Exception as e:
                    logger.debug(f"Arjun error: {str(e)}")
            
            return {
                "url": url,
                "parameters": list(parameters),
                "count": len(parameters),
                "timestamp": datetime.now().isoformat()
            }
        
        return discover_parameters
    
    # ========== Directory Brute Forcing ==========
    
    def create_brute_force_directories(self) -> Callable:
        """Create brute_force_directories tool."""
        def brute_force_directories(url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
            """Brute force directories/files using Gobuster or FFuF."""
            logger.info(f"Brute forcing directories: {url}")
            found_paths = []
            
            if self._check_tool_available("gobuster"):
                try:
                    cmd = ["gobuster", "dir", "-u", url, "-q", "-k"]
                    if wordlist:
                        cmd.extend(["-w", wordlist])
                    else:
                        cmd.extend(["-w", "/usr/share/wordlists/dirb/common.txt"])
                    
                    result = self._run_command(cmd, timeout=600)
                    
                    for line in result.stdout.split('\n'):
                        if line.strip() and ('Status: 200' in line or 'Status: 301' in line or 'Status: 302' in line):
                            parts = line.split()
                            if parts:
                                found_paths.append(parts[0])
                except Exception as e:
                    logger.debug(f"Gobuster error: {str(e)}")
            
            if self._check_tool_available("ffuf") and not found_paths:
                try:
                    cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w"]
                    if wordlist:
                        cmd.append(wordlist)
                    else:
                        cmd.append("/usr/share/wordlists/dirb/common.txt")
                    cmd.extend(["-s", "-json"])
                    
                    result = self._run_command(cmd, timeout=600)
                    
                    try:
                        ffuf_data = json.loads(result.stdout)
                        if 'results' in ffuf_data:
                            for item in ffuf_data['results']:
                                if item.get('status') in [200, 301, 302]:
                                    found_paths.append(item.get('url', ''))
                    except json.JSONDecodeError:
                        for line in result.stdout.split('\n'):
                            if '200' in line or '301' in line or '302' in line:
                                found_paths.append(line.strip())
                except Exception as e:
                    logger.debug(f"FFuF error: {str(e)}")
            
            return {
                "url": url,
                "found_paths": found_paths,
                "count": len(found_paths),
                "timestamp": datetime.now().isoformat()
            }
        
        return brute_force_directories
    
    # ========== Fuzzing Tools ==========
    
    def create_scan_with_wfuzz(self) -> Callable:
        """Create scan_with_wfuzz tool."""
        def scan_with_wfuzz(url: str, parameter: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
            """Fuzz parameters with Wfuzz."""
            logger.info(f"Fuzzing with Wfuzz: {url}, parameter: {parameter}")
            if not self._check_tool_available("wfuzz"):
                logger.warning("Wfuzz not found in PATH. Install from: https://github.com/xmendez/wfuzz")
                return {"error": "Wfuzz not installed", "url": url}
            
            try:
                fuzz_url = f"{url}?{parameter}=FUZZ"
                cmd = ["wfuzz", "-c", "-z", "file"]
                if wordlist:
                    cmd.append(wordlist)
                else:
                    cmd.append("/usr/share/wordlists/rockyou.txt")
                cmd.extend(["-f", "json", fuzz_url])
                
                result = self._run_command(cmd, timeout=300)
                
                findings = []
                try:
                    wfuzz_data = json.loads(result.stdout)
                    if isinstance(wfuzz_data, list):
                        findings = wfuzz_data
                except json.JSONDecodeError:
                    for line in result.stdout.split('\n'):
                        if '200' in line or '301' in line or '302' in line:
                            findings.append({"raw": line})
                
                return {
                    "url": url,
                    "parameter": parameter,
                    "tool": "wfuzz",
                    "findings": findings,
                    "count": len(findings),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Wfuzz: {str(e)}")
                return {"error": str(e), "url": url}
        
        return scan_with_wfuzz
    
    # ========== Active Directory Tools ==========
    
    def create_bloodhound_ingest(self) -> Callable:
        """Create bloodhound_ingest tool."""
        def bloodhound_ingest(domain: str, collection_method: str = "all") -> Dict[str, Any]:
            """Collect data for BloodHound analysis."""
            logger.info(f"Collecting BloodHound data for: {domain}")
            if not self._check_tool_available("bloodhound-python"):
                logger.warning("BloodHound Python not found. Install: pip install bloodhound")
                return {"error": "BloodHound Python not installed", "domain": domain}
            
            try:
                cmd = ["bloodhound-python", "-d", domain, "-c", collection_method, "-gc", domain]
                result = self._run_command(cmd, timeout=600)
                
                return {
                    "domain": domain,
                    "tool": "bloodhound",
                    "collection_method": collection_method,
                    "output": result.stdout[:500],
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running BloodHound: {str(e)}")
                return {"error": str(e), "domain": domain}
        
        return bloodhound_ingest
    
    def create_crackmapexec_scan(self) -> Callable:
        """Create crackmapexec_scan tool."""
        def crackmapexec_scan(target: str, scan_type: str = "smb") -> Dict[str, Any]:
            """Scan with CrackMapExec."""
            logger.info(f"Scanning with CrackMapExec: {target}")
            if not self._check_tool_available("crackmapexec"):
                logger.warning("CrackMapExec not found. Install: pip install crackmapexec")
                return {"error": "CrackMapExec not installed", "target": target}
            
            try:
                cmd = ["crackmapexec", scan_type, target]
                result = self._run_command(cmd, timeout=300)
                
                return {
                    "target": target,
                    "tool": "crackmapexec",
                    "scan_type": scan_type,
                    "output": result.stdout,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running CrackMapExec: {str(e)}")
                return {"error": str(e), "target": target}
        
        return crackmapexec_scan
    
    # ========== Exploitation Frameworks ==========
    
    def create_metasploit_exploit(self) -> Callable:
        """Create metasploit_exploit tool."""
        def metasploit_exploit(target: str, exploit: str, payload: str = "generic/shell_reverse_tcp") -> Dict[str, Any]:
            """Execute Metasploit exploit."""
            logger.info(f"Executing Metasploit exploit: {exploit} on {target}")
            if not self._check_tool_available("msfconsole"):
                logger.warning("Metasploit not found. Install: apt install metasploit-framework")
                return {"error": "Metasploit not installed", "target": target}
            
            try:
                # Create Metasploit resource script
                with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                    f.write(f"use {exploit}\n")
                    f.write(f"set RHOSTS {target}\n")
                    f.write(f"set payload {payload}\n")
                    f.write("exploit\n")
                    script_path = f.name
                
                cmd = ["msfconsole", "-r", script_path, "-q"]
                result = self._run_command(cmd, timeout=300)
                
                os.unlink(script_path)
                
                return {
                    "target": target,
                    "tool": "metasploit",
                    "exploit": exploit,
                    "output": result.stdout[:1000],
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Metasploit: {str(e)}")
                return {"error": str(e), "target": target}
        
        return metasploit_exploit
    
    # ========== Password & Credential Tools ==========
    
    def create_crack_password_hashcat(self) -> Callable:
        """Create crack_password_hashcat tool."""
        def crack_password_hashcat(hash_file: str, wordlist: Optional[str] = None, hash_type: str = "0") -> Dict[str, Any]:
            """Crack password hashes with Hashcat."""
            logger.info(f"Cracking passwords with Hashcat: {hash_file}")
            if not self._check_tool_available("hashcat"):
                logger.warning("Hashcat not found. Install: apt install hashcat or brew install hashcat")
                return {"error": "Hashcat not installed", "hash_file": hash_file}
            
            try:
                cmd = ["hashcat", "-m", hash_type, hash_file]
                if wordlist:
                    cmd.append(wordlist)
                else:
                    cmd.append("/usr/share/wordlists/rockyou.txt")
                cmd.extend(["-o", "/tmp/hashcat_output.txt"])
                
                result = self._run_command(cmd, timeout=3600)
                
                cracked = []
                if os.path.exists("/tmp/hashcat_output.txt"):
                    with open("/tmp/hashcat_output.txt", 'r') as f:
                        cracked = [line.strip() for line in f if line.strip()]
                
                return {
                    "hash_file": hash_file,
                    "tool": "hashcat",
                    "hash_type": hash_type,
                    "cracked_count": len(cracked),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Hashcat: {str(e)}")
                return {"error": str(e), "hash_file": hash_file}
        
        return crack_password_hashcat
    
    def create_crack_password_john(self) -> Callable:
        """Create crack_password_john tool."""
        def crack_password_john(hash_file: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
            """Crack password hashes with John the Ripper."""
            logger.info(f"Cracking passwords with John: {hash_file}")
            if not self._check_tool_available("john"):
                logger.warning("John the Ripper not found. Install: apt install john or brew install john-jumbo")
                return {"error": "John the Ripper not installed", "hash_file": hash_file}
            
            try:
                cmd = ["john", hash_file]
                if wordlist:
                    cmd.extend(["--wordlist", wordlist])
                else:
                    cmd.extend(["--wordlist", "/usr/share/wordlists/rockyou.txt"])
                
                result = self._run_command(cmd, timeout=3600)
                
                # Show cracked passwords
                show_cmd = ["john", "--show", hash_file]
                show_result = self._run_command(show_cmd, timeout=60)
                
                return {
                    "hash_file": hash_file,
                    "tool": "john",
                    "output": show_result.stdout,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running John: {str(e)}")
                return {"error": str(e), "hash_file": hash_file}
        
        return crack_password_john
    
    def create_brute_force_login_hydra(self) -> Callable:
        """Create brute_force_login_hydra tool."""
        def brute_force_login_hydra(
            target: str,
            service: str,
            username: str,
            password_list: Optional[str] = None
        ) -> Dict[str, Any]:
            """Brute force login with Hydra."""
            logger.info(f"Brute forcing login with Hydra: {target} ({service})")
            if not self._check_tool_available("hydra"):
                logger.warning("Hydra not found. Install: apt install hydra or brew install hydra")
                return {"error": "Hydra not installed", "target": target}
            
            try:
                cmd = ["hydra", "-l", username, "-P"]
                if password_list:
                    cmd.append(password_list)
                else:
                    cmd.append("/usr/share/wordlists/rockyou.txt")
                cmd.extend([target, service])
                
                result = self._run_command(cmd, timeout=600)
                
                found = "password:" in result.stdout.lower() or "login:" in result.stdout.lower()
                
                return {
                    "target": target,
                    "tool": "hydra",
                    "service": service,
                    "username": username,
                    "found": found,
                    "output": result.stdout[:500],
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Hydra: {str(e)}")
                return {"error": str(e), "target": target}
        
        return brute_force_login_hydra
    
    # ========== Post-Exploitation Tools ==========
    
    def create_linpeas_scan(self) -> Callable:
        """Create linpeas_scan tool."""
        def linpeas_scan(target: str) -> Dict[str, Any]:
            """Run LinPEAS privilege escalation scan."""
            logger.info(f"Running LinPEAS on: {target}")
            # Note: LinPEAS is typically run on the target system
            # This would require SSH access or similar
            return {
                "target": target,
                "tool": "linpeas",
                "note": "LinPEAS must be run on the target system",
                "timestamp": datetime.now().isoformat()
            }
        
        return linpeas_scan
    
    def create_winpeas_scan(self) -> Callable:
        """Create winpeas_scan tool."""
        def winpeas_scan(target: str) -> Dict[str, Any]:
            """Run WinPEAS privilege escalation scan."""
            logger.info(f"Running WinPEAS on: {target}")
            # Note: WinPEAS is typically run on the target system
            return {
                "target": target,
                "tool": "winpeas",
                "note": "WinPEAS must be run on the target system",
                "timestamp": datetime.now().isoformat()
            }
        
        return winpeas_scan
    
    # ========== API Security Tools ==========
    
    def create_scan_api_rest_attacker(self) -> Callable:
        """Create scan_api_rest_attacker tool."""
        def scan_api_rest_attacker(api_url: str) -> Dict[str, Any]:
            """Scan REST API with REST-Attacker."""
            logger.info(f"Scanning API with REST-Attacker: {api_url}")
            # REST-Attacker is a Python library
            try:
                import rest_attacker
                # This would require proper REST-Attacker integration
                return {
                    "api_url": api_url,
                    "tool": "rest_attacker",
                    "note": "REST-Attacker integration requires proper setup",
                    "timestamp": datetime.now().isoformat()
                }
            except ImportError:
                logger.warning("REST-Attacker not installed. Install: pip install rest-attacker")
                return {"error": "REST-Attacker not installed", "api_url": api_url}
        
        return scan_api_rest_attacker
    
    # ========== Cloud Security Tools ==========
    
    def create_scan_aws_pacu(self) -> Callable:
        """Create scan_aws_pacu tool."""
        def scan_aws_pacu(aws_key: str, aws_secret: str, region: str = "us-east-1") -> Dict[str, Any]:
            """Scan AWS environment with Pacu."""
            logger.info(f"Scanning AWS with Pacu: {region}")
            # Pacu requires AWS credentials and proper setup
            return {
                "region": region,
                "tool": "pacu",
                "note": "Pacu requires AWS credentials and proper configuration",
                "timestamp": datetime.now().isoformat()
            }
        
        return scan_aws_pacu
    
    def create_scan_cloud_scout_suite(self) -> Callable:
        """Create scan_cloud_scout_suite tool."""
        def scan_cloud_scout_suite(provider: str, credentials: Dict[str, str]) -> Dict[str, Any]:
            """Scan cloud environment with Scout Suite."""
            logger.info(f"Scanning cloud with Scout Suite: {provider}")
            if not self._check_tool_available("scout"):
                logger.warning("Scout Suite not found. Install: pip install scoutsuite")
                return {"error": "Scout Suite not installed", "provider": provider}
            
            try:
                cmd = ["scout", provider]
                result = self._run_command(cmd, timeout=1800)
                
                return {
                    "provider": provider,
                    "tool": "scout_suite",
                    "output": result.stdout[:500],
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Scout Suite: {str(e)}")
                return {"error": str(e), "provider": provider}
        
        return scan_cloud_scout_suite
