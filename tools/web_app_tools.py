"""
Web Application Security Tools

This module contains integrations for web application vulnerability scanners.
These tools replace custom implementations with industry-standard SOTA (State-of-the-Art) tools.

Tool Selection Rationale:
- Nuclei: Fast, template-based scanner with 10,000+ community templates. Chosen for speed and coverage.
- SQLMap: Industry standard for SQL injection testing. Most comprehensive SQLi tool available.
- Dalfox: Modern XSS scanner with advanced payload generation. Better than custom XSS testing.
- XSStrike: Advanced XSS detection with intelligent payload generation. Complements Dalfox.
- OWASP ZAP: Comprehensive web app scanner with active/passive scanning. Industry standard.
- Nikto: Web server vulnerability scanner. Excellent for finding server misconfigurations.
- Wapiti: Web vulnerability scanner focusing on injection flaws. Good complement to other tools.
"""

import json
import os
import tempfile
import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable
import requests

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_web_app_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register web application security tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_scan_with_nuclei():
        """
        Create scan_with_nuclei tool.
        
        Why Nuclei: Fast vulnerability scanner with 10,000+ community templates.
        Replaces custom vulnerability scanning with industry-standard tool.
        """
        def scan_with_nuclei(url: str, template_tags: Optional[str] = None) -> Dict[str, Any]:
            """Scan target with Nuclei - fast vulnerability scanner with templates."""
            logger.info(f"Scanning with Nuclei: {url}")
            if not factory._check_tool_available("nuclei"):
                logger.warning("Nuclei not found in PATH. Install from: https://github.com/projectdiscovery/nuclei")
                return {"error": "Nuclei not installed", "url": url}
            
            try:
                cmd = ["nuclei", "-u", url, "-json", "-silent"]
                if template_tags:
                    cmd.extend(["-tags", template_tags])
                
                result = factory._run_command(cmd, timeout=20)
                
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
    
    def create_scan_with_sqlmap():
        """
        Create scan_with_sqlmap tool.
        
        Why SQLMap: Industry standard for SQL injection testing. Most comprehensive SQLi tool.
        Replaces custom SQL injection payload crafting with automated testing.
        """
        def scan_with_sqlmap(url: str, parameter: Optional[str] = None) -> Dict[str, Any]:
            """Scan target with SQLMap - automated SQL injection testing."""
            logger.info(f"Scanning with SQLMap: {url}")
            if not factory._check_tool_available("sqlmap"):
                logger.warning("SQLMap not found in PATH. Install from: https://github.com/sqlmapproject/sqlmap")
                return {"error": "SQLMap not installed", "url": url}
            
            try:
                cmd = ["sqlmap", "-u", url, "--batch", "--level=3", "--risk=2", "--json"]
                if parameter:
                    cmd.extend(["-p", parameter])
                
                result = factory._run_command(cmd, timeout=20)
                
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
    
    def create_scan_xss_with_dalfox():
        """
        Create scan_xss_with_dalfox tool.
        
        Why Dalfox: Modern XSS scanner with advanced payload generation and DOM-based detection.
        Replaces custom XSS payload crafting with intelligent automated testing.
        """
        def scan_xss_with_dalfox(url: str, parameter: Optional[str] = None) -> Dict[str, Any]:
            """Scan for XSS vulnerabilities using Dalfox."""
            logger.info(f"Scanning XSS with Dalfox: {url}")
            if not factory._check_tool_available("dalfox"):
                logger.warning("Dalfox not found in PATH. Install from: https://github.com/hahwul/dalfox")
                return {"error": "Dalfox not installed", "url": url}
            
            try:
                cmd = ["dalfox", "url", url, "--json"]
                if parameter:
                    cmd.extend(["-p", parameter])
                
                result = factory._run_command(cmd, timeout=20)
                
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
    
    def create_scan_xss_with_xsstrike():
        """
        Create scan_xss_with_xsstrike tool.
        
        Why XSStrike: Advanced XSS detection with intelligent payload generation and WAF evasion.
        Complements Dalfox with different detection techniques.
        """
        def scan_xss_with_xsstrike(url: str) -> Dict[str, Any]:
            """Scan for XSS vulnerabilities using XSStrike."""
            logger.info(f"Scanning XSS with XSStrike: {url}")
            if not factory._check_tool_available("xsstrike"):
                logger.warning("XSStrike not found in PATH. Install from: https://github.com/s0md3v/XSStrike")
                return {"error": "XSStrike not installed", "url": url}
            
            try:
                result = factory._run_command(
                    ["xsstrike", "-u", url, "--crawl", "--json"],
                    timeout=20
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
    
    def create_scan_with_owasp_zap():
        """
        Create scan_with_owasp_zap tool.
        
        Why OWASP ZAP: Comprehensive web app scanner with active/passive scanning.
        Industry standard tool with extensive vulnerability coverage.
        """
        def scan_with_owasp_zap(url: str, zap_proxy: Optional[str] = "http://127.0.0.1:8080") -> Dict[str, Any]:
            """Scan target with OWASP ZAP via API."""
            logger.info(f"Scanning with OWASP ZAP: {url}")
            try:
                # Start spider scan
                spider_url = f"{zap_proxy}/JSON/spider/action/scan/"
                params = {"url": url}
                response = requests.get(spider_url, params=params, timeout=20)
                
                if response.status_code != 200:
                    return {"error": "ZAP API not accessible", "url": url}
                
                # Wait for scan to complete (simplified - in production, poll status)
                time.sleep(10)
                
                # Get alerts
                alerts_url = f"{zap_proxy}/JSON/core/view/alerts/"
                alerts_response = requests.get(alerts_url, timeout=20)
                
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
    
    def create_scan_with_nikto():
        """
        Create scan_with_nikto tool.
        
        Why Nikto: Web server vulnerability scanner focusing on misconfigurations and known issues.
        Excellent for finding server-level vulnerabilities.
        """
        def scan_with_nikto(url: str) -> Dict[str, Any]:
            """Scan web server with Nikto."""
            logger.info(f"Scanning with Nikto: {url}")
            if not factory._check_tool_available("nikto"):
                logger.warning("Nikto not found in PATH. Install from: https://github.com/sullo/nikto")
                return {"error": "Nikto not installed", "url": url}
            
            try:
                result = factory._run_command(
                    ["nikto", "-h", url, "-Format", "json"],
                    timeout=20
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
    
    def create_scan_with_wapiti():
        """
        Create scan_with_wapiti tool.
        
        Why Wapiti: Web vulnerability scanner focusing on injection flaws (XSS, SQLi, etc.).
        Good complement to other scanners with different detection methods.
        """
        def scan_with_wapiti(url: str) -> Dict[str, Any]:
            """Scan web application with Wapiti."""
            logger.info(f"Scanning with Wapiti: {url}")
            if not factory._check_tool_available("wapiti"):
                logger.warning("Wapiti not found in PATH. Install: pip install wapiti3")
                return {"error": "Wapiti not installed", "url": url}
            
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output_file = os.path.join(tmpdir, "wapiti_report.json")
                    result = factory._run_command(
                        ["wapiti", "-u", url, "-f", "json", "-o", tmpdir],
                        timeout=20
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
    
    # Register all web application tools
    tools['scan_with_nuclei'] = create_scan_with_nuclei()
    tools['scan_with_sqlmap'] = create_scan_with_sqlmap()
    tools['scan_xss_with_dalfox'] = create_scan_xss_with_dalfox()
    tools['scan_xss_with_xsstrike'] = create_scan_xss_with_xsstrike()
    tools['scan_with_owasp_zap'] = create_scan_with_owasp_zap()
    tools['scan_with_nikto'] = create_scan_with_nikto()
    tools['scan_with_wapiti'] = create_scan_with_wapiti()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_web_app_tools',
    'scan_with_nuclei',
    'scan_with_sqlmap',
    'scan_xss_with_dalfox',
    'scan_xss_with_xsstrike',
    'scan_with_owasp_zap',
    'scan_with_nikto',
    'scan_with_wapiti',
]

