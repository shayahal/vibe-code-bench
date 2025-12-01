"""
Network & Infrastructure Security Tools

This module contains integrations for network scanning and infrastructure testing tools.

Tool Selection Rationale:
- Nmap: Industry standard network mapper. Most comprehensive port scanner available.
- Masscan: Ultra-fast port scanner. 10x faster than Nmap for large networks.
- RustScan: Modern, fast port scanner written in Rust. Excellent for quick scans.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_network_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register network & infrastructure security tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_scan_with_nmap():
        """
        Create scan_with_nmap tool.
        
        Why Nmap: Industry standard network mapper with comprehensive port scanning,
        service detection, and vulnerability scanning capabilities.
        """
        def scan_with_nmap(target: str, scan_type: str = "default") -> Dict[str, Any]:
            """Scan network target with Nmap."""
            logger.info(f"Scanning with Nmap: {target}")
            if not factory._check_tool_available("nmap"):
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
                result = factory._run_command(cmd, timeout=20)
                
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
    
    def create_scan_with_masscan():
        """
        Create scan_with_masscan tool.
        
        Why Masscan: Ultra-fast port scanner capable of scanning entire internet ranges.
        10x faster than Nmap for large network scans.
        """
        def scan_with_masscan(target: str, ports: str = "1-1000", rate: str = "1000") -> Dict[str, Any]:
            """Fast port scan with Masscan."""
            logger.info(f"Scanning with Masscan: {target}")
            if not factory._check_tool_available("masscan"):
                logger.warning("Masscan not found in PATH. Install: apt install masscan or brew install masscan")
                return {"error": "Masscan not installed", "target": target}
            
            try:
                cmd = ["masscan", "-p", ports, "--rate", rate, target, "-oJ", "-"]
                result = factory._run_command(cmd, timeout=20)
                
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
    
    def create_scan_with_rustscan():
        """
        Create scan_with_rustscan tool.
        
        Why RustScan: Modern, fast port scanner written in Rust.
        Excellent for quick scans with clean output.
        """
        def scan_with_rustscan(target: str, ports: str = "1-1000") -> Dict[str, Any]:
            """Fast port scan with RustScan."""
            logger.info(f"Scanning with RustScan: {target}")
            if not factory._check_tool_available("rustscan"):
                logger.warning("RustScan not found in PATH. Install: cargo install rustscan")
                return {"error": "RustScan not installed", "target": target}
            
            try:
                cmd = ["rustscan", "-a", target, "-p", ports, "--", "-sV"]
                result = factory._run_command(cmd, timeout=20)
                
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
    
    # Register all network tools
    tools['scan_with_nmap'] = create_scan_with_nmap()
    tools['scan_with_masscan'] = create_scan_with_masscan()
    tools['scan_with_rustscan'] = create_scan_with_rustscan()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_network_tools',
    'scan_with_nmap',
    'scan_with_masscan',
    'scan_with_rustscan',
]

