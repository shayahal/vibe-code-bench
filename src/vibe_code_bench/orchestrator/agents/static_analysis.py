"""
Static Analysis Agent Node

Performs static code analysis on the generated website using:
- Bandit (Python security linter)
- Semgrep (general static analysis)
- npm audit (Node.js dependency vulnerabilities)
"""

import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


def run_bandit(website_dir: Path) -> Dict[str, Any]:
    """
    Run Bandit security linter on Python files.
    
    Args:
        website_dir: Directory containing website files
        
    Returns:
        Dictionary with Bandit results
    """
    logger.info("Running Bandit on Python files...")
    
    # Check if bandit is available
    if not shutil.which("bandit"):
        logger.warning("Bandit not found. Install with: pip install bandit[toml]")
        return {
            "tool": "bandit",
            "available": False,
            "error": "Bandit not installed"
        }
    
    # Find all Python files
    python_files = list(website_dir.rglob("*.py"))
    if not python_files:
        logger.info("No Python files found for Bandit analysis")
        return {
            "tool": "bandit",
            "available": True,
            "files_scanned": 0,
            "vulnerabilities": []
        }
    
    try:
        # Run bandit with JSON output
        result = subprocess.run(
            ["bandit", "-r", str(website_dir), "-f", "json", "-ll"],  # -ll = low and low severity
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(website_dir)
        )
        
        # Parse JSON output
        if result.returncode == 0 or result.stdout:
            try:
                bandit_data = json.loads(result.stdout)
                vulnerabilities = []
                
                for result_item in bandit_data.get("results", []):
                    # Map Bandit severity to our severity levels
                    severity_map = {
                        "HIGH": "High",
                        "MEDIUM": "Medium",
                        "LOW": "Low"
                    }
                    
                    vulnerabilities.append({
                        "id": f"STATIC-BANDIT-{len(vulnerabilities) + 1:03d}",
                        "tool": "bandit",
                        "severity": severity_map.get(result_item.get("issue_severity", "LOW"), "Low"),
                        "type": "Static Analysis",
                        "file": result_item.get("filename", "unknown"),
                        "line": result_item.get("line_number", 0),
                        "test_id": result_item.get("test_id", "unknown"),
                        "issue_text": result_item.get("issue_text", ""),
                        "issue_confidence": result_item.get("issue_confidence", "LOW"),
                        "description": f"{result_item.get('test_name', 'Unknown issue')}: {result_item.get('issue_text', '')}"
                    })
                
                logger.info(f"Bandit found {len(vulnerabilities)} issues")
                return {
                    "tool": "bandit",
                    "available": True,
                    "files_scanned": len(bandit_data.get("results", [])),
                    "vulnerabilities": vulnerabilities,
                    "metrics": bandit_data.get("metrics", {})
                }
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse Bandit JSON output: {result.stdout[:200]}")
                return {
                    "tool": "bandit",
                    "available": True,
                    "error": "Failed to parse output",
                    "raw_output": result.stdout[:500]
                }
        else:
            logger.warning(f"Bandit exited with code {result.returncode}: {result.stderr[:200]}")
            return {
                "tool": "bandit",
                "available": True,
                "error": f"Bandit exited with code {result.returncode}",
                "stderr": result.stderr[:500]
            }
            
    except subprocess.TimeoutExpired:
        logger.error("Bandit analysis timed out")
        return {
            "tool": "bandit",
            "available": True,
            "error": "Analysis timed out"
        }
    except Exception as e:
        logger.error(f"Error running Bandit: {e}")
        return {
            "tool": "bandit",
            "available": True,
            "error": str(e)
        }


def run_semgrep(website_dir: Path) -> Dict[str, Any]:
    """
    Run Semgrep static analysis.
    
    Args:
        website_dir: Directory containing website files
        
    Returns:
        Dictionary with Semgrep results
    """
    logger.info("Running Semgrep static analysis...")
    
    # Check if semgrep is available
    if not shutil.which("semgrep"):
        logger.warning("Semgrep not found. Install with: pip install semgrep")
        return {
            "tool": "semgrep",
            "available": False,
            "error": "Semgrep not installed"
        }
    
    try:
        # Run semgrep with JSON output
        # Using auto mode to detect languages and run security rules
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", str(website_dir)],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(website_dir)
        )
        
        # Parse JSON output
        if result.stdout:
            try:
                semgrep_data = json.loads(result.stdout)
                vulnerabilities = []
                
                for result_item in semgrep_data.get("results", []):
                    # Map Semgrep severity to our severity levels
                    severity_map = {
                        "ERROR": "High",
                        "WARNING": "Medium",
                        "INFO": "Low"
                    }
                    
                    # Get severity from check_id or default to WARNING
                    severity = severity_map.get(
                        result_item.get("extra", {}).get("severity", "WARNING"),
                        "Medium"
                    )
                    
                    vulnerabilities.append({
                        "id": f"STATIC-SEMGREP-{len(vulnerabilities) + 1:03d}",
                        "tool": "semgrep",
                        "severity": severity,
                        "type": "Static Analysis",
                        "file": result_item.get("path", "unknown"),
                        "line": result_item.get("start", {}).get("line", 0),
                        "rule_id": result_item.get("check_id", "unknown"),
                        "message": result_item.get("message", ""),
                        "description": f"{result_item.get('check_id', 'Unknown rule')}: {result_item.get('message', '')}"
                    })
                
                logger.info(f"Semgrep found {len(vulnerabilities)} issues")
                return {
                    "tool": "semgrep",
                    "available": True,
                    "files_scanned": len(set(r.get("path") for r in semgrep_data.get("results", []))),
                    "vulnerabilities": vulnerabilities,
                    "errors": semgrep_data.get("errors", [])
                }
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse Semgrep JSON output: {result.stdout[:200]}")
                return {
                    "tool": "semgrep",
                    "available": True,
                    "error": "Failed to parse output",
                    "raw_output": result.stdout[:500]
                }
        else:
            # No results or errors
            logger.info("Semgrep found no issues")
            return {
                "tool": "semgrep",
                "available": True,
                "files_scanned": 0,
                "vulnerabilities": []
            }
            
    except subprocess.TimeoutExpired:
        logger.error("Semgrep analysis timed out")
        return {
            "tool": "semgrep",
            "available": True,
            "error": "Analysis timed out"
        }
    except Exception as e:
        logger.error(f"Error running Semgrep: {e}")
        return {
            "tool": "semgrep",
            "available": True,
            "error": str(e)
        }


def run_npm_audit(website_dir: Path) -> Dict[str, Any]:
    """
    Run npm audit on package.json if present.
    
    Args:
        website_dir: Directory containing website files
        
    Returns:
        Dictionary with npm audit results
    """
    logger.info("Running npm audit on dependencies...")
    
    # Check if npm is available
    if not shutil.which("npm"):
        logger.warning("npm not found. npm audit requires Node.js/npm to be installed")
        return {
            "tool": "npm_audit",
            "available": False,
            "error": "npm not installed"
        }
    
    # Find package.json
    package_json = website_dir / "package.json"
    if not package_json.exists():
        # Check in subdirectories
        package_json_files = list(website_dir.rglob("package.json"))
        if not package_json_files:
            logger.info("No package.json found for npm audit")
            return {
                "tool": "npm_audit",
                "available": True,
                "files_scanned": 0,
                "vulnerabilities": []
            }
        package_json = package_json_files[0]
    
    package_dir = package_json.parent
    
    try:
        # Run npm audit with JSON output
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(package_dir)
        )
        
        # Parse JSON output
        if result.stdout:
            try:
                audit_data = json.loads(result.stdout)
                vulnerabilities = []
                
                # npm audit structure: {vulnerabilities: {package: {...}}}
                for package_name, vuln_info in audit_data.get("vulnerabilities", {}).items():
                    # npm audit can have multiple vulnerabilities per package
                    for vuln in vuln_info.get("via", []):
                        if isinstance(vuln, str):
                            # Direct dependency vulnerability
                            severity_map = {
                                "critical": "Critical",
                                "high": "High",
                                "moderate": "Medium",
                                "low": "Low"
                            }
                            
                            severity = severity_map.get(
                                vuln_info.get("severity", "moderate").lower(),
                                "Medium"
                            )
                            
                            vulnerabilities.append({
                                "id": f"STATIC-NPM-{len(vulnerabilities) + 1:03d}",
                                "tool": "npm_audit",
                                "severity": severity,
                                "type": "Dependency Vulnerability",
                                "package": package_name,
                                "title": vuln_info.get("title", "Unknown vulnerability"),
                                "description": vuln_info.get("description", ""),
                                "url": vuln_info.get("url", "")
                            })
                
                logger.info(f"npm audit found {len(vulnerabilities)} vulnerabilities")
                return {
                    "tool": "npm_audit",
                    "available": True,
                    "package_json": str(package_json),
                    "vulnerabilities": vulnerabilities,
                    "summary": audit_data.get("metadata", {}).get("vulnerabilities", {})
                }
            except json.JSONDecodeError:
                # npm audit might return non-JSON if no vulnerabilities
                if "found 0 vulnerabilities" in result.stdout.lower():
                    logger.info("npm audit found no vulnerabilities")
                    return {
                        "tool": "npm_audit",
                        "available": True,
                        "package_json": str(package_json),
                        "vulnerabilities": []
                    }
                logger.warning(f"Failed to parse npm audit JSON output: {result.stdout[:200]}")
                return {
                    "tool": "npm_audit",
                    "available": True,
                    "error": "Failed to parse output",
                    "raw_output": result.stdout[:500]
                }
        else:
            logger.warning(f"npm audit exited with code {result.returncode}: {result.stderr[:200]}")
            return {
                "tool": "npm_audit",
                "available": True,
                "error": f"npm audit exited with code {result.returncode}",
                "stderr": result.stderr[:500]
            }
            
    except subprocess.TimeoutExpired:
        logger.error("npm audit timed out")
        return {
            "tool": "npm_audit",
            "available": True,
            "error": "Analysis timed out"
        }
    except Exception as e:
        logger.error(f"Error running npm audit: {e}")
        return {
            "tool": "npm_audit",
            "available": True,
            "error": str(e)
        }


def static_analysis_node(state: OrchestratorState) -> OrchestratorState:
    """
    Run static analysis tools on the generated website.
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Updated state with static_analysis_result
    """
    logger.info("="*60)
    logger.info("STEP 4: Running Static Analysis")
    logger.info("="*60)
    
    website_dir = state.get("website_dir")
    if not website_dir:
        logger.error("website_dir not set in state - cannot run static analysis")
        raise ValueError("website_dir not set in state - cannot run static analysis")
    
    website_dir = Path(website_dir)
    if not website_dir.exists():
        logger.error(f"Website directory does not exist: {website_dir}")
        raise ValueError(f"Website directory does not exist: {website_dir}")
    
    run_id = state.get("run_id")
    if not run_id:
        logger.error("run_id not set in state")
        raise ValueError("run_id not set in state")
    
    # Run all static analysis tools
    results = {
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "website_dir": str(website_dir),
        "tools": []
    }
    
    # Run Bandit (Python)
    bandit_result = run_bandit(website_dir)
    results["tools"].append(bandit_result)
    
    # Run Semgrep (general)
    semgrep_result = run_semgrep(website_dir)
    results["tools"].append(semgrep_result)
    
    # Run npm audit (Node.js)
    npm_result = run_npm_audit(website_dir)
    results["tools"].append(npm_result)
    
    # Collect all vulnerabilities
    all_vulnerabilities = []
    for tool_result in results["tools"]:
        if tool_result.get("available") and "vulnerabilities" in tool_result:
            all_vulnerabilities.extend(tool_result["vulnerabilities"])
    
    # Calculate summary statistics
    results["summary"] = {
        "total_vulnerabilities": len(all_vulnerabilities),
        "by_severity": {
            "Critical": len([v for v in all_vulnerabilities if v.get("severity") == "Critical"]),
            "High": len([v for v in all_vulnerabilities if v.get("severity") == "High"]),
            "Medium": len([v for v in all_vulnerabilities if v.get("severity") == "Medium"]),
            "Low": len([v for v in all_vulnerabilities if v.get("severity") == "Low"])
        },
        "by_tool": {
            tool_result.get("tool", "unknown"): len(tool_result.get("vulnerabilities", []))
            for tool_result in results["tools"]
            if tool_result.get("available")
        }
    }
    
    results["vulnerabilities"] = all_vulnerabilities
    
    # Save results to file
    run_dir = state.get("run_dir")
    if run_dir:
        run_dir = Path(run_dir)
        static_analysis_file = run_dir / "evals" / "static_analysis.json"
        static_analysis_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(static_analysis_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Static analysis results saved: {static_analysis_file}")
    
    logger.info(f"Static analysis completed: {results['summary']['total_vulnerabilities']} vulnerabilities found")
    logger.info(f"  Critical: {results['summary']['by_severity']['Critical']}")
    logger.info(f"  High: {results['summary']['by_severity']['High']}")
    logger.info(f"  Medium: {results['summary']['by_severity']['Medium']}")
    logger.info(f"  Low: {results['summary']['by_severity']['Low']}")
    
    return {
        **state,
        'static_analysis_result': results
        # Supervisor will route to next step
    }

