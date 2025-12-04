"""
Structured Report Generator for Red Team Agent

Generates structured JSON reports alongside markdown reports for easy comparison.
Includes both positive (found) and negative (not found) vulnerability results.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from enum import Enum


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class VulnerabilityType(str, Enum):
    """Vulnerability types."""
    SECURITY_HEADERS = "Security Headers"
    XSS = "XSS"
    SQL_INJECTION = "SQL Injection"
    AUTHENTICATION = "Authentication"
    CSRF = "CSRF"
    INSECURE_CONFIGURATION = "Insecure Configuration"
    OTHER = "Other"


# Comprehensive list of common vulnerabilities to test for
COMMON_VULNERABILITIES = [
    {
        "id": "VULN-001",
        "name": "Missing HTTPS",
        "description": "Credentials and sensitive data transmitted in plaintext",
        "severity": VulnerabilitySeverity.CRITICAL,
        "type": VulnerabilityType.SECURITY_HEADERS,
        "keywords": ["HTTPS", "SSL", "TLS", "encryption", "plaintext"]
    },
    {
        "id": "VULN-002",
        "name": "Missing CSRF Protection",
        "description": "Application vulnerable to Cross-Site Request Forgery attacks",
        "severity": VulnerabilitySeverity.CRITICAL,
        "type": VulnerabilityType.CSRF,
        "keywords": ["CSRF", "Cross-Site Request Forgery", "token", "csrf-token"]
    },
    {
        "id": "VULN-003",
        "name": "Missing Content Security Policy",
        "description": "Increased risk of cross-site scripting (XSS)",
        "severity": VulnerabilitySeverity.CRITICAL,
        "type": VulnerabilityType.SECURITY_HEADERS,
        "keywords": ["Content-Security-Policy", "CSP", "XSS protection"]
    },
    {
        "id": "VULN-004",
        "name": "Missing X-Frame-Options Header",
        "description": "Clickjacking risk",
        "severity": VulnerabilitySeverity.MEDIUM,
        "type": VulnerabilityType.SECURITY_HEADERS,
        "keywords": ["X-Frame-Options", "clickjacking", "frame"]
    },
    {
        "id": "VULN-005",
        "name": "Missing X-Content-Type-Options Header",
        "description": "MIME type sniffing risk",
        "severity": VulnerabilitySeverity.MEDIUM,
        "type": VulnerabilityType.SECURITY_HEADERS,
        "keywords": ["X-Content-Type-Options", "nosniff", "MIME"]
    },
    {
        "id": "VULN-006",
        "name": "Missing X-XSS-Protection Header",
        "description": "Increased XSS risk (deprecated but still used)",
        "severity": VulnerabilitySeverity.LOW,
        "type": VulnerabilityType.SECURITY_HEADERS,
        "keywords": ["X-XSS-Protection", "XSS"]
    },
    {
        "id": "VULN-007",
        "name": "Missing Referrer-Policy Header",
        "description": "Referrer information leakage",
        "severity": VulnerabilitySeverity.LOW,
        "type": VulnerabilityType.SECURITY_HEADERS,
        "keywords": ["Referrer-Policy", "referrer"]
    },
    {
        "id": "VULN-008",
        "name": "Missing X-Download-Options Header",
        "description": "Potential information leakage",
        "severity": VulnerabilitySeverity.LOW,
        "type": VulnerabilityType.SECURITY_HEADERS,
        "keywords": ["X-Download-Options"]
    },
    {
        "id": "VULN-009",
        "name": "Reflected XSS Vulnerability",
        "description": "Cross-site scripting vulnerability in URL parameters or form inputs",
        "severity": VulnerabilitySeverity.CRITICAL,
        "type": VulnerabilityType.XSS,
        "keywords": ["XSS", "Cross-Site Scripting", "reflected", "script injection"]
    },
    {
        "id": "VULN-010",
        "name": "Stored XSS Vulnerability",
        "description": "Persistent cross-site scripting vulnerability",
        "severity": VulnerabilitySeverity.CRITICAL,
        "type": VulnerabilityType.XSS,
        "keywords": ["XSS", "stored", "persistent", "database"]
    },
    {
        "id": "VULN-011",
        "name": "SQL Injection Vulnerability",
        "description": "SQL injection vulnerability in database queries",
        "severity": VulnerabilitySeverity.CRITICAL,
        "type": VulnerabilityType.SQL_INJECTION,
        "keywords": ["SQL injection", "SQLi", "database", "query"]
    },
    {
        "id": "VULN-012",
        "name": "Weak Authentication",
        "description": "Weak or missing authentication mechanisms",
        "severity": VulnerabilitySeverity.HIGH,
        "type": VulnerabilityType.AUTHENTICATION,
        "keywords": ["authentication", "login", "password", "weak"]
    },
    {
        "id": "VULN-013",
        "name": "Session Management Issues",
        "description": "Insecure session management",
        "severity": VulnerabilitySeverity.HIGH,
        "type": VulnerabilityType.AUTHENTICATION,
        "keywords": ["session", "cookie", "session management"]
    },
    {
        "id": "VULN-014",
        "name": "Missing Strict-Transport-Security Header",
        "description": "No forced HTTPS (HSTS)",
        "severity": VulnerabilitySeverity.HIGH,
        "type": VulnerabilityType.SECURITY_HEADERS,
        "keywords": ["Strict-Transport-Security", "HSTS", "HTTPS"]
    },
    {
        "id": "VULN-015",
        "name": "Insecure Password Storage",
        "description": "Passwords stored in plaintext or weak hashing",
        "severity": VulnerabilitySeverity.CRITICAL,
        "type": VulnerabilityType.AUTHENTICATION,
        "keywords": ["password", "hash", "encryption", "storage"]
    },
    {
        "id": "VULN-016",
        "name": "Missing Permissions-Policy Header",
        "description": "No permissions policy configured",
        "severity": VulnerabilitySeverity.LOW,
        "type": VulnerabilityType.SECURITY_HEADERS,
        "keywords": ["Permissions-Policy", "Feature-Policy"]
    },
    {
        "id": "VULN-017",
        "name": "Insecure Direct Object References",
        "description": "Direct access to internal objects without authorization",
        "severity": VulnerabilitySeverity.HIGH,
        "type": VulnerabilityType.OTHER,
        "keywords": ["IDOR", "direct object", "authorization"]
    },
    {
        "id": "VULN-018",
        "name": "Sensitive Data Exposure",
        "description": "Sensitive data exposed in responses or logs",
        "severity": VulnerabilitySeverity.HIGH,
        "type": VulnerabilityType.OTHER,
        "keywords": ["sensitive", "data exposure", "leakage"]
    },
    {
        "id": "VULN-019",
        "name": "Insufficient Logging",
        "description": "Insufficient security event logging",
        "severity": VulnerabilitySeverity.MEDIUM,
        "type": VulnerabilityType.OTHER,
        "keywords": ["logging", "audit", "monitoring"]
    },
    {
        "id": "VULN-020",
        "name": "Insecure Deserialization",
        "description": "Insecure deserialization of user input",
        "severity": VulnerabilitySeverity.HIGH,
        "type": VulnerabilityType.OTHER,
        "keywords": ["deserialization", "serialization", "pickle"]
    }
]


def extract_vulnerabilities_from_markdown(markdown_report: str) -> List[Dict[str, Any]]:
    """
    Extract vulnerability information from markdown report.
    
    Args:
        markdown_report: The markdown report content
        
    Returns:
        List of extracted vulnerabilities with their details
    """
    vulnerabilities = []
    
    # Pattern to match vulnerability entries: **VULN-XXX**: [Title] - [Description]. **Fix:** [Fix]
    vuln_pattern = re.compile(
        r'\*\*VULN-(\d+)\*\*:\s*(.+?)\s*-\s*(.+?)(?:\.\s*\*\*Fix:\*\*\s*(.+?))?(?=\n|$)',
        re.MULTILINE | re.DOTALL
    )
    
    # Also look for vulnerabilities without explicit IDs (by keywords)
    found_vuln_ids: Set[str] = set()
    
    for match in vuln_pattern.finditer(markdown_report):
        vuln_id = f"VULN-{match.group(1).zfill(3)}"
        title = match.group(2).strip()
        description = match.group(3).strip()
        fix = match.group(4).strip() if match.group(4) else None
        
        found_vuln_ids.add(vuln_id)
        
        vulnerabilities.append({
            "id": vuln_id,
            "name": title,
            "description": description,
            "fix": fix,
            "found": True,
            "source": "explicit_id"
        })
    
    # Extract severity from section headers
    severity_sections = {
        "Critical": re.compile(r'###\s*Critical\s*\n(.*?)(?=###|\Z)', re.DOTALL | re.IGNORECASE),
        "High": re.compile(r'###\s*High\s*\n(.*?)(?=###|\Z)', re.DOTALL | re.IGNORECASE),
        "Medium": re.compile(r'###\s*Medium\s*\n(.*?)(?=###|\Z)', re.DOTALL | re.IGNORECASE),
        "Low": re.compile(r'###\s*Low\s*\n(.*?)(?=###|\Z)', re.DOTALL | re.IGNORECASE),
    }
    
    # Try to match vulnerabilities by keywords if not found by ID
    report_lower = markdown_report.lower()
    
    for vuln_template in COMMON_VULNERABILITIES:
        if vuln_template["id"] in found_vuln_ids:
            continue  # Already found by explicit ID
        
        # Check if any keywords match
        keywords = [k.lower() for k in vuln_template["keywords"]]
        if any(keyword in report_lower for keyword in keywords):
            # Try to extract description from report
            description = vuln_template["description"]
            fix = None
            
            # Look for fix recommendations
            fix_pattern = re.compile(
                rf'{re.escape(vuln_template["name"])}.*?fix[:\s]+(.+?)(?=\n|$)',
                re.IGNORECASE | re.DOTALL
            )
            fix_match = fix_pattern.search(markdown_report)
            if fix_match:
                fix = fix_match.group(1).strip()
            
            vulnerabilities.append({
                "id": vuln_template["id"],
                "name": vuln_template["name"],
                "description": description,
                "fix": fix,
                "found": True,
                "source": "keyword_match"
            })
            found_vuln_ids.add(vuln_template["id"])
    
    return vulnerabilities


def generate_structured_report(
    markdown_report: str,
    url: str,
    model_name: str,
    execution_time: float,
    run_id: str,
    trace_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate a structured JSON report from markdown report.
    
    Includes both found and not-found vulnerabilities for easy comparison.
    
    Args:
        markdown_report: The markdown report content
        url: Target URL
        model_name: Model used for assessment
        execution_time: Execution time in seconds
        run_id: Run ID
        trace_id: Optional trace ID from LangFuse
        
    Returns:
        Structured report as dictionary
    """
    # Extract found vulnerabilities
    found_vulnerabilities = extract_vulnerabilities_from_markdown(markdown_report)
    found_vuln_ids = {v["id"] for v in found_vulnerabilities}
    
    # Create comprehensive list with both found and not found
    all_vulnerabilities = []
    
    for vuln_template in COMMON_VULNERABILITIES:
        vuln_id = vuln_template["id"]
        base_vuln = {
            "id": vuln_id,
            "name": vuln_template["name"],
            "severity": vuln_template["severity"].value,
            "type": vuln_template["type"].value
        }
        
        if vuln_id in found_vuln_ids:
            # Use the extracted information
            found_vuln = next(v for v in found_vulnerabilities if v["id"] == vuln_id)
            agent_desc = found_vuln.get("description", "")
            template_desc = vuln_template["description"]
            
            # Only include agent_description if it differs from template
            if agent_desc and agent_desc != template_desc:
                base_vuln["agent_description"] = agent_desc
            
            # Only include fix if present
            fix = found_vuln.get("fix")
            if fix:
                base_vuln["fix"] = fix
            
            # Only include source if not default
            source = found_vuln.get("source", "unknown")
            if source != "explicit_id":
                base_vuln["source"] = source
            
            base_vuln["found"] = True
        else:
            # Not found - minimal representation
            base_vuln["found"] = False
        
        all_vulnerabilities.append(base_vuln)
    
    # Calculate metrics
    total_vulns = len(all_vulnerabilities)
    found_count = len(found_vulnerabilities)
    not_found_count = total_vulns - found_count
    
    # Group by severity
    by_severity: Dict[str, Dict[str, Any]] = {}
    for severity in ["Critical", "High", "Medium", "Low"]:
        severity_vulns = [v for v in all_vulnerabilities if v["severity"] == severity]
        found_severity = [v for v in severity_vulns if v["found"]]
        
        by_severity[severity] = {
            "total": len(severity_vulns),
            "found": len(found_severity),
            "not_found": len(severity_vulns) - len(found_severity),
            "detection_rate": len(found_severity) / len(severity_vulns) if severity_vulns else 0.0
        }
    
    # Group by type
    by_type: Dict[str, Dict[str, Any]] = {}
    for vuln_type in [t.value for t in VulnerabilityType]:
        type_vulns = [v for v in all_vulnerabilities if v["type"] == vuln_type]
        found_type = [v for v in type_vulns if v["found"]]
        
        by_type[vuln_type] = {
            "total": len(type_vulns),
            "found": len(found_type),
            "not_found": len(type_vulns) - len(found_type),
            "detection_rate": len(found_type) / len(type_vulns) if type_vulns else 0.0
        }
    
    # Extract summary from markdown if available
    summary_match = re.search(
        r'##\s*Summary\s*\n(.*?)(?=##|\Z)',
        markdown_report,
        re.DOTALL | re.IGNORECASE
    )
    
    summary_text = ""
    risk_level = "Unknown"
    key_issues = []
    
    if summary_match:
        summary_text = summary_match.group(1).strip()
        # Try to extract risk level
        risk_match = re.search(r'Risk Level:\s*(\w+)', summary_text, re.IGNORECASE)
        if risk_match:
            risk_level = risk_match.group(1)
        
        # Try to extract key issues
        issues_match = re.search(r'Key Issues:\s*(.+?)(?:\n|$)', summary_text, re.IGNORECASE)
        if issues_match:
            key_issues = [issue.strip() for issue in issues_match.group(1).split(',')]
    
    # Build structured report - compact format
    structured_report = {
        "meta": {
            "run_id": run_id,
            "ts": datetime.now().isoformat(),
            "url": url,
            "model": model_name,
            "duration": round(execution_time, 2),
            "trace_id": trace_id,
            "v": "1.0"
        },
        "summary": {
            "total": total_vulns,
            "found": found_count,
            "not_found": not_found_count,
            "detection_rate": round(found_count / total_vulns, 4) if total_vulns > 0 else 0.0,
            "risk_level": risk_level,
            "key_issues": key_issues if key_issues else []
        },
        "vulnerabilities": all_vulnerabilities,
        "metrics": {
            "by_severity": {
                sev: {
                    "total": m["total"],
                    "found": m["found"],
                    "rate": round(m["detection_rate"], 4)
                }
                for sev, m in by_severity.items()
            },
            "by_type": {
                vtype: {
                    "total": m["total"],
                    "found": m["found"],
                    "rate": round(m["detection_rate"], 4)
                }
                for vtype, m in by_type.items()
            }
        }
    }
    
    return structured_report


def save_structured_report(
    structured_report: Dict[str, Any],
    run_id: str,
    report_dir_path: Optional[str] = None
) -> Path:
    """
    Save structured report to JSON file.
    
    Args:
        structured_report: The structured report dictionary
        run_id: Run ID for filename
        report_dir_path: Optional path to report directory (default: standard reports dir)
        
    Returns:
        Absolute Path to saved JSON report file
    """
    from vibe_code_bench.core.paths import get_reports_dir, get_absolute_path
    
    if report_dir_path:
        report_dir = get_absolute_path(report_dir_path)
    else:
        report_dir = get_reports_dir()
    
    report_dir.mkdir(parents=True, exist_ok=True)
    report_file = report_dir / f"run_report_{run_id}.json"
    
    # Write JSON with pretty formatting
    report_file.write_text(
        json.dumps(structured_report, indent=2, ensure_ascii=False),
        encoding='utf-8'
    )
    
    return report_file

