"""Data models for the red team agent using Pydantic for validation."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, field_validator


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class VulnerabilityType(str, Enum):
    """Common vulnerability types."""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    AUTH_BYPASS = "Authentication Bypass"
    IDOR = "Insecure Direct Object Reference (IDOR)"
    SSRF = "Server-Side Request Forgery (SSRF)"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    SECURITY_MISCONFIGURATION = "Security Misconfiguration"
    MISSING_RATE_LIMIT = "Missing Rate Limiting"
    WEAK_CRYPTO = "Weak Cryptography"
    OTHER = "Other"


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding."""
    
    vulnerability_type: str = Field(description="Type of vulnerability (e.g., SQL Injection, XSS)")
    severity: Severity = Field(description="Severity level")
    url: str = Field(description="Affected URL")
    description: str = Field(description="Detailed description of the vulnerability")
    proof_of_concept: str = Field(default="", description="PoC or evidence")
    remediation: str = Field(default="", description="Recommended fix")
    
    # Classification
    cwe_id: int | None = Field(default=None, description="CWE ID if applicable")
    owasp_category: str = Field(default="", description="OWASP Top 10 category")
    
    # Metadata
    tool: str = Field(description="Tool that found this vulnerability")
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    raw_output: dict[str, Any] = Field(default_factory=dict, description="Raw tool output")
    
    class Config:
        use_enum_values = True


class ToolResult(BaseModel):
    """Result from a single tool execution."""
    
    tool_name: str = Field(description="Name of the tool")
    target_url: str = Field(description="Target URL that was scanned")
    success: bool = Field(description="Whether the tool executed successfully")
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    execution_time_ms: float = Field(default=0, description="Execution time in milliseconds")
    error_message: str | None = Field(default=None, description="Error message if failed")
    
    @property
    def has_findings(self) -> bool:
        """Check if any vulnerabilities were found."""
        return len(self.findings) > 0


class ScanReport(BaseModel):
    """Complete scan report for a target URL."""
    
    target_url: str = Field(description="Target URL that was scanned")
    scan_id: str = Field(description="Unique identifier for this scan")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = Field(default=None)
    
    # Results
    tool_results: list[ToolResult] = Field(default_factory=list)
    
    # Summary
    total_findings: int = Field(default=0)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_type: dict[str, int] = Field(default_factory=dict)
    
    # All findings flattened
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)
    
    # Metadata
    tools_used: list[str] = Field(default_factory=list)
    tools_available: list[str] = Field(default_factory=list)
    
    def finalize(self) -> "ScanReport":
        """Finalize the report with computed summaries."""
        self.completed_at = datetime.utcnow()
        
        # Collect all findings
        all_findings = []
        for result in self.tool_results:
            all_findings.extend(result.findings)
        
        self.vulnerabilities = all_findings
        self.total_findings = len(all_findings)
        
        # Count by severity
        self.findings_by_severity = {}
        for finding in all_findings:
            sev = finding.severity
            self.findings_by_severity[sev] = self.findings_by_severity.get(sev, 0) + 1
        
        # Count by type
        self.findings_by_type = {}
        for finding in all_findings:
            vtype = finding.vulnerability_type
            self.findings_by_type[vtype] = self.findings_by_type.get(vtype, 0) + 1
        
        # Tools used
        self.tools_used = [r.tool_name for r in self.tool_results if r.success]
        
        return self
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return self.model_dump(mode="json")
    
    def get_critical_findings(self) -> list[VulnerabilityFinding]:
        """Get all critical severity findings."""
        return [f for f in self.vulnerabilities if f.severity == Severity.CRITICAL]
    
    def get_high_findings(self) -> list[VulnerabilityFinding]:
        """Get all high severity findings."""
        return [f for f in self.vulnerabilities if f.severity == Severity.HIGH]


# OWASP Top 10 2021 mapping
OWASP_MAPPING = {
    "SQL Injection": "A03:2021 Injection",
    "XSS": "A03:2021 Injection",
    "Cross-Site Scripting (XSS)": "A03:2021 Injection",
    "Command Injection": "A03:2021 Injection",
    "CSRF": "A01:2021 Broken Access Control",
    "Cross-Site Request Forgery (CSRF)": "A01:2021 Broken Access Control",
    "Authentication Bypass": "A07:2021 Identification and Authentication Failures",
    "IDOR": "A01:2021 Broken Access Control",
    "Insecure Direct Object Reference (IDOR)": "A01:2021 Broken Access Control",
    "SSRF": "A10:2021 Server-Side Request Forgery",
    "Path Traversal": "A01:2021 Broken Access Control",
    "Information Disclosure": "A01:2021 Broken Access Control",
    "Security Misconfiguration": "A05:2021 Security Misconfiguration",
    "Missing Rate Limiting": "A05:2021 Security Misconfiguration",
    "Weak Cryptography": "A02:2021 Cryptographic Failures",
}


def get_owasp_category(vuln_type: str) -> str:
    """Get OWASP Top 10 2021 category for a vulnerability type."""
    return OWASP_MAPPING.get(vuln_type, "")


# CWE mapping for common vulnerabilities
CWE_MAPPING = {
    "SQL Injection": 89,
    "XSS": 79,
    "Cross-Site Scripting (XSS)": 79,
    "CSRF": 352,
    "Cross-Site Request Forgery (CSRF)": 352,
    "Authentication Bypass": 287,
    "IDOR": 639,
    "Insecure Direct Object Reference (IDOR)": 639,
    "SSRF": 918,
    "Path Traversal": 22,
    "Command Injection": 78,
    "Information Disclosure": 200,
    "Security Misconfiguration": 16,
    "Missing Rate Limiting": 770,
}


def get_cwe_id(vuln_type: str) -> int | None:
    """Get CWE ID for a vulnerability type."""
    return CWE_MAPPING.get(vuln_type)


# Severity classification for common vulnerability types
SEVERITY_MAPPING = {
    "SQL Injection": Severity.CRITICAL,
    "Command Injection": Severity.CRITICAL,
    "Authentication Bypass": Severity.CRITICAL,
    "XSS": Severity.HIGH,
    "Cross-Site Scripting (XSS)": Severity.HIGH,
    "SSRF": Severity.HIGH,
    "IDOR": Severity.HIGH,
    "Insecure Direct Object Reference (IDOR)": Severity.HIGH,
    "Path Traversal": Severity.HIGH,
    "CSRF": Severity.MEDIUM,
    "Cross-Site Request Forgery (CSRF)": Severity.MEDIUM,
    "Information Disclosure": Severity.MEDIUM,
    "Security Misconfiguration": Severity.MEDIUM,
    "Missing Rate Limiting": Severity.MEDIUM,
    "Weak Cryptography": Severity.MEDIUM,
}


def classify_severity(vuln_type: str) -> Severity:
    """Classify severity for a vulnerability type."""
    return SEVERITY_MAPPING.get(vuln_type, Severity.INFO)
