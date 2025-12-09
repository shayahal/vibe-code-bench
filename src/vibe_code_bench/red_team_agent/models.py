"""Data models for red team agent."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


@dataclass
class VulnerabilityFinding:
    """Represents a security vulnerability finding."""

    vulnerability_type: str  # SQLi, XSS, CSRF, etc.
    severity: str  # Critical, High, Medium, Low
    affected_url: str
    description: str
    proof_of_concept: str
    remediation: str
    cwe_id: Optional[int] = None
    owasp_category: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    test_type: Optional[str] = None  # Which test found this
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "affected_url": self.affected_url,
            "description": self.description,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "discovered_at": self.discovered_at,
            "test_type": self.test_type,
            "additional_info": self.additional_info,
        }


@dataclass
class SecurityTestResult:
    """Result of a security test execution."""

    test_type: str
    target_url: str
    status: str  # vulnerable, safe, error
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    execution_time: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "test_type": self.test_type,
            "target_url": self.target_url,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "execution_time": self.execution_time,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


@dataclass
class AttackSurface:
    """Represents an attack surface category."""

    category: str  # forms, api_endpoints, auth_endpoints, sensitive_pages
    items: List[Dict[str, Any]] = field(default_factory=list)
    priority: str = "Medium"  # High, Medium, Low
    test_suites: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "category": self.category,
            "items": self.items,
            "priority": self.priority,
            "test_suites": self.test_suites,
        }


@dataclass
class TestingPlan:
    """Comprehensive testing plan for the red team agent."""

    base_url: str
    attack_surfaces: List[AttackSurface] = field(default_factory=list)
    total_pages: int = 0
    total_forms: int = 0
    total_api_endpoints: int = 0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "base_url": self.base_url,
            "attack_surfaces": [as_.to_dict() for as_ in self.attack_surfaces],
            "total_pages": self.total_pages,
            "total_forms": self.total_forms,
            "total_api_endpoints": self.total_api_endpoints,
            "created_at": self.created_at,
        }


@dataclass
class RedTeamReport:
    """Final red team security assessment report."""

    base_url: str
    tested_at: str
    total_findings: int
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_type: Dict[str, int] = field(default_factory=dict)
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    test_results: List[SecurityTestResult] = field(default_factory=list)
    testing_methodology: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "base_url": self.base_url,
            "tested_at": self.tested_at,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_type": self.findings_by_type,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "test_results": [tr.to_dict() for tr in self.test_results],
            "testing_methodology": self.testing_methodology,
            "summary": self.summary,
            "recommendations": self.recommendations,
        }
