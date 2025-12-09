"""Tests for red team agent models."""

import pytest
from datetime import datetime

from vibe_code_bench.red_team_agent.models import (
    VulnerabilityFinding,
    SecurityTestResult,
    AttackSurface,
    TestingPlan,
    RedTeamReport,
)


class TestVulnerabilityFinding:
    """Test VulnerabilityFinding model."""

    def test_create_finding(self):
        """Test creating a vulnerability finding."""
        finding = VulnerabilityFinding(
            vulnerability_type="XSS",
            severity="High",
            affected_url="https://example.com/page",
            description="XSS vulnerability found",
            proof_of_concept="<script>alert('XSS')</script>",
            remediation="Sanitize input",
        )
        assert finding.vulnerability_type == "XSS"
        assert finding.severity == "High"
        assert finding.affected_url == "https://example.com/page"

    def test_to_dict(self):
        """Test converting finding to dictionary."""
        finding = VulnerabilityFinding(
            vulnerability_type="SQL Injection",
            severity="Critical",
            affected_url="https://example.com/form",
            description="SQL injection found",
            proof_of_concept="' OR '1'='1",
            remediation="Use parameterized queries",
        )
        result = finding.to_dict()
        assert isinstance(result, dict)
        assert result["vulnerability_type"] == "SQL Injection"
        assert result["severity"] == "Critical"


class TestSecurityTestResult:
    """Test SecurityTestResult model."""

    def test_create_result(self):
        """Test creating a security test result."""
        result = SecurityTestResult(
            test_type="XSS",
            target_url="https://example.com/page",
            status="vulnerable",
        )
        assert result.test_type == "XSS"
        assert result.status == "vulnerable"
        assert len(result.findings) == 0

    def test_result_with_findings(self):
        """Test result with findings."""
        finding = VulnerabilityFinding(
            vulnerability_type="XSS",
            severity="High",
            affected_url="https://example.com/page",
            description="XSS found",
            proof_of_concept="<script>alert('XSS')</script>",
            remediation="Sanitize input",
        )
        result = SecurityTestResult(
            test_type="XSS",
            target_url="https://example.com/page",
            status="vulnerable",
            findings=[finding],
        )
        assert len(result.findings) == 1
        assert result.findings[0].vulnerability_type == "XSS"


class TestTestingPlan:
    """Test TestingPlan model."""

    def test_create_plan(self):
        """Test creating a testing plan."""
        plan = TestingPlan(base_url="https://example.com", total_pages=10)
        assert plan.base_url == "https://example.com"
        assert plan.total_pages == 10
        assert len(plan.attack_surfaces) == 0

    def test_plan_with_surfaces(self):
        """Test plan with attack surfaces."""
        surface = AttackSurface(
            category="forms_login",
            items=[{"url": "https://example.com/login", "method": "post"}],
            priority="High",
            test_suites=["SQLi", "XSS"],
        )
        plan = TestingPlan(
            base_url="https://example.com",
            total_pages=10,
            attack_surfaces=[surface],
        )
        assert len(plan.attack_surfaces) == 1
        assert plan.attack_surfaces[0].category == "forms_login"


class TestRedTeamReport:
    """Test RedTeamReport model."""

    def test_create_report(self):
        """Test creating a red team report."""
        report = RedTeamReport(
            base_url="https://example.com",
            tested_at=datetime.utcnow().isoformat(),
            total_findings=5,
        )
        assert report.base_url == "https://example.com"
        assert report.total_findings == 5
        assert len(report.vulnerabilities) == 0
