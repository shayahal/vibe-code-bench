"""Unified report data models for browsing and red team agents."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any


@dataclass
class BaseReport:
    """Base report with common fields."""

    base_url: str
    timestamp: str
    run_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "base_url": self.base_url,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
        }


@dataclass
class BrowsingReportData(BaseReport):
    """Browsing agent report data."""

    total_pages: int = 0
    pages_with_forms: int = 0
    pages_requiring_auth: int = 0
    authentication_required: bool = False
    sitemap_used: bool = False
    robots_respected: bool = True
    discovery_methods: Dict[str, int] = field(default_factory=dict)
    page_types: Dict[str, int] = field(default_factory=dict)
    key_pages: List[Dict[str, Any]] = field(default_factory=list)
    forms_found: int = 0
    auth_endpoints: int = 0
    errors: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        base_dict = super().to_dict()
        base_dict.update({
            "total_pages": self.total_pages,
            "pages_with_forms": self.pages_with_forms,
            "pages_requiring_auth": self.pages_requiring_auth,
            "authentication_required": self.authentication_required,
            "sitemap_used": self.sitemap_used,
            "robots_respected": self.robots_respected,
            "discovery_methods": self.discovery_methods,
            "page_types": self.page_types,
            "key_pages": self.key_pages,
            "forms_found": self.forms_found,
            "auth_endpoints": self.auth_endpoints,
            "errors": self.errors,
            "tools_used": self.tools_used,
        })
        return base_dict


@dataclass
class RedTeamReportData(BaseReport):
    """Red team agent report data."""

    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_type: Dict[str, int] = field(default_factory=dict)
    tests_executed: int = 0
    tests_vulnerable: int = 0
    tests_safe: int = 0
    tests_error: int = 0
    key_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    test_results_summary: Dict[str, Any] = field(default_factory=dict)
    tools_used: List[str] = field(default_factory=list)
    status: str = "unknown"  # safe, vulnerable, errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        base_dict = super().to_dict()
        base_dict.update({
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_type": self.findings_by_type,
            "tests_executed": self.tests_executed,
            "tests_vulnerable": self.tests_vulnerable,
            "tests_safe": self.tests_safe,
            "tests_error": self.tests_error,
            "key_vulnerabilities": self.key_vulnerabilities,
            "test_results_summary": self.test_results_summary,
            "tools_used": self.tools_used,
            "status": self.status,
        })
        return base_dict


@dataclass
class CombinedReportData(BaseReport):
    """Combined report merging browsing and red team data."""

    browsing_data: Optional[BrowsingReportData] = None
    red_team_data: Optional[RedTeamReportData] = None
    correlation: List[Dict[str, Any]] = field(default_factory=list)  # Which pages had vulnerabilities

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        base_dict = super().to_dict()
        base_dict.update({
            "browsing_data": self.browsing_data.to_dict() if self.browsing_data else None,
            "red_team_data": self.red_team_data.to_dict() if self.red_team_data else None,
            "correlation": self.correlation,
        })
        return base_dict


# Conversion utilities

def discovery_result_to_browsing_data(
    discovery_result: Any, run_id: Optional[str] = None, tools_used: Optional[List[str]] = None
) -> BrowsingReportData:
    """
    Convert DiscoveryResult to BrowsingReportData.

    Args:
        discovery_result: DiscoveryResult object from browsing agent
        run_id: Optional run ID
        tools_used: Optional list of tools used during discovery

    Returns:
        BrowsingReportData object
    """
    # Count pages by type and discovery method
    page_types = {}
    discovery_methods = {}
    pages_with_forms = 0
    pages_requiring_auth = 0
    forms_found = 0
    auth_endpoints = 0
    key_pages = []

    for page in discovery_result.pages:
        # Page types
        page_type = page.page_type or "unknown"
        page_types[page_type] = page_types.get(page_type, 0) + 1

        # Discovery methods
        method = page.discovered_via or "unknown"
        discovery_methods[method] = discovery_methods.get(method, 0) + 1

        # Forms and auth
        if page.has_forms:
            pages_with_forms += 1
            forms_found += len(page.forms)
        if page.requires_auth:
            pages_requiring_auth += 1
            auth_endpoints += 1

        # Collect key pages (those with forms, auth, or important types)
        if page.has_forms or page.requires_auth or page.page_type in ["homepage", "login", "admin"]:
            key_pages.append({
                "url": page.url,
                "title": page.title,
                "page_type": page.page_type,
                "has_forms": page.has_forms,
                "requires_auth": page.requires_auth,
                "forms_count": len(page.forms),
            })

    return BrowsingReportData(
        base_url=discovery_result.base_url,
        timestamp=discovery_result.discovered_at,
        run_id=run_id,
        total_pages=discovery_result.total_pages,
        pages_with_forms=pages_with_forms,
        pages_requiring_auth=pages_requiring_auth,
        authentication_required=discovery_result.authentication_required,
        sitemap_used=discovery_result.sitemap_used,
        robots_respected=discovery_result.robots_respected,
        discovery_methods=discovery_methods,
        page_types=page_types,
        key_pages=key_pages[:20],  # Limit to top 20 key pages
        forms_found=forms_found,
        auth_endpoints=auth_endpoints,
        errors=discovery_result.errors,
        tools_used=tools_used or [],
    )


def red_team_report_to_red_team_data(
    red_team_report: Any, run_id: Optional[str] = None
) -> RedTeamReportData:
    """
    Convert RedTeamReport to RedTeamReportData.

    Args:
        red_team_report: RedTeamReport object from red team agent
        run_id: Optional run ID

    Returns:
        RedTeamReportData object
    """
    # Count test results by status
    tests_vulnerable = sum(1 for r in red_team_report.test_results if r.status == "vulnerable")
    tests_safe = sum(1 for r in red_team_report.test_results if r.status == "safe")
    tests_error = sum(1 for r in red_team_report.test_results if r.status == "error")

    # Determine overall status
    if tests_error > 0:
        status = "errors"
    elif tests_vulnerable > 0:
        status = "vulnerable"
    else:
        status = "safe"

    # Extract key vulnerabilities (Critical and High severity)
    key_vulnerabilities = []
    for vuln in red_team_report.vulnerabilities:
        if vuln.severity in ["Critical", "High"]:
            key_vulnerabilities.append({
                "vulnerability_type": vuln.vulnerability_type,
                "severity": vuln.severity,
                "affected_url": vuln.affected_url,
                "description": vuln.description[:200],  # Truncate for concise report
                "test_type": vuln.test_type,
            })

    # Summarize test results by type
    test_results_summary = {}
    for result in red_team_report.test_results:
        test_type = result.test_type
        if test_type not in test_results_summary:
            test_results_summary[test_type] = {
                "total": 0,
                "vulnerable": 0,
                "safe": 0,
                "error": 0,
            }
        test_results_summary[test_type]["total"] += 1
        test_results_summary[test_type][result.status] = (
            test_results_summary[test_type].get(result.status, 0) + 1
        )

    # Extract tools used from testing methodology
    tools_used = []
    methodology = red_team_report.testing_methodology or {}
    if methodology.get("automated_scanning"):
        tools_used.append("automated_scanning")
    if methodology.get("llm_testing"):
        tools_used.append("llm_testing")
    if methodology.get("anchor_browser"):
        tools_used.append("anchor_browser")

    return RedTeamReportData(
        base_url=red_team_report.base_url,
        timestamp=red_team_report.tested_at,
        run_id=run_id,
        total_findings=red_team_report.total_findings,
        findings_by_severity=red_team_report.findings_by_severity,
        findings_by_type=red_team_report.findings_by_type,
        tests_executed=len(red_team_report.test_results),
        tests_vulnerable=tests_vulnerable,
        tests_safe=tests_safe,
        tests_error=tests_error,
        key_vulnerabilities=key_vulnerabilities[:10],  # Limit to top 10 vulnerabilities
        test_results_summary=test_results_summary,
        tools_used=tools_used,
        status=status,
    )


def merge_reports(
    browsing_data: BrowsingReportData, red_team_data: RedTeamReportData
) -> CombinedReportData:
    """
    Merge browsing and red team reports into combined report.

    Args:
        browsing_data: BrowsingReportData object
        red_team_data: RedTeamReportData object

    Returns:
        CombinedReportData object
    """
    # Create correlation between discovered pages and vulnerabilities
    correlation = []
    
    # Match vulnerabilities to pages
    if red_team_data.key_vulnerabilities:
        for vuln in red_team_data.key_vulnerabilities:
            affected_url = vuln.get("affected_url", "")
            # Find matching page in browsing data
            matching_page = None
            for page in browsing_data.key_pages:
                if page.get("url") == affected_url:
                    matching_page = page
                    break
            
            correlation.append({
                "page_url": affected_url,
                "page_type": matching_page.get("page_type") if matching_page else "unknown",
                "vulnerability_type": vuln.get("vulnerability_type"),
                "severity": vuln.get("severity"),
            })

    # Use the earlier timestamp as the base timestamp
    base_timestamp = min(browsing_data.timestamp, red_team_data.timestamp)
    # Use red_team run_id if available, otherwise browsing run_id
    run_id = red_team_data.run_id or browsing_data.run_id

    return CombinedReportData(
        base_url=browsing_data.base_url,
        timestamp=base_timestamp,
        run_id=run_id,
        browsing_data=browsing_data,
        red_team_data=red_team_data,
        correlation=correlation,
    )
