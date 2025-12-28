"""Test script to verify concise report generation works correctly."""

import sys
import os
from pathlib import Path
from datetime import datetime

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from vibe_code_bench.core.report_models import (
    BrowsingReportData,
    RedTeamReportData,
    CombinedReportData,
    discovery_result_to_browsing_data,
    red_team_report_to_red_team_data,
    merge_reports,
)
from vibe_code_bench.core.report_generators import (
    BrowsingReportGenerator,
    RedTeamReportGenerator,
)
from vibe_code_bench.core.combined_report import CombinedReportGenerator
from vibe_code_bench.browsing_agent.models import DiscoveryResult, PageInfo
from vibe_code_bench.red_team_agent.models import RedTeamReport, VulnerabilityFinding, SecurityTestResult


def test_browsing_report():
    """Test browsing report generation."""
    print("Testing browsing report generation...")
    
    # Create sample discovery result
    pages = [
        PageInfo(
            url="https://example.com/",
            title="Homepage",
            page_type="homepage",
            has_forms=False,
            requires_auth=False,
            discovered_via="sitemap",
        ),
        PageInfo(
            url="https://example.com/login",
            title="Login",
            page_type="login",
            has_forms=True,
            requires_auth=True,
            forms=[{"action": "/login", "method": "POST", "fields": ["username", "password"]}],
            discovered_via="link_crawl",
        ),
        PageInfo(
            url="https://example.com/contact",
            title="Contact",
            page_type="contact",
            has_forms=True,
            requires_auth=False,
            forms=[{"action": "/contact", "method": "POST", "fields": ["name", "email", "message"]}],
            discovered_via="link_crawl",
        ),
    ]
    
    discovery_result = DiscoveryResult(
        base_url="https://example.com",
        discovered_at=datetime.utcnow().isoformat() + "Z",
        total_pages=3,
        authentication_required=True,
        pages=pages,
        sitemap_used=True,
        robots_respected=True,
    )
    
    # Convert to browsing data
    browsing_data = discovery_result_to_browsing_data(
        discovery_result,
        run_id="test_browsing_001",
        tools_used=["browser_crawl", "sitemap", "llm_agent"],
    )
    
    # Generate markdown
    markdown = BrowsingReportGenerator.generate_markdown(browsing_data)
    
    # Verify content
    assert "# Website Discovery Report" in markdown
    assert "https://example.com" in markdown
    assert "Total pages: 3" in markdown
    assert "Pages with forms: 2" in markdown
    assert "Forms found: 2" in markdown
    assert "Auth endpoints: 1" in markdown
    
    # Check conciseness (should be < 100 lines)
    lines = markdown.split('\n')
    assert len(lines) < 100, f"Report too long: {len(lines)} lines"
    
    print(f"✓ Browsing report generated successfully ({len(lines)} lines)")
    print(f"  Report preview:\n{markdown[:300]}...")
    
    return browsing_data


def test_red_team_report():
    """Test red team report generation."""
    print("\nTesting red team report generation...")
    
    # Create sample vulnerabilities
    vulnerabilities = [
        VulnerabilityFinding(
            vulnerability_type="SQL Injection",
            severity="Critical",
            affected_url="https://example.com/login",
            description="SQL injection vulnerability in login form",
            proof_of_concept="' OR '1'='1",
            remediation="Use parameterized queries",
            test_type="Form Testing",
        ),
        VulnerabilityFinding(
            vulnerability_type="XSS",
            severity="High",
            affected_url="https://example.com/contact",
            description="Cross-site scripting vulnerability in contact form",
            proof_of_concept="<script>alert('XSS')</script>",
            remediation="Sanitize user input",
            test_type="Form Testing",
        ),
    ]
    
    # Create test results
    test_results = [
        SecurityTestResult(
            test_type="Form Testing",
            target_url="https://example.com/login",
            status="vulnerable",
            findings=[vulnerabilities[0]],
            execution_time=1.5,
        ),
        SecurityTestResult(
            test_type="Form Testing",
            target_url="https://example.com/contact",
            status="vulnerable",
            findings=[vulnerabilities[1]],
            execution_time=1.2,
        ),
        SecurityTestResult(
            test_type="Session Management",
            target_url="https://example.com/",
            status="safe",
            findings=[],
            execution_time=0.5,
        ),
    ]
    
    red_team_report = RedTeamReport(
        base_url="https://example.com",
        tested_at=datetime.utcnow().isoformat(),
        total_findings=2,
        findings_by_severity={"Critical": 1, "High": 1, "Medium": 0, "Low": 0},
        findings_by_type={"SQL Injection": 1, "XSS": 1},
        vulnerabilities=vulnerabilities,
        test_results=test_results,
        testing_methodology={
            "automated_scanning": True,
            "llm_testing": True,
            "anchor_browser": True,
            "test_results_count": 3,
        },
        summary="Found 2 vulnerabilities",
        recommendations=["Fix SQL injection", "Fix XSS"],
    )
    
    # Convert to red team data
    red_team_data = red_team_report_to_red_team_data(
        red_team_report,
        run_id="test_red_team_001",
    )
    
    # Generate markdown
    markdown = RedTeamReportGenerator.generate_markdown(red_team_data)
    
    # Verify content
    assert "# Security Assessment Report" in markdown
    assert "https://example.com" in markdown
    assert "Vulnerabilities found: 2" in markdown
    assert "Tests executed: 3" in markdown
    assert "Critical: 1" in markdown
    assert "High: 1" in markdown
    assert "SQL Injection" in markdown
    assert "XSS" in markdown
    
    # Check conciseness (should be < 150 lines)
    lines = markdown.split('\n')
    assert len(lines) < 150, f"Report too long: {len(lines)} lines"
    
    print(f"✓ Red team report generated successfully ({len(lines)} lines)")
    print(f"  Report preview:\n{markdown[:400]}...")
    
    return red_team_data


def test_combined_report(browsing_data, red_team_data):
    """Test combined report generation."""
    print("\nTesting combined report generation...")
    
    # Merge reports
    combined_data = merge_reports(browsing_data, red_team_data)
    combined_data.run_id = "test_combined_001"
    
    # Generate markdown
    markdown = CombinedReportGenerator.generate_markdown(combined_data)
    
    # Verify content
    assert "# Combined Security Assessment Report" in markdown
    assert "https://example.com" in markdown
    assert "Discovery Summary" in markdown
    assert "Security Assessment Summary" in markdown
    assert "Correlation" in markdown
    assert "Total pages discovered: 3" in markdown
    assert "Vulnerabilities found: 2" in markdown
    
    # Check conciseness (should be < 200 lines)
    lines = markdown.split('\n')
    assert len(lines) < 200, f"Report too long: {len(lines)} lines"
    
    print(f"✓ Combined report generated successfully ({len(lines)} lines)")
    print(f"  Report preview:\n{markdown[:400]}...")
    
    return combined_data


def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing Concise Report System")
    print("=" * 60)
    
    try:
        browsing_data = test_browsing_report()
        red_team_data = test_red_team_report()
        combined_data = test_combined_report(browsing_data, red_team_data)
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        print("\nSummary:")
        print(f"- Browsing report: {len(BrowsingReportGenerator.generate_markdown(browsing_data).split(chr(10)))} lines")
        print(f"- Red team report: {len(RedTeamReportGenerator.generate_markdown(red_team_data).split(chr(10)))} lines")
        print(f"- Combined report: {len(CombinedReportGenerator.generate_markdown(combined_data).split(chr(10)))} lines")
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
