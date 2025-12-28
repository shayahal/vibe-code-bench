"""Test script to verify the concise report system works correctly."""

import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_imports():
    """Test that all new modules can be imported."""
    print("Testing imports...")
    
    try:
        from vibe_code_bench.core.report_models import (
            BaseReport,
            BrowsingReportData,
            RedTeamReportData,
            CombinedReportData,
            discovery_result_to_browsing_data,
            red_team_report_to_red_team_data,
            merge_reports,
        )
        print("✓ report_models imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import report_models: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    try:
        from vibe_code_bench.core.report_generators import (
            BrowsingReportGenerator,
            RedTeamReportGenerator,
        )
        print("✓ report_generators imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import report_generators: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    try:
        from vibe_code_bench.core.combined_report import CombinedReportGenerator
        print("✓ combined_report imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import combined_report: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


def test_data_models():
    """Test that data models can be instantiated."""
    print("\nTesting data models...")
    
    try:
        from vibe_code_bench.core.report_models import BrowsingReportData, RedTeamReportData
        
        # Test BrowsingReportData
        browsing_data = BrowsingReportData(
            base_url="https://example.com",
            timestamp="2025-01-01T00:00:00Z",
            run_id="test_browsing",
            total_pages=10,
        )
        assert browsing_data.base_url == "https://example.com"
        assert browsing_data.total_pages == 10
        print("✓ BrowsingReportData created successfully")
        
        # Test RedTeamReportData
        red_team_data = RedTeamReportData(
            base_url="https://example.com",
            timestamp="2025-01-01T00:00:00Z",
            run_id="test_red_team",
            total_findings=5,
        )
        assert red_team_data.base_url == "https://example.com"
        assert red_team_data.total_findings == 5
        print("✓ RedTeamReportData created successfully")
        
        return True
    except Exception as e:
        print(f"✗ Failed to create data models: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_report_generation():
    """Test that reports can be generated."""
    print("\nTesting report generation...")
    
    try:
        from vibe_code_bench.core.report_models import BrowsingReportData, RedTeamReportData
        from vibe_code_bench.core.report_generators import (
            BrowsingReportGenerator,
            RedTeamReportGenerator,
        )
        
        # Test browsing report generation
        browsing_data = BrowsingReportData(
            base_url="https://example.com",
            timestamp="2025-01-01T00:00:00Z",
            run_id="test_browsing",
            total_pages=10,
            pages_with_forms=2,
            forms_found=3,
        )
        markdown = BrowsingReportGenerator.generate_markdown(browsing_data)
        assert "# Website Discovery Report" in markdown
        assert "https://example.com" in markdown
        assert "Total pages: 10" in markdown
        print("✓ Browsing report markdown generated successfully")
        print(f"  Report length: {len(markdown)} characters")
        
        # Test red team report generation
        red_team_data = RedTeamReportData(
            base_url="https://example.com",
            timestamp="2025-01-01T00:00:00Z",
            run_id="test_red_team",
            total_findings=2,
            findings_by_severity={"High": 1, "Medium": 1},
            tests_executed=5,
            status="vulnerable",
        )
        markdown = RedTeamReportGenerator.generate_markdown(red_team_data)
        assert "# Security Assessment Report" in markdown
        assert "https://example.com" in markdown
        assert "Vulnerabilities found: 2" in markdown
        print("✓ Red team report markdown generated successfully")
        print(f"  Report length: {len(markdown)} characters")
        
        return True
    except Exception as e:
        print(f"✗ Failed to generate reports: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_conversion_utilities():
    """Test conversion utilities with sample data."""
    print("\nTesting conversion utilities...")
    
    try:
        from vibe_code_bench.core.report_models import (
            discovery_result_to_browsing_data,
            red_team_report_to_red_team_data,
        )
        from vibe_code_bench.browsing_agent.models import DiscoveryResult, PageInfo
        from vibe_code_bench.red_team_agent.models import RedTeamReport, SecurityTestResult
        
        # Test browsing conversion
        pages = [
            PageInfo(
                url="https://example.com/page1",
                title="Page 1",
                page_type="homepage",
                has_forms=True,
                forms=[{"action": "/submit", "method": "POST"}],
            ),
            PageInfo(
                url="https://example.com/page2",
                title="Page 2",
                page_type="contact",
                requires_auth=True,
            ),
        ]
        discovery_result = DiscoveryResult(
            base_url="https://example.com",
            discovered_at="2025-01-01T00:00:00Z",
            total_pages=2,
            authentication_required=True,
            pages=pages,
        )
        browsing_data = discovery_result_to_browsing_data(discovery_result, run_id="test")
        assert browsing_data.total_pages == 2
        assert browsing_data.pages_with_forms == 1
        assert browsing_data.pages_requiring_auth == 1
        print("✓ discovery_result_to_browsing_data works correctly")
        
        # Test red team conversion
        red_team_report = RedTeamReport(
            base_url="https://example.com",
            tested_at="2025-01-01T00:00:00Z",
            total_findings=0,
            findings_by_severity={},
            findings_by_type={},
            vulnerabilities=[],
            test_results=[
                SecurityTestResult(
                    test_type="Session Management",
                    target_url="https://example.com",
                    status="safe",
                )
            ],
            testing_methodology={"automated_scanning": True},
        )
        red_team_data = red_team_report_to_red_team_data(red_team_report, run_id="test")
        assert red_team_data.total_findings == 0
        assert red_team_data.tests_executed == 1
        assert red_team_data.status == "safe"
        print("✓ red_team_report_to_red_team_data works correctly")
        
        return True
    except Exception as e:
        print(f"✗ Failed conversion utilities: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing Concise Report System")
    print("=" * 60)
    
    all_passed = True
    
    all_passed &= test_imports()
    all_passed &= test_data_models()
    all_passed &= test_report_generation()
    all_passed &= test_conversion_utilities()
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
