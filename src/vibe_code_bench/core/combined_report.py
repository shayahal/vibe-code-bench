"""Combined report generator that merges browsing and red team reports."""

import json
from pathlib import Path
from typing import Optional

from vibe_code_bench.core.paths import get_reports_dir, get_reports_dir_for_date, get_absolute_path, extract_base_run_id
from vibe_code_bench.core.report_models import (
    CombinedReportData,
    BrowsingReportData,
    RedTeamReportData,
    discovery_result_to_browsing_data,
    red_team_report_to_red_team_data,
    merge_reports,
)
from vibe_code_bench.browsing_agent.models import DiscoveryResult
from vibe_code_bench.red_team_agent.models import RedTeamReport


class CombinedReportGenerator:
    """Generates combined reports merging browsing and red team data."""

    @staticmethod
    def generate_markdown(data: CombinedReportData) -> str:
        """
        Generate concise combined markdown report.

        Args:
            data: CombinedReportData object

        Returns:
            Markdown formatted report string
        """
        md = []
        md.append("# Combined Security Assessment Report")
        md.append("")
        md.append(f"**Target:** {data.base_url}")
        if data.browsing_data:
            md.append(f"**Discovery:** {data.browsing_data.timestamp}")
        if data.red_team_data:
            md.append(f"**Testing:** {data.red_team_data.timestamp}")
        if data.run_id:
            md.append(f"**Run ID:** {data.run_id}")
        md.append("")

        # Discovery Summary
        if data.browsing_data:
            md.append("## Discovery Summary")
            md.append("")
            md.append(f"- Total pages discovered: {data.browsing_data.total_pages}")
            md.append(f"- Pages with forms: {data.browsing_data.pages_with_forms}")
            md.append(f"- Pages requiring auth: {data.browsing_data.pages_requiring_auth}")
            md.append(f"- Forms found: {data.browsing_data.forms_found}")
            md.append(f"- Auth endpoints: {data.browsing_data.auth_endpoints}")
            if data.browsing_data.tools_used:
                md.append(f"- Discovery tools: {', '.join(data.browsing_data.tools_used)}")
            md.append("")

        # Security Assessment Summary
        if data.red_team_data:
            md.append("## Security Assessment Summary")
            md.append("")
            md.append(f"- Vulnerabilities found: {data.red_team_data.total_findings}")
            md.append(f"- Tests executed: {data.red_team_data.tests_executed}")
            md.append(f"- Status: {data.red_team_data.status}")
            if data.red_team_data.tools_used:
                md.append(f"- Testing tools: {', '.join(data.red_team_data.tools_used)}")
            md.append("")

            # Findings breakdown
            if data.red_team_data.findings_by_severity:
                md.append("### Findings by Severity")
                md.append("")
                for severity in ["Critical", "High", "Medium", "Low"]:
                    count = data.red_team_data.findings_by_severity.get(severity, 0)
                    if count > 0:
                        md.append(f"- {severity}: {count}")
                md.append("")

        # Correlation
        if data.correlation:
            md.append("## Correlation")
            md.append("")
            md.append("Pages with vulnerabilities:")
            md.append("")
            for corr in data.correlation:
                md.append(f"- **{corr.get('page_url', 'Unknown')}**")
                md.append(f"  - Page type: {corr.get('page_type', 'unknown')}")
                md.append(f"  - Vulnerability: {corr.get('vulnerability_type', 'Unknown')} ({corr.get('severity', 'Unknown')})")
                md.append("")
        else:
            if data.red_team_data and data.red_team_data.total_findings == 0:
                md.append("## Correlation")
                md.append("")
                md.append("No vulnerabilities found in discovered pages.")
                md.append("")

        return "\n".join(md)

    @staticmethod
    def load_browsing_report(report_path: str) -> DiscoveryResult:
        """
        Load browsing report from JSON file.

        Args:
            report_path: Path to browsing report JSON file

        Returns:
            DiscoveryResult object
        """
        abs_path = get_absolute_path(report_path)
        if not abs_path.exists():
            # Try reports directory
            reports_dir = get_reports_dir()
            abs_path = reports_dir / report_path
            if not abs_path.exists():
                raise FileNotFoundError(f"Browsing report not found: {report_path}")

        with open(abs_path, "r", encoding="utf-8") as f:
            report_dict = json.load(f)

        # Convert dict to DiscoveryResult
        from vibe_code_bench.browsing_agent.models import PageInfo

        pages = [PageInfo(**page) for page in report_dict.get("pages", [])]
        
        return DiscoveryResult(
            base_url=report_dict["base_url"],
            discovered_at=report_dict["discovered_at"],
            total_pages=report_dict["total_pages"],
            authentication_required=report_dict.get("authentication_required", False),
            pages=pages,
            sitemap_used=report_dict.get("sitemap_used", False),
            robots_respected=report_dict.get("robots_respected", True),
            errors=report_dict.get("errors", []),
        )

    @staticmethod
    def load_red_team_report(report_path: Optional[str]) -> RedTeamReport:
        """
        Load red team report from JSON file.

        Args:
            report_path: Path to red team report JSON file

        Returns:
            RedTeamReport object
        """
        if report_path is None:
            raise ValueError("Red team report path cannot be None")
        abs_path = get_absolute_path(report_path)
        if not abs_path.exists():
            # Try reports directory
            reports_dir = get_reports_dir()
            abs_path = reports_dir / report_path
            if not abs_path.exists():
                raise FileNotFoundError(f"Red team report not found: {report_path}")

        with open(abs_path, "r", encoding="utf-8") as f:
            report_dict = json.load(f)

        # Convert dict to RedTeamReport
        from vibe_code_bench.red_team_agent.models import VulnerabilityFinding, SecurityTestResult

        vulnerabilities = [
            VulnerabilityFinding(**v) for v in report_dict.get("vulnerabilities", [])
        ]
        test_results = [
            SecurityTestResult(**tr) for tr in report_dict.get("test_results", [])
        ]

        return RedTeamReport(
            base_url=report_dict["base_url"],
            tested_at=report_dict["tested_at"],
            total_findings=report_dict["total_findings"],
            findings_by_severity=report_dict.get("findings_by_severity", {}),
            findings_by_type=report_dict.get("findings_by_type", {}),
            vulnerabilities=vulnerabilities,
            test_results=test_results,
            testing_methodology=report_dict.get("testing_methodology", {}),
            summary=report_dict.get("summary", ""),
            recommendations=report_dict.get("recommendations", []),
        )

    @staticmethod
    def generate_combined_report(
        browsing_report_path: str,
        red_team_report_path: Optional[str],
        run_id: Optional[str] = None,
        browsing_tools_used: Optional[list] = None,
    ) -> CombinedReportData:
        """
        Generate combined report from browsing and red team report paths.

        Args:
            browsing_report_path: Path to browsing report JSON file
            red_team_report_path: Path to red team report JSON file (can be None)
            run_id: Optional run ID for the combined report
            browsing_tools_used: Optional list of tools used during browsing

        Returns:
            CombinedReportData object
        """
        # Load reports
        browsing_result = CombinedReportGenerator.load_browsing_report(browsing_report_path)
        red_team_report = None
        if red_team_report_path:
            red_team_report = CombinedReportGenerator.load_red_team_report(red_team_report_path)

        # Convert to unified models
        browsing_data = discovery_result_to_browsing_data(
            browsing_result, run_id=run_id, tools_used=browsing_tools_used
        )
        red_team_data = None
        if red_team_report:
            red_team_data = red_team_report_to_red_team_data(red_team_report, run_id=run_id)

        # Merge reports (handle case where red_team_data might be None)
        if red_team_data:
            combined_data = merge_reports(browsing_data, red_team_data)
        else:
            # Create combined data with only browsing data
            from vibe_code_bench.core.report_models import CombinedReportData
            combined_data = CombinedReportData(
                base_url=browsing_data.base_url,
                timestamp=browsing_data.timestamp,
                run_id=run_id or browsing_data.run_id,
                browsing_data=browsing_data,
                red_team_data=None,
                correlation=[],
            )
        if run_id:
            combined_data.run_id = run_id

        return combined_data

    @staticmethod
    def save_report(data: CombinedReportData, run_id: Optional[str] = None) -> Path:
        """
        Save combined report to markdown file.

        Args:
            data: CombinedReportData object
            run_id: Optional run ID (if not provided, uses data.run_id or generates timestamp)

        Returns:
            Path to saved report file
        """
        if run_id:
            data.run_id = run_id

        if not data.run_id:
            from datetime import datetime
            data.run_id = f"combined_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Ensure filename always has combined_ prefix
        if not data.run_id.startswith("combined_"):
            data.run_id = f"combined_{data.run_id}"

        # Extract date from timestamp or run_id
        from datetime import datetime
        try:
            # Try to parse timestamp
            dt = datetime.fromisoformat(data.timestamp.replace('Z', '+00:00'))
            date_str = dt.strftime("%Y-%m-%d")
        except:
            # Fallback to extracting from run_id or use today
            if len(data.run_id) >= 17:  # combined_YYYYMMDD_HHMMSS
                date_part = data.run_id[9:17]  # YYYYMMDD
                date_str = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}"
            else:
                date_str = datetime.now().strftime("%Y-%m-%d")
        
        reports_dir = get_reports_dir_for_date(date_str)
        # Use unified run folder (extract base run_id without prefix)
        base_run_id = extract_base_run_id(data.run_id, data.timestamp)
        run_folder = reports_dir / base_run_id
        run_folder.mkdir(parents=True, exist_ok=True)
        report_file = run_folder / f"{data.run_id}.md"

        markdown_content = CombinedReportGenerator.generate_markdown(data)
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        return report_file


# Standalone convenience function for generating and saving combined reports
def generate_combined_report(
    browsing_report_path: str,
    red_team_report_path: Optional[str],
    run_id: Optional[str] = None,
    browsing_tools_used: Optional[list] = None,
) -> Path:
    """
    Generate and save combined report from browsing and red team report paths.
    
    This is a convenience function that loads both reports, merges them,
    and saves the combined markdown report in one call.

    Args:
        browsing_report_path: Path to browsing report JSON file
        red_team_report_path: Path to red team report JSON file
        run_id: Optional run ID for the combined report
        browsing_tools_used: Optional list of tools used during browsing

    Returns:
        Path to saved combined report markdown file
    """
    combined_data = CombinedReportGenerator.generate_combined_report(
        browsing_report_path=browsing_report_path,
        red_team_report_path=red_team_report_path,
        run_id=run_id,
        browsing_tools_used=browsing_tools_used,
    )
    return CombinedReportGenerator.save_report(combined_data, run_id=run_id)
