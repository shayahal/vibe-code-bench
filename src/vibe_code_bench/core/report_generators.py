"""Report generators for concise markdown reports."""

from typing import Optional
from pathlib import Path

from vibe_code_bench.core.paths import get_reports_dir, get_reports_dir_for_date, extract_base_run_id
from vibe_code_bench.core.report_models import BrowsingReportData, RedTeamReportData


class BrowsingReportGenerator:
    """Generates concise browsing agent reports."""

    @staticmethod
    def generate_markdown(data: BrowsingReportData) -> str:
        """
        Generate concise markdown report from BrowsingReportData.

        Args:
            data: BrowsingReportData object

        Returns:
            Markdown formatted report string
        """
        md = []
        md.append("# Website Discovery Report")
        md.append("")
        md.append(f"**Target:** {data.base_url}")
        md.append(f"**Discovered:** {data.timestamp}")
        if data.run_id:
            md.append(f"**Run ID:** {data.run_id}")
        md.append("")

        # Summary
        md.append("## Summary")
        md.append("")
        md.append(f"- Total pages: {data.total_pages}")
        md.append(f"- Pages with forms: {data.pages_with_forms}")
        md.append(f"- Auth required: {'Yes' if data.authentication_required else 'No'}")
        discovery_methods_str = ', '.join(data.discovery_methods.keys()) if data.discovery_methods else 'crawl'
        # Filter out 'unknown' if there are other methods
        if 'unknown' in discovery_methods_str and len(data.discovery_methods) > 1:
            discovery_methods_str = ', '.join([k for k in data.discovery_methods.keys() if k != 'unknown'])
        md.append(f"- Discovery method: {discovery_methods_str}")
        if data.tools_used:
            md.append(f"- Tools operated: {len(data.tools_used)} ({', '.join(data.tools_used)})")
        md.append("")

        # Key Pages
        if data.page_types:
            md.append("## Key Pages")
            md.append("")
            for page_type, count in sorted(data.page_types.items(), key=lambda x: x[1], reverse=True):
                md.append(f"- {page_type}: {count} page{'s' if count != 1 else ''}")
            md.append("")

        # Forms and Auth
        if data.forms_found > 0 or data.auth_endpoints > 0:
            md.append("## Forms & Authentication")
            md.append("")
            if data.forms_found > 0:
                md.append(f"- Forms found: {data.forms_found}")
            if data.auth_endpoints > 0:
                md.append(f"- Auth endpoints: {data.auth_endpoints}")
            md.append("")

        # Discovery Details
        if data.key_pages:
            md.append("## Discovery Details")
            md.append("")
            md.append("Important pages/endpoints discovered:")
            md.append("")
            for page in data.key_pages[:10]:  # Limit to top 10
                page_info = f"- **{page.get('url', 'Unknown')}**"
                if page.get("title"):
                    page_info += f" - {page['title']}"
                if page.get("page_type"):
                    page_info += f" ({page['page_type']})"
                if page.get("has_forms"):
                    page_info += " [Has Forms]"
                if page.get("requires_auth"):
                    page_info += " [Requires Auth]"
                md.append(page_info)
            md.append("")
            if data.tools_used:
                md.append(f"*Tools used: {', '.join(data.tools_used)}*")
                md.append("")

        # Errors
        if data.errors:
            md.append("## Errors")
            md.append("")
            for error in data.errors[:5]:  # Limit to first 5 errors
                md.append(f"- {error}")
            md.append("")

        return "\n".join(md)

    @staticmethod
    def save_report(data: BrowsingReportData, run_id: Optional[str] = None) -> Path:
        """
        Save browsing report to markdown file.

        Args:
            data: BrowsingReportData object
            run_id: Optional run ID (if not provided, uses data.run_id or generates timestamp)

        Returns:
            Path to saved report file
        """
        if run_id:
            data.run_id = run_id

        if not data.run_id:
            from datetime import datetime
            data.run_id = f"browsing_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Ensure filename always has browsing_ prefix
        if not data.run_id.startswith("browsing_"):
            data.run_id = f"browsing_{data.run_id}"

        # Extract date from timestamp or run_id
        from datetime import datetime
        try:
            # Try to parse timestamp
            dt = datetime.fromisoformat(data.timestamp.replace('Z', '+00:00'))
            date_str = dt.strftime("%Y-%m-%d")
        except:
            # Fallback to extracting from run_id or use today
            if len(data.run_id) >= 17:  # browsing_YYYYMMDD_HHMMSS
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

        markdown_content = BrowsingReportGenerator.generate_markdown(data)
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        return report_file


class RedTeamReportGenerator:
    """Generates concise red team agent reports."""

    @staticmethod
    def generate_markdown(data: RedTeamReportData) -> str:
        """
        Generate concise markdown report from RedTeamReportData.

        Args:
            data: RedTeamReportData object

        Returns:
            Markdown formatted report string
        """
        md = []
        md.append("# Security Assessment Report")
        md.append("")
        md.append(f"**Target:** {data.base_url}")
        md.append(f"**Tested:** {data.timestamp}")
        if data.run_id:
            md.append(f"**Run ID:** {data.run_id}")
        md.append("")

        # Summary
        md.append("## Summary")
        md.append("")
        md.append(f"- Vulnerabilities found: {data.total_findings}")
        md.append(f"- Tests executed: {data.tests_executed}")
        if data.tools_used:
            md.append(f"- Tools used: {len(data.tools_used)} ({', '.join(data.tools_used)})")
        md.append(f"- Status: {data.status}")
        md.append("")

        # Findings
        if data.findings_by_severity:
            md.append("## Findings")
            md.append("")
            for severity in ["Critical", "High", "Medium", "Low"]:
                count = data.findings_by_severity.get(severity, 0)
                if count > 0:
                    md.append(f"- {severity}: {count}")
            md.append("")

        # Key Vulnerabilities
        if data.key_vulnerabilities:
            md.append("## Key Vulnerabilities")
            md.append("")
            for vuln in data.key_vulnerabilities:
                md.append(f"### {vuln.get('vulnerability_type', 'Unknown')} ({vuln.get('severity', 'Unknown')})")
                md.append("")
                md.append(f"- **Affected URL:** {vuln.get('affected_url', 'Unknown')}")
                md.append(f"- **Description:** {vuln.get('description', 'No description')}")
                if vuln.get("test_type"):
                    md.append(f"- **Found by:** {vuln['test_type']}")
                md.append("")
            md.append("")

        # Test Results
        if data.test_results_summary:
            md.append("## Test Results")
            md.append("")
            md.append("Summary of test types, tools used and results:")
            md.append("")
            for test_type, results in data.test_results_summary.items():
                md.append(f"### {test_type}")
                md.append("")
                md.append(f"- Total: {results.get('total', 0)}")
                if results.get("vulnerable", 0) > 0:
                    md.append(f"- Vulnerable: {results['vulnerable']}")
                if results.get("safe", 0) > 0:
                    md.append(f"- Safe: {results['safe']}")
                if results.get("error", 0) > 0:
                    md.append(f"- Errors: {results['error']}")
                md.append("")
            md.append("")

        return "\n".join(md)

    @staticmethod
    def save_report(data: RedTeamReportData, run_id: Optional[str] = None) -> Path:
        """
        Save red team report to markdown file.

        Args:
            data: RedTeamReportData object
            run_id: Optional run ID (if not provided, uses data.run_id or generates timestamp)

        Returns:
            Path to saved report file
        """
        if run_id:
            data.run_id = run_id

        if not data.run_id:
            from datetime import datetime
            data.run_id = f"red_team_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Ensure filename always has red_team_ prefix
        if not data.run_id.startswith("red_team_"):
            data.run_id = f"red_team_{data.run_id}"

        # Extract date from timestamp or run_id
        from datetime import datetime
        try:
            # Try to parse timestamp
            dt = datetime.fromisoformat(data.timestamp.replace('Z', '+00:00'))
            date_str = dt.strftime("%Y-%m-%d")
        except:
            # Fallback to extracting from run_id or use today
            if len(data.run_id) >= 17:  # red_team_YYYYMMDD_HHMMSS
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

        markdown_content = RedTeamReportGenerator.generate_markdown(data)
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        return report_file
