"""Detailed report generators that include process logs, agent outputs, and thinking process."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

from vibe_code_bench.core.paths import get_reports_dir_for_date, get_runs_dir
from vibe_code_bench.core.report_models import BrowsingReportData, RedTeamReportData
from vibe_code_bench.browsing_agent.models import DiscoveryResult
from vibe_code_bench.red_team_agent.models import RedTeamReport, TestingPlan


class BrowsingDetailedReportGenerator:
    """Generates detailed browsing agent reports with process logs and agent thinking."""

    @staticmethod
    def generate_detailed_markdown(
        data: BrowsingReportData,
        discovery_result: Optional[DiscoveryResult] = None,
        testing_plan: Optional[TestingPlan] = None,
        run_dir: Optional[Path] = None,
        agent_output: Optional[str] = None,
    ) -> str:
        """
        Generate detailed markdown report with process information.
        
        Args:
            data: BrowsingReportData object
            discovery_result: Original DiscoveryResult for full details
            testing_plan: TestingPlan generated for red team agent
            run_dir: Optional run directory path to read logs from
            agent_output: Optional agent output/thinking process
            
        Returns:
            Detailed markdown formatted report string
        """
        md = []
        md.append("# Detailed Website Discovery Report")
        md.append("")
        md.append(f"**Target:** {data.base_url}")
        md.append(f"**Discovered:** {data.timestamp}")
        if data.run_id:
            md.append(f"**Run ID:** {data.run_id}")
        md.append("")
        
        # Process Overview
        md.append("## Process Overview")
        md.append("")
        md.append("### Discovery Process")
        md.append("")
        md.append("The browsing agent executed the following process:")
        md.append("")
        md.append("1. **Initialization**: Set up browser, discovery engine, and analysis tools")
        md.append("2. **Robots.txt Analysis**: Parsed robots.txt to identify allowed/disallowed paths")
        md.append("3. **Sitemap Discovery**: Checked for sitemap.xml to discover pages")
        md.append("4. **Link Crawling**: Systematically crawled links from discovered pages")
        if data.tools_used:
            md.append(f"5. **Tools Used**: {', '.join(data.tools_used)}")
        md.append("")
        
        # Agent Output and Thinking Process
        if agent_output:
            md.append("## Agent Output and Thinking Process")
            md.append("")
            md.append("### LLM Agent Guidance")
            md.append("")
            md.append("```")
            md.append(agent_output)
            md.append("```")
            md.append("")
        
        # Error Logs
        error_log_path = None
        if run_dir:
            error_log_path = run_dir / "errors.log"
        if not error_log_path or not error_log_path.exists():
            # Try to find error log in reports folder
            try:
                from vibe_code_bench.core.paths import get_reports_dir_for_date
                from datetime import datetime
                try:
                    dt = datetime.fromisoformat(data.timestamp.replace('Z', '+00:00'))
                    date_str = dt.strftime("%Y-%m-%d")
                except:
                    if len(data.run_id) >= 17:
                        date_part = data.run_id[9:17]
                        date_str = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}"
                    else:
                        date_str = datetime.now().strftime("%Y-%m-%d")
                reports_dir = get_reports_dir_for_date(date_str)
                base_run_id = extract_base_run_id(data.run_id, data.timestamp)
                run_folder = reports_dir / base_run_id
                error_log_path = run_folder / "errors.log"
            except:
                pass
        
        if error_log_path and error_log_path.exists():
            md.append("## Error Log")
            md.append("")
            try:
                with open(error_log_path, "r", encoding="utf-8") as f:
                    error_log_content = f.read()
                    if error_log_content.strip():
                        md.append("```")
                        md.append(error_log_content)
                        md.append("```")
                    else:
                        md.append("*No errors logged.*")
            except Exception as e:
                md.append(f"*Error reading error log file: {e}*")
            md.append("")
            
            # Also try to load errors.json summary
            error_summary_path = error_log_path.parent / "errors.json"
            if error_summary_path.exists():
                try:
                    import json
                    with open(error_summary_path, "r", encoding="utf-8") as f:
                        error_summary = json.load(f)
                    md.append("### Error Summary")
                    md.append("")
                    md.append(f"- **Total Errors**: {error_summary.get('total_errors', 0)}")
                    if error_summary.get('errors_by_type'):
                        md.append("")
                        md.append("**Errors by Type:**")
                        for error_type, count in error_summary['errors_by_type'].items():
                            md.append(f"- {error_type}: {count}")
                    if error_summary.get('errors_by_context'):
                        md.append("")
                        md.append("**Errors by Context:**")
                        for context, count in error_summary['errors_by_context'].items():
                            md.append(f"- {context}: {count}")
                    md.append("")
                except Exception as e:
                    md.append(f"*Error reading error summary: {e}*")
                    md.append("")
        
        # Logs from Run Directory
        if run_dir:
            logs_dir = run_dir / "logs"
            if logs_dir.exists():
                md.append("## Process Logs")
                md.append("")
                log_files = list(logs_dir.glob("*.log"))
                if log_files:
                    for log_file in sorted(log_files)[:5]:  # Limit to first 5 log files
                        md.append(f"### {log_file.name}")
                        md.append("")
                        try:
                            with open(log_file, "r", encoding="utf-8") as f:
                                log_content = f.read()
                                # Show last 100 lines
                                log_lines = log_content.split("\n")
                                if len(log_lines) > 100:
                                    md.append("```")
                                    md.append("\n".join(log_lines[-100:]))
                                    md.append("```")
                                else:
                                    md.append("```")
                                    md.append(log_content)
                                    md.append("```")
                        except Exception as e:
                            md.append(f"*Error reading log file: {e}*")
                        md.append("")
        
        # Testing Plan Generated for Red Team Agent
        if testing_plan:
            md.append("## Testing Plan Generated for Red Team Agent")
            md.append("")
            md.append("Based on the discovery results, the following testing plan was generated:")
            md.append("")
            md.append(f"- **Base URL**: {testing_plan.base_url}")
            md.append(f"- **Total Pages**: {testing_plan.total_pages}")
            md.append(f"- **Total Forms**: {testing_plan.total_forms}")
            md.append(f"- **Total API Endpoints**: {testing_plan.total_api_endpoints}")
            md.append(f"- **Created At**: {testing_plan.created_at}")
            md.append("")
            
            if testing_plan.attack_surfaces:
                md.append("### Attack Surfaces Identified")
                md.append("")
                for surface in testing_plan.attack_surfaces:
                    md.append(f"#### {surface.category} (Priority: {surface.priority})")
                    md.append("")
                    md.append(f"- Items: {len(surface.items)}")
                    if surface.test_suites:
                        md.append(f"- Test Suites: {', '.join(surface.test_suites)}")
                    md.append("")
                    if surface.items:
                        md.append("**Items:**")
                        for item in surface.items[:10]:  # Limit to first 10
                            if isinstance(item, dict):
                                url = item.get("url", item.get("endpoint", "Unknown"))
                                md.append(f"- {url}")
                            else:
                                md.append(f"- {item}")
                        md.append("")
        
        # Full Discovery Results
        if discovery_result:
            md.append("## Complete Discovery Results")
            md.append("")
            md.append(f"### All Discovered Pages ({len(discovery_result.pages)})")
            md.append("")
            for i, page in enumerate(discovery_result.pages, 1):
                md.append(f"{i}. **{page.url}**")
                if page.title:
                    md.append(f"   - Title: {page.title}")
                if page.page_type:
                    md.append(f"   - Type: {page.page_type}")
                if page.status_code:
                    md.append(f"   - Status: {page.status_code}")
                if page.discovered_via:
                    md.append(f"   - Discovered via: {page.discovered_via}")
                if page.has_forms:
                    md.append(f"   - Forms: {len(page.forms)}")
                if page.requires_auth:
                    md.append(f"   - Requires Auth: Yes")
                md.append("")
        
        # Errors
        if data.errors:
            md.append("## Errors Encountered")
            md.append("")
            for error in data.errors:
                md.append(f"- {error}")
            md.append("")
        
        return "\n".join(md)

    @staticmethod
    def save_detailed_report(
        data: BrowsingReportData,
        discovery_result: Optional[DiscoveryResult] = None,
        testing_plan: Optional[TestingPlan] = None,
        run_dir: Optional[Path] = None,
        agent_output: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> Path:
        """
        Save detailed browsing report to markdown file.
        
        Args:
            data: BrowsingReportData object
            discovery_result: Original DiscoveryResult
            testing_plan: TestingPlan generated for red team agent
            run_dir: Optional run directory path
            agent_output: Optional agent output
            run_id: Optional run ID
            
        Returns:
            Path to saved detailed report file
        """
        if run_id:
            data.run_id = run_id

        if not data.run_id:
            data.run_id = f"browsing_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if not data.run_id.startswith("browsing_"):
            data.run_id = f"browsing_{data.run_id}"

        # Extract date from timestamp or run_id
        try:
            dt = datetime.fromisoformat(data.timestamp.replace('Z', '+00:00'))
            date_str = dt.strftime("%Y-%m-%d")
        except:
            if len(data.run_id) >= 17:
                date_part = data.run_id[9:17]
                date_str = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}"
            else:
                date_str = datetime.now().strftime("%Y-%m-%d")
        
        reports_dir = get_reports_dir_for_date(date_str)
        # Use unified run folder (extract base run_id without prefix)
        base_run_id = extract_base_run_id(data.run_id, data.timestamp)
        run_folder = reports_dir / base_run_id
        run_folder.mkdir(parents=True, exist_ok=True)
        report_file = run_folder / f"{data.run_id}_detailed.md"

        markdown_content = BrowsingDetailedReportGenerator.generate_detailed_markdown(
            data, discovery_result, testing_plan, run_dir, agent_output
        )
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        return report_file


class RedTeamDetailedReportGenerator:
    """Generates detailed red team agent reports with process logs and agent thinking."""

    @staticmethod
    def generate_detailed_markdown(
        data: RedTeamReportData,
        red_team_report: Optional[RedTeamReport] = None,
        testing_plan: Optional[TestingPlan] = None,
        run_dir: Optional[Path] = None,
    ) -> str:
        """
        Generate detailed markdown report with process information.
        
        Args:
            data: RedTeamReportData object
            red_team_report: Original RedTeamReport for full details
            testing_plan: TestingPlan used for testing
            run_dir: Optional run directory path to read logs from
            
        Returns:
            Detailed markdown formatted report string
        """
        md = []
        md.append("# Detailed Security Assessment Report")
        md.append("")
        md.append(f"**Target:** {data.base_url}")
        md.append(f"**Tested:** {data.timestamp}")
        if data.run_id:
            md.append(f"**Run ID:** {data.run_id}")
        md.append("")
        
        # Process Overview
        md.append("## Process Overview")
        md.append("")
        md.append("### Security Testing Process")
        md.append("")
        md.append("The red team agent executed the following workflow:")
        md.append("")
        md.append("1. **Report Analysis**: Analyzed browsing report to identify attack surfaces")
        md.append("2. **Testing Plan Generation**: Created comprehensive testing plan")
        md.append("3. **Security Testing**: Executed multiple test suites")
        md.append("4. **Results Aggregation**: Collected and analyzed all findings")
        md.append("5. **Report Generation**: Generated comprehensive security assessment")
        md.append("")
        
        # Testing Plan
        if testing_plan:
            md.append("## Testing Plan")
            md.append("")
            md.append(f"- **Base URL**: {testing_plan.base_url}")
            md.append(f"- **Total Pages**: {testing_plan.total_pages}")
            md.append(f"- **Total Forms**: {testing_plan.total_forms}")
            md.append(f"- **Total API Endpoints**: {testing_plan.total_api_endpoints}")
            md.append(f"- **Created At**: {testing_plan.created_at}")
            md.append("")
            
            if testing_plan.attack_surfaces:
                md.append("### Attack Surfaces")
                md.append("")
                for surface in testing_plan.attack_surfaces:
                    md.append(f"#### {surface.category} (Priority: {surface.priority})")
                    md.append("")
                    md.append(f"- Items: {len(surface.items)}")
                    if surface.test_suites:
                        md.append(f"- Test Suites: {', '.join(surface.test_suites)}")
                    md.append("")
        
        # Error Logs
        error_log_path = None
        if run_dir:
            error_log_path = run_dir / "errors.log"
        if not error_log_path or not error_log_path.exists():
            # Try to find error log in reports folder
            try:
                from vibe_code_bench.core.paths import get_reports_dir_for_date
                from datetime import datetime
                try:
                    dt = datetime.fromisoformat(data.timestamp.replace('Z', '+00:00'))
                    date_str = dt.strftime("%Y-%m-%d")
                except:
                    if len(data.run_id) >= 17:
                        date_part = data.run_id[9:17]
                        date_str = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}"
                    else:
                        date_str = datetime.now().strftime("%Y-%m-%d")
                reports_dir = get_reports_dir_for_date(date_str)
                base_run_id = extract_base_run_id(data.run_id, data.timestamp)
                run_folder = reports_dir / base_run_id
                error_log_path = run_folder / "errors.log"
            except:
                pass
        
        if error_log_path and error_log_path.exists():
            md.append("## Error Log")
            md.append("")
            try:
                with open(error_log_path, "r", encoding="utf-8") as f:
                    error_log_content = f.read()
                    if error_log_content.strip():
                        md.append("```")
                        md.append(error_log_content)
                        md.append("```")
                    else:
                        md.append("*No errors logged.*")
            except Exception as e:
                md.append(f"*Error reading error log file: {e}*")
            md.append("")
            
            # Also try to load errors.json summary
            error_summary_path = error_log_path.parent / "errors.json"
            if error_summary_path.exists():
                try:
                    import json
                    with open(error_summary_path, "r", encoding="utf-8") as f:
                        error_summary = json.load(f)
                    md.append("### Error Summary")
                    md.append("")
                    md.append(f"- **Total Errors**: {error_summary.get('total_errors', 0)}")
                    if error_summary.get('errors_by_type'):
                        md.append("")
                        md.append("**Errors by Type:**")
                        for error_type, count in error_summary['errors_by_type'].items():
                            md.append(f"- {error_type}: {count}")
                    if error_summary.get('errors_by_context'):
                        md.append("")
                        md.append("**Errors by Context:**")
                        for context, count in error_summary['errors_by_context'].items():
                            md.append(f"- {context}: {count}")
                    md.append("")
                except Exception as e:
                    md.append(f"*Error reading error summary: {e}*")
                    md.append("")
        
        # Logs from Run Directory
        if run_dir:
            logs_dir = run_dir / "logs"
            if logs_dir.exists():
                md.append("## Process Logs")
                md.append("")
                log_files = list(logs_dir.glob("*.log"))
                if log_files:
                    for log_file in sorted(log_files):
                        md.append(f"### {log_file.name}")
                        md.append("")
                        try:
                            with open(log_file, "r", encoding="utf-8") as f:
                                log_content = f.read()
                                # Show last 200 lines for detailed report
                                log_lines = log_content.split("\n")
                                if len(log_lines) > 200:
                                    md.append("```")
                                    md.append("\n".join(log_lines[-200:]))
                                    md.append("```")
                                else:
                                    md.append("```")
                                    md.append(log_content)
                                    md.append("```")
                        except Exception as e:
                            md.append(f"*Error reading log file: {e}*")
                        md.append("")
        
        # All Test Results
        if red_team_report and red_team_report.test_results:
            md.append("## All Test Results")
            md.append("")
            for i, result in enumerate(red_team_report.test_results, 1):
                md.append(f"### Test {i}: {result.test_type}")
                md.append("")
                md.append(f"- **Target URL**: {result.target_url}")
                md.append(f"- **Status**: {result.status}")
                md.append(f"- **Execution Time**: {result.execution_time:.2f}s")
                if result.error_message:
                    md.append(f"- **Error**: {result.error_message}")
                if result.findings:
                    md.append(f"- **Findings**: {len(result.findings)}")
                    for finding in result.findings:
                        md.append(f"  - {finding.vulnerability_type} ({finding.severity})")
                md.append("")
        
        # All Vulnerabilities
        if red_team_report and red_team_report.vulnerabilities:
            md.append("## All Vulnerabilities Found")
            md.append("")
            for vuln in red_team_report.vulnerabilities:
                md.append(f"### {vuln.vulnerability_type} ({vuln.severity})")
                md.append("")
                md.append(f"- **Affected URL**: {vuln.affected_url}")
                md.append(f"- **Description**: {vuln.description}")
                md.append(f"- **Proof of Concept**: {vuln.proof_of_concept}")
                md.append(f"- **Remediation**: {vuln.remediation}")
                if vuln.cwe_id:
                    md.append(f"- **CWE ID**: {vuln.cwe_id}")
                if vuln.owasp_category:
                    md.append(f"- **OWASP Category**: {vuln.owasp_category}")
                md.append("")
        
        return "\n".join(md)

    @staticmethod
    def save_detailed_report(
        data: RedTeamReportData,
        red_team_report: Optional[RedTeamReport] = None,
        testing_plan: Optional[TestingPlan] = None,
        run_dir: Optional[Path] = None,
        run_id: Optional[str] = None,
    ) -> Path:
        """
        Save detailed red team report to markdown file.
        
        Args:
            data: RedTeamReportData object
            red_team_report: Original RedTeamReport
            testing_plan: TestingPlan used
            run_dir: Optional run directory path
            run_id: Optional run ID
            
        Returns:
            Path to saved detailed report file
        """
        if run_id:
            data.run_id = run_id

        if not data.run_id:
            data.run_id = f"red_team_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if not data.run_id.startswith("red_team_"):
            data.run_id = f"red_team_{data.run_id}"

        # Extract date from timestamp or run_id
        try:
            dt = datetime.fromisoformat(data.timestamp.replace('Z', '+00:00'))
            date_str = dt.strftime("%Y-%m-%d")
        except:
            if len(data.run_id) >= 17:
                date_part = data.run_id[9:17]
                date_str = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}"
            else:
                date_str = datetime.now().strftime("%Y-%m-%d")
        
        reports_dir = get_reports_dir_for_date(date_str)
        # Use unified run folder (extract base run_id without prefix)
        base_run_id = extract_base_run_id(data.run_id, data.timestamp)
        run_folder = reports_dir / base_run_id
        run_folder.mkdir(parents=True, exist_ok=True)
        report_file = run_folder / f"{data.run_id}_detailed.md"

        markdown_content = RedTeamDetailedReportGenerator.generate_detailed_markdown(
            data, red_team_report, testing_plan, run_dir
        )
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(markdown_content)

        return report_file
