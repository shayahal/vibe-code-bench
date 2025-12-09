"""Report generator for aggregating findings and creating comprehensive security reports."""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from vibe_code_bench.core.paths import get_reports_dir
from vibe_code_bench.red_team_agent.models import (
    VulnerabilityFinding,
    SecurityTestResult,
    RedTeamReport,
)
from vibe_code_bench.red_team_agent.logging_config import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generates comprehensive security assessment reports."""

    def __init__(self, base_url: str, testing_plan: Optional[Any] = None):
        """
        Initialize report generator.

        Args:
            base_url: Base URL of the tested website
            testing_plan: Optional TestingPlan object for additional context
        """
        self.logger = get_logger(f"{__name__}.ReportGenerator")
        self.base_url = base_url
        self.testing_plan = testing_plan

    def aggregate_findings(
        self, test_results: List[SecurityTestResult]
    ) -> List[VulnerabilityFinding]:
        """
        Aggregate and deduplicate findings from all test results.

        Args:
            test_results: List of SecurityTestResult objects

        Returns:
            List of deduplicated VulnerabilityFinding objects
        """
        self.logger.info("[PHASE] Results Aggregation - Aggregate Findings - Started")

        all_findings = []
        seen_findings = set()

        for result in test_results:
            for finding in result.findings:
                # Create a unique key for deduplication
                finding_key = (
                    finding.vulnerability_type,
                    finding.affected_url,
                    finding.description[:100],  # First 100 chars of description
                )

                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    all_findings.append(finding)

        self.logger.info(f"[PHASE] Aggregated {len(all_findings)} unique findings from {len(test_results)} test results")
        return all_findings

    def categorize_findings(
        self, findings: List[VulnerabilityFinding]
    ) -> Dict[str, Any]:
        """
        Categorize findings by severity and type.

        Args:
            findings: List of VulnerabilityFinding objects

        Returns:
            Dictionary with categorized findings
        """
        self.logger.info("[PHASE] Results Aggregation - Categorize Findings - Started")

        findings_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        findings_by_type = {}

        for finding in findings:
            # Count by severity
            severity = finding.severity
            if severity in findings_by_severity:
                findings_by_severity[severity] += 1

            # Count by type
            vuln_type = finding.vulnerability_type
            findings_by_type[vuln_type] = findings_by_type.get(vuln_type, 0) + 1

        self.logger.info(f"[PHASE] Findings by severity: {findings_by_severity}")
        self.logger.info(f"[PHASE] Findings by type: {findings_by_type}")

        return {
            "by_severity": findings_by_severity,
            "by_type": findings_by_type,
        }

    def generate_summary(
        self, 
        findings: List[VulnerabilityFinding], 
        categories: Dict[str, Any],
        test_results: List[SecurityTestResult],
        testing_methodology: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate executive summary as a narrative of the run.

        Args:
            findings: List of VulnerabilityFinding objects
            categories: Categorized findings dictionary
            test_results: List of SecurityTestResult objects
            testing_methodology: Optional testing methodology information

        Returns:
            Narrative summary string
        """
        total = len(findings)
        critical = categories["by_severity"]["Critical"]
        high = categories["by_severity"]["High"]
        medium = categories["by_severity"]["Medium"]
        low = categories["by_severity"]["Low"]
        
        # Analyze test results to create narrative
        total_tests = len(test_results)
        test_types = {}
        vulnerable_tests = 0
        safe_tests = 0
        error_tests = 0
        
        for result in test_results:
            test_type = result.test_type
            test_types[test_type] = test_types.get(test_type, 0) + 1
            
            if result.status == "vulnerable":
                vulnerable_tests += 1
            elif result.status == "safe":
                safe_tests += 1
            elif result.status == "error":
                error_tests += 1
        
        # Count unique URLs tested
        tested_urls = set()
        for result in test_results:
            tested_urls.add(result.target_url)
        
        # Build narrative summary
        summary_parts = []
        
        summary_parts.append(f"A security assessment was conducted on {self.base_url} using a combination of automated scanning tools and LLM-guided testing.")
        
        if total_tests > 0:
            url_text = f"{len(tested_urls)} unique URL{'s' if len(tested_urls) != 1 else ''}"
            summary_parts.append(f"The assessment executed {total_tests} security test{'s' if total_tests != 1 else ''} across {url_text}.")
        
        if test_types:
            test_type_list = ", ".join([f"{count} {test_type.lower()} test{'s' if count > 1 else ''}" for test_type, count in sorted(test_types.items(), key=lambda x: x[1], reverse=True)])
            summary_parts.append(f"Testing included {test_type_list}.")
        
        if total == 0:
            summary_parts.append("No security vulnerabilities were identified during this assessment.")
            if safe_tests > 0:
                summary_parts.append(f"All {safe_tests} test{'s' if safe_tests != 1 else ''} completed successfully with no findings.")
        else:
            summary_parts.append(f"The assessment identified {total} security vulnerability{'ies' if total != 1 else ''}.")
            if critical > 0:
                summary_parts.append(f"Of particular concern are {critical} critical severity finding{'s' if critical != 1 else ''} that require immediate attention.")
            if high > 0:
                summary_parts.append(f"Additionally, {high} high severity issue{'s' if high != 1 else ''} were discovered.")
            if medium > 0:
                summary_parts.append(f"The assessment also found {medium} medium severity vulnerability{'ies' if medium != 1 else ''}.")
            if low > 0:
                summary_parts.append(f"Finally, {low} low severity issue{'s' if low != 1 else ''} were identified.")
        
        if error_tests > 0:
            summary_parts.append(f"Note: {error_tests} test{'s' if error_tests != 1 else ''} encountered errors during execution and may require manual review.")
        
        summary_parts.append("All findings should be reviewed and validated by security professionals before remediation.")
        
        return " ".join(summary_parts)

    def generate_recommendations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        """
        Generate remediation recommendations.

        Args:
            findings: List of VulnerabilityFinding objects

        Returns:
            List of recommendation strings
        """
        recommendations = []

        # Collect unique remediation advice
        remediation_set = set()
        for finding in findings:
            if finding.remediation:
                remediation_set.add(finding.remediation)

        recommendations.extend(sorted(remediation_set))

        # Add general recommendations
        general_recommendations = [
            "Implement a comprehensive security testing program",
            "Regularly update and patch all dependencies",
            "Implement security headers (CSP, HSTS, etc.)",
            "Use parameterized queries for all database operations",
            "Implement proper input validation and sanitization",
            "Use Content Security Policy (CSP) to prevent XSS",
            "Implement CSRF tokens on all state-changing operations",
            "Use strong authentication mechanisms and session management",
            "Implement proper access control and authorization checks",
            "Regular security audits and penetration testing",
        ]

        recommendations.extend(general_recommendations)

        return recommendations

    def generate_report(
        self,
        test_results: List[SecurityTestResult],
        testing_methodology: Optional[Dict[str, Any]] = None,
    ) -> RedTeamReport:
        """
        Generate comprehensive security assessment report.

        Args:
            test_results: List of SecurityTestResult objects
            testing_methodology: Optional testing methodology information

        Returns:
            RedTeamReport object
        """
        self.logger.info("[PHASE] Results Aggregation - Generate Report - Started")

        # Aggregate findings
        findings = self.aggregate_findings(test_results)

        # Categorize findings
        categories = self.categorize_findings(findings)

        # Generate summary
        summary = self.generate_summary(findings, categories, test_results, testing_methodology)

        # Generate recommendations
        recommendations = self.generate_recommendations(findings)

        # Create report
        report = RedTeamReport(
            base_url=self.base_url,
            tested_at=datetime.utcnow().isoformat(),
            total_findings=len(findings),
            findings_by_severity=categories["by_severity"],
            findings_by_type=categories["by_type"],
            vulnerabilities=findings,
            test_results=test_results,
            testing_methodology=testing_methodology or {},
            summary=summary,
            recommendations=recommendations,
        )

        self.logger.info("[PHASE] Results Aggregation - Generate Report - Completed")
        self.logger.info(f"[PHASE] Report generated with {len(findings)} findings")

        return report

    def save_report(self, report: RedTeamReport, run_id: Optional[str] = None, run_dir: Optional[Path] = None) -> Path:
        """
        Save report to file (JSON and Markdown).

        Args:
            report: RedTeamReport object
            run_id: Optional run ID for filename
            run_dir: Optional run directory for markdown report

        Returns:
            Path to saved JSON report file
        """
        self.logger.info("[PHASE] Results Aggregation - Save Report - Started")

        if run_id is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            run_id = f"red_team_{timestamp}"

        reports_dir = get_reports_dir()
        report_file = reports_dir / f"{run_id}.json"

        # Convert report to dict and save JSON
        report_dict = report.to_dict()
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)

        self.logger.info(f"[PHASE] JSON report saved to: {report_file}")

        # Save markdown report if run_dir is provided
        if run_dir:
            markdown_file = run_dir / f"{run_id}_report.md"
            markdown_content = self._generate_markdown_report(report)
            with open(markdown_file, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            self.logger.info(f"[PHASE] Markdown report saved to: {markdown_file}")
            
            # Save summary markdown
            summary_file = run_dir / f"{run_id}_summary.md"
            summary_content = self._generate_summary_markdown(report, report_file)
            with open(summary_file, "w", encoding="utf-8") as f:
                f.write(summary_content)
            self.logger.info(f"[PHASE] Summary markdown saved to: {summary_file}")

        return report_file

    def _generate_markdown_report(self, report: RedTeamReport) -> str:
        """
        Generate markdown report from RedTeamReport.

        Args:
            report: RedTeamReport object

        Returns:
            Markdown formatted report string
        """
        md = []
        md.append("# Security Assessment Report")
        md.append("")
        md.append(f"**Target Website:** {report.base_url}")
        md.append(f"**Assessment Date:** {report.tested_at}")
        md.append(f"**Run ID:** {report.tested_at.split('T')[0].replace('-', '')}")
        md.append("")
        md.append("---")
        md.append("")

        # Executive Summary
        md.append("## Executive Summary")
        md.append("")
        md.append(report.summary)
        md.append("")

        # Findings Overview
        md.append("## Findings Overview")
        md.append("")
        md.append(f"- **Total Vulnerabilities Found:** {report.total_findings}")
        md.append("")
        md.append("### Findings by Severity")
        md.append("")
        for severity in ["Critical", "High", "Medium", "Low"]:
            count = report.findings_by_severity.get(severity, 0)
            md.append(f"- **{severity}:** {count}")
        md.append("")

        if report.findings_by_type:
            md.append("### Findings by Type")
            md.append("")
            for vuln_type, count in sorted(
                report.findings_by_type.items(), key=lambda x: x[1], reverse=True
            ):
                md.append(f"- **{vuln_type}:** {count}")
            md.append("")

        # Detailed Vulnerabilities
        if report.vulnerabilities:
            md.append("## Detailed Vulnerabilities")
            md.append("")
            for i, vuln in enumerate(report.vulnerabilities, 1):
                md.append(f"### {i}. {vuln.vulnerability_type} ({vuln.severity})")
                md.append("")
                md.append(f"- **Affected URL:** {vuln.affected_url}")
                md.append(f"- **Description:** {vuln.description}")
                md.append(f"- **OWASP Category:** {vuln.owasp_category}")
                if vuln.cwe_id:
                    md.append(f"- **CWE ID:** {vuln.cwe_id}")
                md.append("")
                md.append("#### Proof of Concept")
                md.append("")
                md.append(f"```")
                md.append(vuln.proof_of_concept)
                md.append(f"```")
                md.append("")
                md.append("#### Remediation")
                md.append("")
                md.append(vuln.remediation)
                md.append("")
                md.append("---")
                md.append("")
        else:
            md.append("## Detailed Vulnerabilities")
            md.append("")
            md.append("No vulnerabilities were identified during this assessment.")
            md.append("")

        # Testing Methodology
        md.append("## Testing Methodology")
        md.append("")
        md.append("This security assessment was conducted using the following methods:")
        md.append("")
        md.append(f"- **Automated Scanning:** {'Enabled' if report.testing_methodology.get('automated_scanning') else 'Disabled'}")
        md.append(f"- **LLM-Guided Testing:** {'Enabled' if report.testing_methodology.get('llm_testing') else 'Disabled'}")
        md.append(f"- **Anchor Browser Tools:** {'Enabled' if report.testing_methodology.get('anchor_browser') else 'Disabled'}")
        md.append(f"- **Total Tests Executed:** {report.testing_methodology.get('test_results_count', 0)}")
        md.append("")
        md.append("### Test Categories")
        md.append("")
        md.append("The following security test categories were executed:")
        md.append("")
        md.append("1. **Automated Vulnerability Scanning** - Using external tools (nuclei, wapiti3, nikto) if available")
        md.append("2. **Form Testing** - SQL injection, XSS, and CSRF testing on web forms")
        md.append("3. **Authentication Testing** - Login forms, session management, authorization bypass")
        md.append("4. **API Endpoint Testing** - Authentication bypass, rate limiting, input validation")
        md.append("5. **LLM-Guided Testing** - Intelligent, context-aware testing using AI agents")
        md.append("")

        # Test Results Summary
        md.append("### Test Results Summary")
        md.append("")
        test_types = {}
        for result in report.test_results:
            test_type = result.test_type
            if test_type not in test_types:
                test_types[test_type] = {"total": 0, "vulnerable": 0, "safe": 0, "error": 0}
            test_types[test_type]["total"] += 1
            test_types[test_type][result.status] = test_types[test_type].get(result.status, 0) + 1

        for test_type, counts in test_types.items():
            md.append(f"#### {test_type}")
            md.append("")
            md.append(f"- Total Tests: {counts['total']}")
            md.append(f"- Vulnerable: {counts.get('vulnerable', 0)}")
            md.append(f"- Safe: {counts.get('safe', 0)}")
            md.append(f"- Errors: {counts.get('error', 0)}")
            md.append("")

        # Recommendations
        if report.recommendations:
            md.append("## Recommendations")
            md.append("")
            md.append("Based on this security assessment, the following recommendations are provided:")
            md.append("")
            for i, rec in enumerate(report.recommendations, 1):
                md.append(f"{i}. {rec}")
            md.append("")

        # Appendix
        md.append("## Appendix")
        md.append("")
        md.append("### Test Execution Details")
        md.append("")
        md.append("| Test Type | Target URL | Status | Execution Time (s) | Findings |")
        md.append("|-----------|------------|--------|-------------------|----------|")
        for result in report.test_results[:20]:  # Limit to first 20 for readability
            exec_time = f"{result.execution_time:.2f}" if result.execution_time > 0 else "N/A"
            findings_count = len(result.findings)
            url_display = result.target_url[:50] + "..." if len(result.target_url) > 50 else result.target_url
            md.append(f"| {result.test_type} | `{url_display}` | {result.status} | {exec_time} | {findings_count} |")
        md.append("")

        if len(report.test_results) > 20:
            md.append(f"*Note: Showing first 20 of {len(report.test_results)} test results. See JSON report for complete details.*")
            md.append("")

        md.append("---")
        md.append("")
        md.append(f"*Report generated on {report.tested_at}*")
        md.append("")

        return "\n".join(md)

    def _generate_summary_markdown(self, report: RedTeamReport, report_file: Path) -> str:
        """
        Generate summary markdown report.

        Args:
            report: RedTeamReport object
            report_file: Path to the JSON report file

        Returns:
            Markdown formatted summary string
        """
        from urllib.parse import urlparse
        
        md = []
        domain = urlparse(report.base_url).netloc
        
        # Use relative path for report file
        try:
            from vibe_code_bench.core.paths import get_repo_root
            repo_root = get_repo_root()
            try:
                report_file_relative = report_file.relative_to(repo_root)
            except ValueError:
                # If not relative to repo root, use filename
                report_file_relative = report_file.name
        except Exception:
            report_file_relative = report_file.name
        
        md.append(f"Security Assessment Results for {domain}")
        md.append("")
        md.append(f"Report generated: {report_file_relative}")
        md.append("")
        md.append("## Summary")
        md.append("")
        md.append(f"Total vulnerabilities found: {report.total_findings}")
        md.append("")
        md.append(f"Tests executed: {len(report.test_results)}")
        md.append("")
        
        # Determine status
        vulnerable_tests = sum(1 for r in report.test_results if r.status == "vulnerable")
        error_tests = sum(1 for r in report.test_results if r.status == "error")
        safe_tests = sum(1 for r in report.test_results if r.status == "safe")
        
        if error_tests > 0:
            status = f"{error_tests} test{'s' if error_tests != 1 else ''} encountered errors"
        elif vulnerable_tests > 0:
            status = f"{vulnerable_tests} vulnerability{'ies' if vulnerable_tests != 1 else ''} found"
        else:
            status = "All tests completed"
        
        md.append(f"Status: {status}")
        md.append("")
        md.append("## What was tested")
        md.append("")
        
        # Analyze test results to extract information
        test_types = {}
        for result in report.test_results:
            test_type = result.test_type
            if test_type not in test_types:
                test_types[test_type] = {
                    "count": 0,
                    "vulnerable": 0,
                    "safe": 0,
                    "error": 0,
                    "urls": set()
                }
            test_types[test_type]["count"] += 1
            test_types[test_type][result.status] = test_types[test_type].get(result.status, 0) + 1
            test_types[test_type]["urls"].add(result.target_url)
        
        # Report analysis - try to extract from test results metadata or infer
        # We'll need to pass this info, but for now infer from test results
        form_tests = [r for r in report.test_results if "form" in r.test_type.lower()]
        auth_tests = [r for r in report.test_results if any(x in r.test_type.lower() for x in ["login", "auth", "session"])]
        api_tests = [r for r in report.test_results if "api" in r.test_type.lower()]
        llm_tests = [r for r in report.test_results if "llm" in r.test_type.lower()]
        automated_tests = [r for r in report.test_results if r.test_type in ["Automated Scanning", "nuclei", "wapiti3", "nikto"]]
        
        # Count unique URLs tested
        all_urls = set(r.target_url for r in report.test_results)
        
        # Report analysis
        if self.testing_plan:
            total_pages = self.testing_plan.total_pages
            md.append(f"**Report analysis:** Analyzed {total_pages} page{'s' if total_pages != 1 else ''} from the browsing report")
        else:
            md.append("**Report analysis:** Analyzed browsing report")
        md.append("")
        
        # Extract attack surface information from testing plan if available
        form_count = 0
        auth_endpoint_count = 0
        sensitive_page_count = 0
        input_point_count = 0
        
        if self.testing_plan:
            for attack_surface in self.testing_plan.attack_surfaces:
                if attack_surface.category == "forms":
                    # Count form types
                    form_count = len(attack_surface.items) if attack_surface.items else 0
                elif attack_surface.category == "auth_endpoints":
                    auth_endpoint_count = len(attack_surface.items) if attack_surface.items else 0
                elif attack_surface.category == "sensitive_pages":
                    sensitive_page_count = len(attack_surface.items) if attack_surface.items else 0
                elif attack_surface.category == "input_points":
                    input_point_count = len(attack_surface.items) if attack_surface.items else 0
        
        # Forms
        if form_count > 0:
            md.append(f"Found {form_count} form type{'s' if form_count != 1 else ''}")
        elif form_tests:
            form_urls = set()
            for test in form_tests:
                form_urls.add(test.target_url)
            md.append(f"Found {len(form_urls)} form{'s' if len(form_urls) != 1 else ''} to test")
        else:
            md.append("No forms found")
        
        # Auth endpoints
        if auth_endpoint_count > 0:
            md.append(f"{auth_endpoint_count} auth endpoint{'s' if auth_endpoint_count != 1 else ''} identified")
        elif auth_tests:
            auth_urls = set()
            for test in auth_tests:
                auth_urls.add(test.target_url)
            md.append(f"{len(auth_urls)} auth endpoint{'s' if len(auth_urls) != 1 else ''} identified")
        else:
            md.append("No auth endpoints found")
        
        # Sensitive pages
        if sensitive_page_count > 0:
            md.append(f"{sensitive_page_count} sensitive page{'s' if sensitive_page_count != 1 else ''}")
        else:
            sensitive_tests = [r for r in report.test_results if any(x in r.target_url.lower() for x in ["admin", "account", "profile", "checkout", "payment"])]
            if sensitive_tests:
                md.append(f"{len(set(r.target_url for r in sensitive_tests))} sensitive page{'s' if len(set(r.target_url for r in sensitive_tests)) != 1 else ''}")
            else:
                md.append("No sensitive pages identified")
        
        # Input points
        if input_point_count > 0:
            md.append(f"{input_point_count} input point{'s' if input_point_count != 1 else ''}")
        else:
            # Count form fields from metadata if available
            total_input_points = 0
            for result in report.test_results:
                if "input_points" in result.metadata:
                    total_input_points += result.metadata.get("input_points", 0)
                elif "fields" in result.metadata:
                    total_input_points += len(result.metadata.get("fields", []))
            
            if total_input_points > 0:
                md.append(f"{total_input_points} input point{'s' if total_input_points != 1 else ''}")
        
        md.append("")
        
        # Automated scanning
        auto_scan_text = "**Automated scanning:** "
        if report.testing_methodology.get("automated_scanning", False):
            if automated_tests:
                auto_scan_text += "Completed"
            else:
                auto_scan_text += "Completed (no external tools like nuclei/wapiti3 available)"
        else:
            auto_scan_text += "Disabled"
        md.append(auto_scan_text)
        md.append("")
        
        # Form testing
        form_test_text = "**Form testing:** "
        if form_tests:
            vulnerable_forms = sum(1 for t in form_tests if t.status == "vulnerable")
            if vulnerable_forms > 0:
                form_test_text += f"Completed ({vulnerable_forms} vulnerability{'ies' if vulnerable_forms != 1 else ''} found)"
            else:
                form_test_text += "Completed (no vulnerabilities found)"
        else:
            form_test_text += "Completed (no forms found)"
        md.append(form_test_text)
        md.append("")
        
        # Authentication testing
        md.append("**Authentication testing:** Completed")
        if auth_tests:
            for test in auth_tests:
                test_name = test.test_type
                url_display = test.target_url.replace(report.base_url, "").strip("/") or "homepage"
                status_text = "Vulnerable" if test.status == "vulnerable" else "Safe"
                md.append(f"- {test_name} on {url_display}: {status_text}")
        md.append("")
        
        # API testing
        api_test_text = "**API testing:** "
        if api_tests:
            vulnerable_apis = sum(1 for t in api_tests if t.status == "vulnerable")
            if vulnerable_apis > 0:
                api_test_text += f"Completed ({vulnerable_apis} vulnerability{'ies' if vulnerable_apis != 1 else ''} found)"
            else:
                api_test_text += "Completed (no vulnerabilities found)"
        else:
            api_test_text += "Completed (no API endpoints found)"
        md.append(api_test_text)
        md.append("")
        
        # LLM-guided testing
        llm_test_text = "**LLM-guided testing:** "
        if report.testing_methodology.get("llm_testing", False):
            if llm_tests:
                # Check if fallback was used
                used_fallback = any("fallback" in str(r.metadata.get("agent_output", "")).lower() for r in llm_tests)
                if used_fallback:
                    llm_test_text += "Completed (LLM agent used fallback executor)"
                else:
                    llm_test_text += "Completed"
            else:
                llm_test_text += "Completed (no pages to test)"
        else:
            llm_test_text += "Disabled"
        md.append(llm_test_text)
        md.append("")
        
        md.append("## Findings")
        md.append("")
        if report.total_findings == 0:
            md.append("No vulnerabilities detected in the automated tests. The site appears secure for the tested areas.")
        else:
            md.append(f"{report.total_findings} vulnerability{'ies' if report.total_findings != 1 else ''} detected:")
            md.append("")
            for severity in ["Critical", "High", "Medium", "Low"]:
                count = report.findings_by_severity.get(severity, 0)
                if count > 0:
                    md.append(f"- {severity}: {count}")
            md.append("")
            md.append("See the full report for detailed information about each finding.")
        md.append("")
        
        return "\n".join(md)
