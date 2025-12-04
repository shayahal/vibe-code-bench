"""
Unified Reporting System

Provides standardized report generation for all components:
- Website builder evaluation reports
- Red team agent evaluation reports
- Execution summary reports
- Final comprehensive reports
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from vibe_code_bench.core.logging_setup import get_logger
from vibe_code_bench.core.paths import get_reports_dir, get_absolute_path

logger = get_logger(__name__)


class ReportGenerator:
    """Base class for report generation."""
    
    @staticmethod
    def save_json_report(report: Dict[str, Any], output_path: Path) -> Path:
        """
        Save report as JSON file.
        
        Args:
            report: Report dictionary
            output_path: Path to save JSON file
            
        Returns:
            Path to saved file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return output_path
    
    @staticmethod
    def save_markdown_report(content: str, output_path: Path) -> Path:
        """
        Save report as Markdown file.
        
        Args:
            content: Markdown content
            output_path: Path to save Markdown file
            
        Returns:
            Path to saved file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return output_path


class WebsiteBuilderReportGenerator(ReportGenerator):
    """Generates reports for website builder quality evaluations."""

    @staticmethod
    def generate_report(eval_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate structured report from evaluation results.

        Args:
            eval_results: Website builder evaluation results

        Returns:
            Structured report dictionary
        """
        metadata = eval_results.get('metadata', {})
        return {
            'metadata': {
                'report_type': metadata.get('report_type', 'website_builder_quality_evaluation'),
                'builder_name': metadata.get('builder_name', 'unknown'),
                'evaluation_date': metadata.get('evaluation_date', datetime.now().isoformat()),
                'timestamp': datetime.now().isoformat()
            },
            'quality_analysis': eval_results.get('quality_analysis', {}),
            'metrics': eval_results.get('metrics', {}),
            'criteria_summary': eval_results.get('criteria_summary', {})
        }

    @staticmethod
    def generate_markdown(eval_results: Dict[str, Any]) -> str:
        """
        Generate Markdown report from evaluation results.

        Args:
            eval_results: Website builder evaluation results

        Returns:
            Markdown formatted report
        """
        md = []

        # Header
        md.append("# Website Builder Quality Evaluation Report")
        md.append("")
        md.append("---")
        md.append("")

        # Metadata
        metadata = eval_results.get('metadata', {})
        md.append("## Metadata")
        md.append("")
        md.append(f"- **Builder Name:** {metadata.get('builder_name', 'unknown')}")
        md.append(f"- **Evaluation Date:** {metadata.get('evaluation_date', 'unknown')}")
        md.append("")

        # Metrics
        metrics = eval_results.get('metrics', {})
        criteria_summary = eval_results.get('criteria_summary', {})
        md.append("## Evaluation Metrics")
        md.append("")
        md.append(f"- **Overall Quality Score:** {metrics.get('overall_quality_score', 0):.2%}")
        md.append(f"- **Criteria Met:** {criteria_summary.get('met_criteria', 0)}/{criteria_summary.get('total_criteria', 0)}")
        md.append(f"- **Required Criteria Met:** {criteria_summary.get('required_met', 0)}/{criteria_summary.get('required_total', 0)}")
        md.append(f"- **Optional Criteria Met:** {criteria_summary.get('optional_met', 0)}/{criteria_summary.get('optional_total', 0)}")
        md.append("")

        # Category Scores
        md.append("### Quality by Category")
        md.append("")
        category_scores = metrics.get('category_scores', {})
        for category, score in category_scores.items():
            md.append(f"- **{category.replace('_', ' ').title()}:** {score:.2%}")
        md.append("")

        # Detailed Category Results
        quality_analysis = eval_results.get('quality_analysis', {})
        category_results = quality_analysis.get('category_results', {})

        for category_name, category_data in category_results.items():
            md.append(f"## {category_name.replace('_', ' ').title()}")
            md.append("")
            md.append(f"**Score:** {category_data.get('score', 0):.2%} ({category_data.get('met_criteria', 0)}/{category_data.get('total_criteria', 0)} criteria met)")
            md.append("")

            # Met criteria
            met_criteria = [c for c in category_data.get('criteria', []) if c.get('met', False)]
            if met_criteria:
                md.append("### ✓ Met:")
                md.append("")
                for criterion in met_criteria:
                    required_tag = " *(required)*" if criterion.get('required', False) else ""
                    md.append(f"- **{criterion.get('id')}:** {criterion.get('name')}{required_tag}")
                    md.append(f"  - {criterion.get('description')}")
                md.append("")

            # Unmet criteria
            unmet_criteria = [c for c in category_data.get('criteria', []) if not c.get('met', False)]
            if unmet_criteria:
                md.append("### ✗ Not Met:")
                md.append("")
                for criterion in unmet_criteria:
                    required_tag = " *(required)*" if criterion.get('required', False) else ""
                    md.append(f"- **{criterion.get('id')}:** {criterion.get('name')}{required_tag}")
                    md.append(f"  - {criterion.get('description')}")
                md.append("")

        md.append("---")
        md.append("")
        md.append(f"*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        md.append("")
        
        # Footer
        md.append("---")
        md.append("")
        md.append(f"*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\n".join(md)
    
    @staticmethod
    def save_report(
        eval_results: Dict[str, Any],
        run_id: str,
        output_dir: Optional[Path] = None
    ) -> tuple[Path, Path]:
        """
        Save both JSON and Markdown reports.
        
        Args:
            eval_results: Evaluation results
            run_id: Run identifier
            output_dir: Output directory (defaults to reports directory)
            
        Returns:
            Tuple of (json_path, markdown_path)
        """
        if output_dir is None:
            output_dir = get_reports_dir()
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate structured report
        report = WebsiteBuilderReportGenerator.generate_report(eval_results)
        
        # Save JSON
        json_path = output_dir / f"website_builder_eval_{run_id}.json"
        WebsiteBuilderReportGenerator.save_json_report(report, json_path)
        
        # Generate and save Markdown
        markdown_content = WebsiteBuilderReportGenerator.generate_markdown(eval_results)
        md_path = output_dir / f"website_builder_eval_{run_id}.md"
        WebsiteBuilderReportGenerator.save_markdown_report(markdown_content, md_path)
        
        logger.info(f"Website builder reports saved:")
        logger.info(f"  JSON: {json_path}")
        logger.info(f"  Markdown: {md_path}")
        
        return json_path, md_path


class RedTeamReportGenerator(ReportGenerator):
    """Generates reports for red team agent evaluations."""
    
    @staticmethod
    def generate_report(eval_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate structured report from evaluation results.
        
        Args:
            eval_results: Red team evaluation results
            
        Returns:
            Structured report dictionary
        """
        return {
            'metadata': {
                'report_type': 'red_team_evaluation',
                'url': eval_results.get('url', 'unknown'),
                'model': eval_results.get('model', 'unknown'),
                'evaluation_date': eval_results.get('evaluation_date', datetime.now().isoformat()),
                'timestamp': datetime.now().isoformat()
            },
            'metrics': eval_results.get('metrics', {}),
            'vulnerabilities': eval_results.get('vulnerabilities', [])
        }
    
    @staticmethod
    def generate_markdown(eval_results: Dict[str, Any]) -> str:
        """
        Generate Markdown report from evaluation results.
        
        Args:
            eval_results: Red team evaluation results
            
        Returns:
            Markdown formatted report
        """
        md = []
        
        # Header
        md.append("# Red Team Agent Evaluation Report")
        md.append("")
        md.append("---")
        md.append("")
        
        # Metadata
        md.append("## Metadata")
        md.append("")
        md.append(f"- **URL:** {eval_results.get('url', 'unknown')}")
        md.append(f"- **Model:** {eval_results.get('model', 'unknown')}")
        md.append(f"- **Evaluation Date:** {eval_results.get('evaluation_date', 'unknown')}")
        md.append("")
        
        # Metrics
        metrics = eval_results.get('metrics', {})
        md.append("## Evaluation Metrics")
        md.append("")
        md.append(f"- **Overall Detection Rate:** {metrics.get('overall_detection_rate', 0):.2%}")
        md.append(f"- **Found:** {metrics.get('found', 0)}/{metrics.get('total_vulnerabilities', 0)}")
        md.append(f"- **Not Found:** {metrics.get('not_found', 0)}")
        md.append("")
        
        # By Severity
        md.append("### Detection Rate by Severity")
        md.append("")
        by_severity = metrics.get('by_severity', {})
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in by_severity:
                sev_metrics = by_severity[severity]
                md.append(f"**{severity}:**")
                md.append(f"- Found: {sev_metrics.get('found', 0)}/{sev_metrics.get('total', 0)}")
                md.append(f"- Detection Rate: {sev_metrics.get('detection_rate', 0):.2%}")
                md.append("")
        
        # Found Vulnerabilities
        vulnerabilities = eval_results.get('vulnerabilities', [])
        found_vulns = [v for v in vulnerabilities if v.get('found', False)]
        not_found_vulns = [v for v in vulnerabilities if not v.get('found', False)]
        
        md.append("## Found Vulnerabilities")
        md.append("")
        md.append(f"**Total Found: {len(found_vulns)}**")
        md.append("")
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            severity_vulns = [v for v in found_vulns if v.get('severity') == severity]
            if severity_vulns:
                md.append(f"### {severity} Severity ({len(severity_vulns)})")
                md.append("")
                for vuln in severity_vulns[:10]:  # Limit to first 10 per severity
                    md.append(f"- **{vuln.get('id', 'Unknown')}:** {vuln.get('name', 'Unknown')}")
                    md.append(f"  - Match Confidence: {vuln.get('match_confidence', 0):.2%}")
                    if vuln.get('agent_description'):
                        md.append(f"  - Agent Finding: {vuln.get('agent_description', '')[:200]}")
                if len(severity_vulns) > 10:
                    md.append(f"\n... and {len(severity_vulns) - 10} more")
                md.append("")
        
        # Not Found Vulnerabilities
        md.append("## Not Found Vulnerabilities")
        md.append("")
        md.append(f"**Total Not Found: {len(not_found_vulns)}**")
        md.append("")
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            severity_vulns = [v for v in not_found_vulns if v.get('severity') == severity]
            if severity_vulns:
                md.append(f"### {severity} Severity ({len(severity_vulns)})")
                md.append("")
                for vuln in severity_vulns[:5]:  # Limit to first 5 per severity
                    md.append(f"- **{vuln.get('id', 'Unknown')}:** {vuln.get('name', 'Unknown')}")
                if len(severity_vulns) > 5:
                    md.append(f"\n... and {len(severity_vulns) - 5} more")
                md.append("")
        
        # Footer
        md.append("---")
        md.append("")
        md.append(f"*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\n".join(md)
    
    @staticmethod
    def save_report(
        eval_results: Dict[str, Any],
        run_id: str,
        output_dir: Optional[Path] = None
    ) -> tuple[Path, Path]:
        """
        Save both JSON and Markdown reports.
        
        Args:
            eval_results: Evaluation results
            run_id: Run identifier
            output_dir: Output directory (defaults to reports directory)
            
        Returns:
            Tuple of (json_path, markdown_path)
        """
        if output_dir is None:
            output_dir = get_reports_dir()
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate structured report
        report = RedTeamReportGenerator.generate_report(eval_results)
        
        # Save JSON
        json_path = output_dir / f"red_team_eval_{run_id}.json"
        RedTeamReportGenerator.save_json_report(report, json_path)
        
        # Generate and save Markdown
        markdown_content = RedTeamReportGenerator.generate_markdown(eval_results)
        md_path = output_dir / f"red_team_eval_{run_id}.md"
        RedTeamReportGenerator.save_markdown_report(markdown_content, md_path)
        
        logger.info(f"Red team reports saved:")
        logger.info(f"  JSON: {json_path}")
        logger.info(f"  Markdown: {md_path}")
        
        return json_path, md_path


class ConsolidatedReportGenerator(ReportGenerator):
    """Generates consolidated reports for new run structure."""

    @staticmethod
    def generate_run_json(
        run_id: str,
        prompt: str,
        url: str,
        website_builder_model: str,
        red_team_model: str,
        build_result: Optional[Dict[str, Any]],
        red_team_result: Optional[Dict[str, Any]],
        website_builder_eval: Optional[Dict[str, Any]],
        red_team_eval: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate consolidated run.json with all data.

        Args:
            run_id: Run identifier
            prompt: Website prompt used
            url: Target URL
            website_builder_model: Model used for website builder
            red_team_model: Model used for red team agent
            build_result: Website build results
            red_team_result: Red team agent results
            website_builder_eval: Website builder evaluation results
            red_team_eval: Red team evaluation results

        Returns:
            Complete run data dictionary
        """
        return {
            'metadata': {
                'run_id': run_id,
                'timestamp': datetime.now().isoformat(),
                'prompt': prompt,
                'url': url,
                'models': {
                    'website_builder': website_builder_model,
                    'red_team_agent': red_team_model
                }
            },
            'execution': {
                'website_build': {
                    'status': build_result.get('result', {}).get('status', 'unknown') if build_result else 'not_run',
                    'files_created': build_result.get('result', {}).get('total_files', 0) if build_result else 0,
                    'output_directory': str(build_result.get('website_dir', '')) if build_result else '',
                    'files': build_result.get('result', {}).get('created_files', []) if build_result else []
                } if build_result else None,
                'red_team_assessment': {
                    'execution_time_seconds': round(red_team_result.get('execution_time', 0), 2) if red_team_result else 0,
                    'report_file': str(red_team_result.get('report_file', '')) if red_team_result else '',
                    'trace_id': red_team_result.get('trace_id') if red_team_result else None
                } if red_team_result else None
            },
            'evaluation': {
                'website_builder': {
                    'metrics': website_builder_eval.get('metrics', {}) if website_builder_eval else {},
                    'vulnerabilities': website_builder_eval.get('vulnerabilities', []) if website_builder_eval else [],
                    'builder_analysis': website_builder_eval.get('builder_analysis', {}) if website_builder_eval else {},
                    'security_analysis': website_builder_eval.get('security_analysis', {}) if website_builder_eval else {}
                } if website_builder_eval else None,
                'red_team': {
                    'metrics': red_team_eval.get('metrics', {}) if red_team_eval else {},
                    'vulnerabilities': red_team_eval.get('vulnerabilities', []) if red_team_eval else []
                } if red_team_eval else None
            }
        }

    @staticmethod
    def generate_consolidated_markdown(
        run_id: str,
        prompt: str,
        url: str,
        website_builder_model: str,
        red_team_model: str,
        build_result: Optional[Dict[str, Any]],
        red_team_result: Optional[Dict[str, Any]],
        website_builder_eval: Optional[Dict[str, Any]],
        red_team_eval: Optional[Dict[str, Any]]
    ) -> str:
        """
        Generate consolidated Markdown report.

        Args:
            run_id: Run identifier
            prompt: Website prompt used
            url: Target URL
            website_builder_model: Model used for website builder
            red_team_model: Model used for red team agent
            build_result: Website build results
            red_team_result: Red team agent results
            website_builder_eval: Website builder evaluation results
            red_team_eval: Red team evaluation results

        Returns:
            Markdown formatted consolidated report
        """
        md = []

        # Header
        md.append("# Orchestrator Run Report")
        md.append("")
        md.append("---")
        md.append("")

        # Metadata
        md.append("## Run Metadata")
        md.append("")
        md.append(f"- **Run ID:** `{run_id}`")
        md.append(f"- **Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"- **Prompt:** {prompt[:100]}..." if len(prompt) > 100 else f"- **Prompt:** {prompt}")
        md.append(f"- **Target URL:** {url}")
        md.append(f"- **Website Builder Model:** {website_builder_model}")
        md.append(f"- **Red Team Model:** {red_team_model}")
        md.append("")

        # Execution Summary
        md.append("## Execution Summary")
        md.append("")

        if build_result:
            md.append("### Website Build")
            md.append(f"- **Status:** {build_result.get('result', {}).get('status', 'unknown')}")
            md.append(f"- **Files Created:** {build_result.get('result', {}).get('total_files', 0)}")
            md.append(f"- **Output Directory:** `{build_result.get('website_dir', '')}`")
            md.append("")

        if red_team_result:
            md.append("### Red Team Assessment")
            md.append(f"- **Execution Time:** {red_team_result.get('execution_time', 0):.2f} seconds")
            md.append(f"- **Report File:** `{red_team_result.get('report_file', '')}`")
            if red_team_result.get('trace_id'):
                md.append(f"- **Trace ID:** `{red_team_result.get('trace_id')}`")
            md.append("")

        # Evaluation Results
        md.append("## Evaluation Results")
        md.append("")

        if website_builder_eval:
            md.append("### Website Builder Evaluation")
            md.append("")
            metrics = website_builder_eval.get('metrics', {})
            md.append(f"- **Overall Security Score:** {metrics.get('overall_security_score', 0):.2%}")
            md.append(f"- **Vulnerabilities Found:** {metrics.get('vulnerabilities_found', 0)}/{metrics.get('vulnerabilities_total', 0)}")
            md.append("")

            # By severity
            md.append("#### By Severity")
            md.append("")
            by_severity = metrics.get('by_severity', {})
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if severity in by_severity:
                    sev = by_severity[severity]
                    md.append(f"**{severity}:** {sev.get('found', 0)}/{sev.get('total', 0)} found")
            md.append("")

            # Vulnerabilities found
            vulnerabilities = website_builder_eval.get('vulnerabilities', [])
            found_vulns = [v for v in vulnerabilities if v.get('found', False)]
            if found_vulns:
                md.append("#### Vulnerabilities Found")
                md.append("")
                for vuln in found_vulns[:10]:
                    md.append(f"- **{vuln.get('id')}:** {vuln.get('name')} ({vuln.get('severity')})")
                if len(found_vulns) > 10:
                    md.append(f"\n... and {len(found_vulns) - 10} more")
                md.append("")

        if red_team_eval:
            md.append("### Red Team Agent Evaluation")
            md.append("")
            metrics = red_team_eval.get('metrics', {})
            md.append(f"- **Overall Detection Rate:** {metrics.get('overall_detection_rate', 0):.2%}")
            md.append(f"- **Found:** {metrics.get('found', 0)}/{metrics.get('total_vulnerabilities', 0)}")
            md.append(f"- **Not Found:** {metrics.get('not_found', 0)}")
            md.append("")

            # By severity
            md.append("#### Detection by Severity")
            md.append("")
            by_severity = metrics.get('by_severity', {})
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if severity in by_severity:
                    sev = by_severity[severity]
                    md.append(f"**{severity}:** {sev.get('found', 0)}/{sev.get('total', 0)} detected ({sev.get('detection_rate', 0):.2%})")
            md.append("")

            # Found vulnerabilities
            vulnerabilities = red_team_eval.get('vulnerabilities', [])
            found_vulns = [v for v in vulnerabilities if v.get('found', False)]
            if found_vulns:
                md.append("#### Vulnerabilities Detected")
                md.append("")
                for vuln in found_vulns[:10]:
                    md.append(f"- **{vuln.get('id')}:** {vuln.get('name')} ({vuln.get('severity')})")
                    if vuln.get('match_confidence'):
                        md.append(f"  - Confidence: {vuln.get('match_confidence'):.2%}")
                if len(found_vulns) > 10:
                    md.append(f"\n... and {len(found_vulns) - 10} more")
                md.append("")

        # Footer
        md.append("---")
        md.append("")
        md.append(f"*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(md)

    @staticmethod
    def save_consolidated_reports(
        run_dir: Path,
        run_data: Dict[str, Any],
        markdown_content: str
    ) -> tuple[Path, Path]:
        """
        Save consolidated reports to run directory.

        Args:
            run_dir: Run directory path
            run_data: Complete run data dictionary
            markdown_content: Consolidated markdown content

        Returns:
            Tuple of (run_json_path, report_md_path)
        """
        run_dir = Path(run_dir)

        # Save run.json
        json_path = run_dir / "run.json"
        ConsolidatedReportGenerator.save_json_report(run_data, json_path)

        # Save report.md
        md_path = run_dir / "report.md"
        ConsolidatedReportGenerator.save_markdown_report(markdown_content, md_path)

        logger.info(f"Consolidated reports saved:")
        logger.info(f"  run.json: {json_path}")
        logger.info(f"  report.md: {md_path}")

        return json_path, md_path


class FinalReportGenerator(ReportGenerator):
    """Generates final comprehensive reports combining all results."""

    @staticmethod
    def generate_report(
        run_id: str,
        url: str,
        website_builder_eval: Optional[Dict[str, Any]],
        red_team_eval: Optional[Dict[str, Any]],
        build_result: Optional[Dict[str, Any]],
        red_team_result: Optional[Dict[str, Any]],
        website_builder_model: str = "unknown",
        red_team_model: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Generate final comprehensive report.
        
        Args:
            run_id: Run identifier
            url: Target URL
            website_builder_eval: Website builder evaluation results
            red_team_eval: Red team evaluation results
            build_result: Website build results
            red_team_result: Red team agent results
            website_builder_model: Model used for website builder
            red_team_model: Model used for red team agent
            
        Returns:
            Structured final report dictionary
        """
        report = {
            'metadata': {
                'run_id': run_id,
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'models': {
                    'website_builder': website_builder_model,
                    'red_team_agent': red_team_model
                }
            },
            'execution': {},
            'evaluation': {}
        }
        
        # Execution details
        if build_result:
            report['execution']['website_build'] = {
                'status': build_result.get('result', {}).get('status', 'unknown'),
                'files_created': build_result.get('result', {}).get('total_files', 0),
                'output_directory': str(build_result.get('website_dir', '')),
                'files': build_result.get('result', {}).get('created_files', [])
            }
        
        if red_team_result:
            report['execution']['red_team_assessment'] = {
                'execution_time_seconds': round(red_team_result.get('execution_time', 0), 2),
                'report_file': str(red_team_result.get('report_file', '')),
                'trace_id': red_team_result.get('trace_id')
            }
        
        # Evaluation results
        if website_builder_eval:
            report['evaluation']['website_builder'] = {
                'metrics': website_builder_eval.get('metrics', {}),
                'vulnerabilities_found': website_builder_eval.get('metrics', {}).get('vulnerabilities_found', 0),
                'vulnerabilities_total': website_builder_eval.get('metrics', {}).get('vulnerabilities_total', 0),
                'security_score': website_builder_eval.get('metrics', {}).get('overall_security_score', 0)
            }
        
        if red_team_eval:
            report['evaluation']['red_team'] = {
                'metrics': red_team_eval.get('metrics', {}),
                'detection_rate': red_team_eval.get('metrics', {}).get('overall_detection_rate', 0),
                'found': red_team_eval.get('metrics', {}).get('found', 0),
                'total': red_team_eval.get('metrics', {}).get('total_vulnerabilities', 0)
            }
        
        return report
    
    @staticmethod
    def generate_markdown(report: Dict[str, Any]) -> str:
        """
        Generate Markdown report from structured report.
        
        Args:
            report: Structured report dictionary
            
        Returns:
            Markdown formatted report
        """
        md = []
        
        # Header
        md.append("# Final Evaluation Report")
        md.append("")
        md.append("---")
        md.append("")
        
        # Metadata
        metadata = report.get('metadata', {})
        md.append("## Metadata")
        md.append("")
        md.append(f"- **Run ID:** `{metadata.get('run_id', 'unknown')}`")
        md.append(f"- **Timestamp:** {metadata.get('timestamp', 'unknown')}")
        md.append(f"- **Target URL:** {metadata.get('url', 'unknown')}")
        md.append(f"- **Website Builder Model:** {metadata.get('models', {}).get('website_builder', 'unknown')}")
        md.append(f"- **Red Team Model:** {metadata.get('models', {}).get('red_team_agent', 'unknown')}")
        md.append("")
        
        # Execution Summary
        execution = report.get('execution', {})
        if execution:
            md.append("## Execution Summary")
            md.append("")
            
            if 'website_build' in execution:
                build = execution['website_build']
                md.append("### Website Build")
                md.append(f"- **Status:** {build.get('status', 'unknown')}")
                md.append(f"- **Files Created:** {build.get('files_created', 0)}")
                md.append(f"- **Output Directory:** `{build.get('output_directory', '')}`")
                md.append("")
            
            if 'red_team_assessment' in execution:
                assessment = execution['red_team_assessment']
                md.append("### Red Team Assessment")
                md.append(f"- **Execution Time:** {assessment.get('execution_time_seconds', 0)} seconds")
                md.append(f"- **Report File:** `{assessment.get('report_file', '')}`")
                if assessment.get('trace_id'):
                    md.append(f"- **Trace ID:** `{assessment.get('trace_id')}`")
                md.append("")
        
        # Evaluation Summary
        evaluation = report.get('evaluation', {})
        if evaluation:
            md.append("## Evaluation Summary")
            md.append("")
            
            if 'website_builder' in evaluation:
                wb_eval = evaluation['website_builder']
                md.append("### Website Builder Evaluation")
                md.append(f"- **Security Score:** {wb_eval.get('security_score', 0):.2%}")
                md.append(f"- **Vulnerabilities Found:** {wb_eval.get('vulnerabilities_found', 0)}/{wb_eval.get('vulnerabilities_total', 0)}")
                md.append("")
            
            if 'red_team' in evaluation:
                rt_eval = evaluation['red_team']
                md.append("### Red Team Evaluation")
                md.append(f"- **Detection Rate:** {rt_eval.get('detection_rate', 0):.2%}")
                md.append(f"- **Found:** {rt_eval.get('found', 0)}/{rt_eval.get('total', 0)}")
                md.append("")
        
        # Footer
        md.append("---")
        md.append("")
        md.append(f"*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\n".join(md)
    
    @staticmethod
    def save_report(
        report: Dict[str, Any],
        run_id: str,
        output_dir: Optional[Path] = None
    ) -> tuple[Path, Path]:
        """
        Save both JSON and Markdown reports.
        
        Args:
            report: Structured report dictionary
            run_id: Run identifier
            output_dir: Output directory (defaults to reports directory)
            
        Returns:
            Tuple of (json_path, markdown_path)
        """
        if output_dir is None:
            output_dir = get_reports_dir()
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save JSON
        json_path = output_dir / f"final_report_{run_id}.json"
        FinalReportGenerator.save_json_report(report, json_path)
        
        # Generate and save Markdown
        markdown_content = FinalReportGenerator.generate_markdown(report)
        md_path = output_dir / f"final_report_{run_id}.md"
        FinalReportGenerator.save_markdown_report(markdown_content, md_path)
        
        logger.info(f"Final reports saved:")
        logger.info(f"  JSON: {json_path}")
        logger.info(f"  Markdown: {md_path}")
        
        return json_path, md_path

