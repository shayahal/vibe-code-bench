"""
Evaluator Node

Generates final comprehensive report combining all evaluation results.
"""

from pathlib import Path

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.logging_setup import get_logger
from vibe_code_bench.core.reporting import FinalReportGenerator, ConsolidatedReportGenerator
from vibe_code_bench.orchestrator.agents.vulnerability_merger_agent import (
    merge_vulnerabilities_with_agent
)

logger = get_logger(__name__)


def evaluator_node(state: OrchestratorState) -> OrchestratorState:
    """
    Generate final comprehensive report from all evaluation results.

    Args:
        state: Current orchestrator state

    Returns:
        Updated state with final_report
    """
    logger.info("="*60)
    logger.info("STEP 7: Generating Final Report")
    logger.info("="*60)

    run_id = state.get("run_id")
    if not run_id:
        logger.error("run_id not set in state")
        raise ValueError("run_id not set in state")

    run_dir = state.get("run_dir")
    url = state.get("url", "unknown")
    prompt = state.get("prompt", "")
    output_dir = state.get("output_dir")
    website_builder_model = state.get("website_builder_model", "unknown")
    red_team_model = state.get("red_team_model", "unknown")

    # Get all results
    build_result = state.get("build_result")
    static_analysis_result = state.get("static_analysis_result")
    red_team_result = state.get("red_team_result")
    website_builder_eval = state.get("website_builder_eval_results")
    red_team_eval = state.get("red_team_eval_results")
    
    # Merge vulnerabilities from static analysis and red team using agent-based deduplication
    merged_vulnerabilities = merge_vulnerabilities_with_agent(
        static_analysis_result=static_analysis_result,
        red_team_result=red_team_result,
        model_name=red_team_model
    )

    # Generate consolidated run.json data
    run_data = ConsolidatedReportGenerator.generate_run_json(
        run_id=run_id,
        prompt=prompt,
        url=url,
        website_builder_model=website_builder_model,
        red_team_model=red_team_model,
        build_result=build_result,
        static_analysis_result=static_analysis_result,
        red_team_result=red_team_result,
        website_builder_eval=website_builder_eval,
        red_team_eval=red_team_eval,
        merged_vulnerabilities=merged_vulnerabilities
    )

    # Generate consolidated markdown report
    markdown_content = ConsolidatedReportGenerator.generate_consolidated_markdown(
        run_id=run_id,
        prompt=prompt,
        url=url,
        website_builder_model=website_builder_model,
        red_team_model=red_team_model,
        build_result=build_result,
        static_analysis_result=static_analysis_result,
        red_team_result=red_team_result,
        website_builder_eval=website_builder_eval,
        red_team_eval=red_team_eval,
        merged_vulnerabilities=merged_vulnerabilities
    )

    # Save consolidated reports - main reports in root, detailed in final directory
    run_dir = Path(run_dir)
    
    # Save main consolidated reports in root for easy access
    json_path = run_dir / "run.json"
    ConsolidatedReportGenerator.save_json_report(run_data, json_path)
    
    md_path = run_dir / "report.md"
    ConsolidatedReportGenerator.save_markdown_report(markdown_content, md_path)
    
    # Also save detailed version in final agent directory
    final_dir = run_dir / "reports" / "final"
    final_dir.mkdir(parents=True, exist_ok=True)
    final_json_path = final_dir / "run.json"
    final_md_path = final_dir / "report.md"
    ConsolidatedReportGenerator.save_json_report(run_data, final_json_path)
    ConsolidatedReportGenerator.save_markdown_report(markdown_content, final_md_path)
    
    logger.info(f"Consolidated reports saved:")
    logger.info(f"  Main run.json: {json_path}")
    logger.info(f"  Main report.md: {md_path}")
    logger.info(f"  Final run.json: {final_json_path}")
    logger.info(f"  Final report.md: {final_md_path}")

    # Also generate legacy final report for backward compatibility
    final_report = FinalReportGenerator.generate_report(
        run_id=run_id,
        url=url,
        website_builder_eval=website_builder_eval,
        red_team_eval=red_team_eval,
        build_result=build_result,
        red_team_result=red_team_result,
        website_builder_model=website_builder_model,
        red_team_model=red_team_model
    )

    logger.info("Consolidated reports generated")
    logger.info(f"  run.json: {json_path}")
    logger.info(f"  report.md: {md_path}")

    # Print summary
    if website_builder_eval:
        logger.info(f"\nWebsite Builder Evaluation:")
        logger.info(f"  Quality Score: {website_builder_eval['metrics']['overall_quality_score']:.2%}")
        logger.info(f"  Criteria Met: {website_builder_eval['criteria_summary']['met_criteria']}/{website_builder_eval['criteria_summary']['total_criteria']}")

    if static_analysis_result:
        logger.info(f"\nStatic Analysis:")
        summary = static_analysis_result.get("summary", {})
        logger.info(f"  Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        by_severity = summary.get("by_severity", {})
        logger.info(f"  Critical: {by_severity.get('Critical', 0)}, High: {by_severity.get('High', 0)}, Medium: {by_severity.get('Medium', 0)}, Low: {by_severity.get('Low', 0)}")
    
    if red_team_eval:
        logger.info(f"\nRed Team Evaluation:")
        logger.info(f"  Detection Rate: {red_team_eval['metrics']['overall_detection_rate']:.2%}")
        logger.info(f"  Found: {red_team_eval['metrics']['found']}/{red_team_eval['metrics']['total_vulnerabilities']}")
    
    if merged_vulnerabilities:
        logger.info(f"\nMerged Vulnerabilities:")
        summary = merged_vulnerabilities.get("summary", {})
        logger.info(f"  Total: {summary.get('total', 0)}")
        by_source = summary.get("by_source", {})
        for source, count in by_source.items():
            logger.info(f"  {source.replace('_', ' ').title()}: {count}")

    return {
        **state,
        'final_report': final_report,
        'run_json': json_path,
        'report_md': md_path,
        # Legacy paths for backward compatibility
        'final_report_json': json_path,
        'final_report_md': md_path,
        'final_eval_results': {
            'website_builder': website_builder_eval,
            'red_team': red_team_eval
        },
        # Legacy field for backward compatibility
        'eval_results': red_team_eval,
        'next': '__end__'  # Workflow complete
    }

