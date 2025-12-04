"""
Evaluator Node

Generates final comprehensive report combining all evaluation results.
"""

from pathlib import Path

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.logging_setup import get_logger
from vibe_code_bench.core.reporting import FinalReportGenerator

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
    
    url = state.get("url", "unknown")
    output_dir = state.get("output_dir")
    website_builder_model = state.get("website_builder_model", "unknown")
    red_team_model = state.get("red_team_model", "unknown")
    
    # Get all results
    build_result = state.get("build_result")
    red_team_result = state.get("red_team_result")
    website_builder_eval = state.get("website_builder_eval_results")
    red_team_eval = state.get("red_team_eval_results")
    
    # Generate final report
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
    
    # Save final reports to daily directory
    from vibe_code_bench.core.paths import get_daily_reports_dir
    daily_reports_dir = get_daily_reports_dir(run_id)
    json_path, md_path = FinalReportGenerator.save_report(
        report=final_report,
        run_id=run_id,
        output_dir=daily_reports_dir
    )
    
    logger.info("Final report generated")
    logger.info(f"  JSON: {json_path}")
    logger.info(f"  Markdown: {md_path}")
    
    # Print summary
    if website_builder_eval:
        logger.info(f"\nWebsite Builder Evaluation:")
        logger.info(f"  Security Score: {website_builder_eval['metrics']['overall_security_score']:.2%}")
        logger.info(f"  Vulnerabilities Found: {website_builder_eval['metrics']['vulnerabilities_found']}/{website_builder_eval['metrics']['vulnerabilities_total']}")
    
    if red_team_eval:
        logger.info(f"\nRed Team Evaluation:")
        logger.info(f"  Detection Rate: {red_team_eval['metrics']['overall_detection_rate']:.2%}")
        logger.info(f"  Found: {red_team_eval['metrics']['found']}/{red_team_eval['metrics']['total_vulnerabilities']}")
    
    return {
        **state,
        'final_report': final_report,
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

