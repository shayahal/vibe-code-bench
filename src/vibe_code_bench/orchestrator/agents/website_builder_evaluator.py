"""
Website Builder Evaluator Node

Evaluates website builder results against ground truth (runs after all other steps).
"""

from pathlib import Path

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.logging_setup import get_logger
from vibe_code_bench.core.evaluation import WebsiteBuilderEvaluator
from vibe_code_bench.core.reporting import WebsiteBuilderReportGenerator

logger = get_logger(__name__)


def website_builder_evaluator_node(state: OrchestratorState) -> OrchestratorState:
    """
    Evaluate website builder results against ground truth.
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Updated state with website_builder_eval_results
    """
    logger.info("="*60)
    logger.info("STEP 5: Evaluating Website Builder")
    logger.info("="*60)
    
    website_dir = state.get("website_dir")
    build_result = state.get("build_result")
    run_id = state.get("run_id")
    
    if not website_dir or not build_result:
        logger.warning("Cannot evaluate website builder - missing website_dir or build_result")
        return {
            **state,
            'next': 'red_team_evaluator'  # Skip to next evaluation
        }
    
    ground_truth_path = state.get("website_builder_ground_truth_path")
    if not ground_truth_path:
        logger.info("No website builder ground truth provided - skipping evaluation")
        return {
            **state,
            'next': 'red_team_evaluator'  # Skip to next evaluation
        }
    
    website_builder_model = state.get("website_builder_model", "anthropic/claude-3-haiku")
    output_dir = state.get("output_dir")
    run_dir = output_dir / f"run_{run_id}"
    
    website_builder_eval_results = None
    website_builder_eval_report_json = None
    website_builder_eval_report_md = None
    
    try:
        evaluator = WebsiteBuilderEvaluator(ground_truth_path)
        website_builder_eval_results = evaluator.evaluate(
            builder_module_path="website_generator.main",
            website_dir=website_dir,
            builder_name=f"WebsiteBuilder-{website_builder_model}"
        )
        
        # Save evaluation reports to agent-specific directory
        run_dir = state.get("run_dir")
        if run_dir:
            run_dir = Path(run_dir)
            agent_dir = run_dir / "reports" / "website_builder_evaluator"
            agent_dir.mkdir(parents=True, exist_ok=True)
            
            json_path, md_path = WebsiteBuilderReportGenerator.save_report(
                eval_results=website_builder_eval_results,
                run_id=run_id,
                output_dir=agent_dir
            )
            website_builder_eval_report_json = json_path
            website_builder_eval_report_md = md_path
        else:
            # Fallback to daily directory
            from vibe_code_bench.core.paths import get_daily_reports_dir
            daily_reports_dir = get_daily_reports_dir(run_id)
            json_path, md_path = WebsiteBuilderReportGenerator.save_report(
                eval_results=website_builder_eval_results,
                run_id=run_id,
                output_dir=daily_reports_dir
            )
            website_builder_eval_report_json = json_path
            website_builder_eval_report_md = md_path
        
        logger.info("Website builder evaluation completed")
        logger.info(f"  Quality score: {website_builder_eval_results['metrics']['overall_quality_score']:.2%}")
        logger.info(f"  Criteria met: {website_builder_eval_results['criteria_summary']['met_criteria']}/{website_builder_eval_results['criteria_summary']['total_criteria']}")
    except Exception as e:
        logger.error(f"Website builder evaluation failed: {e}", exc_info=True)
        # Continue without evaluation results
    
    return {
        **state,
        'website_builder_eval_results': website_builder_eval_results,
        'website_builder_eval_report_json': website_builder_eval_report_json,
        'website_builder_eval_report_md': website_builder_eval_report_md,
        'next': 'red_team_evaluator'  # Next step is red team evaluation
    }

