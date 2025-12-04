"""
Red Team Evaluator Node

Evaluates red team agent findings against ground truth (runs after all other steps).
"""

from pathlib import Path

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.logging_setup import get_logger
from vibe_code_bench.core.evaluation import RedTeamEvaluator
from vibe_code_bench.core.reporting import RedTeamReportGenerator

logger = get_logger(__name__)


def red_team_evaluator_node(state: OrchestratorState) -> OrchestratorState:
    """
    Evaluate red team agent findings against ground truth.
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Updated state with red_team_eval_results
    """
    logger.info("="*60)
    logger.info("STEP 6: Evaluating Red Team Agent Findings")
    logger.info("="*60)
    
    red_team_result = state.get("red_team_result")
    url = state.get("url")
    run_id = state.get("run_id")
    
    if not red_team_result or not url:
        logger.warning("Cannot evaluate red team - missing red_team_result or url")
        return {
            **state,
            'next': 'evaluator'  # Skip to final report
        }
    
    ground_truth_path = state.get("red_team_ground_truth_path")
    if not ground_truth_path:
        logger.info("No red team ground truth provided - skipping evaluation")
        return {
            **state,
            'next': 'evaluator'  # Skip to final report
        }
    
    red_team_model = state.get("red_team_model", "anthropic/claude-3-haiku")
    output_dir = state.get("output_dir")
    run_dir = output_dir / f"run_{run_id}"
    
    report = red_team_result.get('report', '')
    
    red_team_eval_results = None
    red_team_eval_report_json = None
    red_team_eval_report_md = None
    
    try:
        evaluator = RedTeamEvaluator(ground_truth_path)
        red_team_eval_results = evaluator.evaluate(
            report_content=report,
            url=url,
            model_name=red_team_model
        )
        
        # Save evaluation reports to daily directory
        from vibe_code_bench.core.paths import get_daily_reports_dir
        daily_reports_dir = get_daily_reports_dir(run_id)
        json_path, md_path = RedTeamReportGenerator.save_report(
            eval_results=red_team_eval_results,
            run_id=run_id,
            output_dir=daily_reports_dir
        )
        red_team_eval_report_json = json_path
        red_team_eval_report_md = md_path
        
        logger.info("Red team evaluation completed")
        logger.info(f"  Detection rate: {red_team_eval_results['metrics']['overall_detection_rate']:.2%}")
        logger.info(f"  Found: {red_team_eval_results['metrics']['found']}/{red_team_eval_results['metrics']['total_vulnerabilities']}")
    except Exception as e:
        logger.error(f"Red team evaluation failed: {e}", exc_info=True)
        # Continue without evaluation results
    
    return {
        **state,
        'red_team_eval_results': red_team_eval_results,
        'red_team_eval_report_json': red_team_eval_report_json,
        'red_team_eval_report_md': red_team_eval_report_md,
        'next': 'evaluator'  # Next step is final report
    }

