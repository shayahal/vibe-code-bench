"""
Evaluator Node

Evaluates red team findings against ground truth.
"""

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


def evaluator_node(state: OrchestratorState, evaluator) -> OrchestratorState:
    """
    Evaluate red team findings against ground truth.
    
    Args:
        state: Current orchestrator state
        evaluator: VulnerabilityEvaluator instance
        
    Returns:
        Updated state with eval_results
    """
    logger.info("="*60)
    logger.info("STEP 5: Evaluating Findings")
    logger.info("="*60)
    
    red_team_result = state.get("red_team_result")
    if not red_team_result:
        logger.error("red_team_result not set in state - cannot evaluate")
        raise ValueError("red_team_result not set in state - cannot evaluate")
    
    url = state.get("url")
    if not url:
        logger.error("url not set in state")
        raise ValueError("url not set in state")
    
    run_id = state.get("run_id")
    if not run_id:
        logger.error("run_id not set in state")
        raise ValueError("run_id not set in state")
    
    output_dir = state.get("output_dir")
    red_team_model = state.get("red_team_model", "anthropic/claude-3-haiku")
    
    report_content = red_team_result.get("report", "")
    logger.debug(f"Evaluating report content ({len(report_content)} characters)")
    
    # Evaluate findings
    results = evaluator.evaluate(
        report_content=report_content,
        url=url,
        model_name=red_team_model
    )
    
    # Save evaluation results
    from vibe_code_bench.core.paths import get_reports_dir
    eval_file = get_reports_dir() / f"evaluation_results_{run_id}.json"
    evaluator.save_evaluation_results(results, str(eval_file))
    
    logger.info("Evaluation completed")
    logger.info(f"Overall detection rate: {results['metrics']['overall_detection_rate']:.2%}")
    logger.info(f"Found: {results['metrics']['found']}/{results['metrics']['total_vulnerabilities']}")
    logger.info(f"Results saved: {eval_file}")
    
    return {
        **state,
        'eval_results': results,
        'next': '__end__'  # Workflow complete
    }

