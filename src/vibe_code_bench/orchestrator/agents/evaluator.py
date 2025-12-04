"""
Evaluator Node

Evaluates red team findings against ground truth.
"""

from vibe_code_bench.orchestrator.state import OrchestratorState


def evaluator_node(state: OrchestratorState, evaluator) -> OrchestratorState:
    """
    Evaluate red team findings against ground truth.
    
    Args:
        state: Current orchestrator state
        evaluator: VulnerabilityEvaluator instance
        
    Returns:
        Updated state with eval_results
    """
    print("\n" + "="*60)
    print("STEP 5: Evaluating Findings")
    print("="*60)
    
    red_team_result = state.get("red_team_result")
    if not red_team_result:
        raise ValueError("red_team_result not set in state - cannot evaluate")
    
    url = state.get("url")
    if not url:
        raise ValueError("url not set in state")
    
    run_id = state.get("run_id")
    if not run_id:
        raise ValueError("run_id not set in state")
    
    output_dir = state.get("output_dir")
    red_team_model = state.get("red_team_model", "anthropic/claude-3-haiku")
    
    report_content = red_team_result.get("report", "")
    
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
    
    print(f"✓ Evaluation completed")
    print(f"  Overall detection rate: {results['metrics']['overall_detection_rate']:.2%}")
    print(f"  Found: {results['metrics']['found']}/{results['metrics']['total_vulnerabilities']}")
    print(f"  Results saved: {eval_file}")
    
    return {
        **state,
        'eval_results': results,
        'next': '__end__'  # Workflow complete
    }

