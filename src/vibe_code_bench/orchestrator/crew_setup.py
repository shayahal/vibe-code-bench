"""
CrewAI Crew Setup

Creates and configures the CrewAI crew for orchestrator workflow.
"""

from typing import Optional, Dict, Any

from vibe_code_bench.orchestrator.crew_context import OrchestratorContext
from vibe_code_bench.orchestrator.crew_agents import (
    create_website_builder_agent,
    create_static_analysis_agent,
    create_red_team_agent,
    create_website_builder_evaluator_agent,
    create_red_team_evaluator_agent,
    create_final_report_agent
)
from vibe_code_bench.orchestrator.crew_tasks import get_all_tasks
from vibe_code_bench.orchestrator.crew_tools import get_red_team_tools, get_tool_summary
from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


class CustomTaskExecutor:
    """
    Custom task executor that runs our node functions directly.
    
    This allows us to use CrewAI for orchestration while executing
    our existing node functions for the actual work.
    """
    
    def __init__(self, context: OrchestratorContext):
        self.context = context
    
    def execute_website_builder(self) -> str:
        """Execute website building."""
        from vibe_code_bench.orchestrator.agents.website_builder import website_builder_node
        
        state = self.context.to_dict()
        updated_state = website_builder_node(state)
        self.context.build_result = updated_state.get('build_result')
        self.context.website_dir = updated_state.get('website_dir')
        return f"Website built. Files: {self.context.build_result.get('result', {}).get('total_files', 0) if self.context.build_result else 0}"
    
    def execute_static_analysis(self) -> str:
        """Execute static analysis."""
        from vibe_code_bench.orchestrator.agents.static_analysis import static_analysis_node
        
        state = self.context.to_dict()
        updated_state = static_analysis_node(state)
        self.context.static_analysis_result = updated_state.get('static_analysis_result')
        summary = self.context.static_analysis_result.get('summary', {}) if self.context.static_analysis_result else {}
        return f"Static analysis completed. Found {summary.get('total_vulnerabilities', 0)} vulnerabilities."
    
    def execute_server_start(self) -> str:
        """Execute server start."""
        from vibe_code_bench.orchestrator.agents.server_manager import server_manager_node
        
        state = self.context.to_dict()
        state['url'] = None
        state['red_team_result'] = None
        updated_state = server_manager_node(state)
        self.context.url = updated_state.get('url')
        self.context.server = updated_state.get('server')
        return f"Server started at {self.context.url}"
    
    def execute_red_team(self) -> str:
        """Execute red team testing."""
        from vibe_code_bench.orchestrator.agents.red_team import red_team_node
        
        state = self.context.to_dict()
        updated_state = red_team_node(state)
        self.context.red_team_result = updated_state.get('red_team_result')
        self.context.red_team_report_file = updated_state.get('red_team_report_file')
        exec_time = self.context.red_team_result.get('execution_time', 0) if self.context.red_team_result else 0
        return f"Red team assessment completed in {exec_time:.2f}s"
    
    def execute_server_stop(self) -> str:
        """Execute server stop."""
        from vibe_code_bench.orchestrator.agents.server_manager import server_manager_node
        
        state = self.context.to_dict()
        if not state.get('red_team_result'):
            raise ValueError("Cannot stop server - red team testing not completed")
        updated_state = server_manager_node(state)
        self.context.server = updated_state.get('server')
        return "Server stopped successfully"
    
    def execute_website_builder_eval(self) -> str:
        """Execute website builder evaluation."""
        from vibe_code_bench.orchestrator.agents.website_builder_evaluator import website_builder_evaluator_node
        
        state = self.context.to_dict()
        updated_state = website_builder_evaluator_node(state)
        self.context.website_builder_eval_results = updated_state.get('website_builder_eval_results')
        if self.context.website_builder_eval_results:
            score = self.context.website_builder_eval_results.get('metrics', {}).get('overall_quality_score', 0)
            return f"Website builder evaluation completed. Quality score: {score:.2%}"
        return "Website builder evaluation skipped"
    
    def execute_red_team_eval(self) -> str:
        """Execute red team evaluation."""
        from vibe_code_bench.orchestrator.agents.red_team_evaluator import red_team_evaluator_node
        
        state = self.context.to_dict()
        updated_state = red_team_evaluator_node(state)
        self.context.red_team_eval_results = updated_state.get('red_team_eval_results')
        if self.context.red_team_eval_results:
            rate = self.context.red_team_eval_results.get('metrics', {}).get('overall_detection_rate', 0)
            found = self.context.red_team_eval_results.get('metrics', {}).get('found', 0)
            total = self.context.red_team_eval_results.get('metrics', {}).get('total_vulnerabilities', 0)
            return f"Red team evaluation completed. Detection rate: {rate:.2%} ({found}/{total})"
        return "Red team evaluation skipped"
    
    def execute_final_report(self) -> str:
        """Execute final report generation."""
        from vibe_code_bench.orchestrator.agents.evaluator import evaluator_node
        
        state = self.context.to_dict()
        updated_state = evaluator_node(state)
        self.context.final_report = updated_state.get('final_report')
        self.context.run_json = updated_state.get('run_json')
        self.context.report_md = updated_state.get('report_md')
        return f"Final report generated. Reports: {self.context.run_json}, {self.context.report_md}"


def execute_crew_workflow(context: OrchestratorContext, enable_observability: bool = True) -> Dict[str, Any]:
    """
    Execute the orchestrator workflow using CrewAI structure.
    
    This function executes tasks sequentially using our existing node functions,
    but uses CrewAI agents and structure for observability and organization.
    
    Args:
        context: Orchestrator context
        enable_observability: Enable CrewAI observability (Weave integration)
        
    Returns:
        Execution result dictionary
    """
    logger.info("Executing CrewAI workflow...")
    
    # Create executor
    executor = CustomTaskExecutor(context)
    
    # Convert model names from "anthropic/claude-3-haiku" to "claude-3-haiku-20240307"
    def normalize_model_name(model_name: str) -> str:
        """Convert model name format to Anthropic format."""
        if model_name.startswith("anthropic/"):
            model_name = model_name.replace("anthropic/", "")
        # Map common names to full Anthropic model names
        model_map = {
            "claude-3-haiku": "claude-3-haiku-20240307",
            "claude-3-sonnet": "claude-3-sonnet-20240229",
            "claude-3-opus": "claude-3-opus-20240229",
        }
        return model_map.get(model_name, model_name)
    
    # Create agents for observability (even if we execute functions directly)
    agents = {
        'website_builder': create_website_builder_agent(
            model_name=normalize_model_name(context.website_builder_model)
        ),
        'static_analysis': create_static_analysis_agent(
            model_name=normalize_model_name(context.website_builder_model)
        ),
        'red_team': create_red_team_agent(
            model_name=normalize_model_name(context.red_team_model)
        ),
        'website_builder_evaluator': create_website_builder_evaluator_agent(
            model_name=normalize_model_name(context.website_builder_model)
        ),
        'red_team_evaluator': create_red_team_evaluator_agent(
            model_name=normalize_model_name(context.red_team_model)
        ),
        'final_report': create_final_report_agent(
            model_name=normalize_model_name(context.website_builder_model)
        )
    }
    
    # Execute tasks sequentially
    results = {}
    
    # Check if we're using an external URL (skip building and server management)
    using_external_url = context.url is not None
    
    try:
        if not using_external_url:
            # Task 1: Build website
            logger.info("Task 1: Building website...")
            results['website_builder'] = executor.execute_website_builder()
            
            # Task 2: Static analysis
            logger.info("Task 2: Running static analysis...")
            results['static_analysis'] = executor.execute_static_analysis()
            
            # Task 3: Start server
            logger.info("Task 3: Starting server...")
            results['server_start'] = executor.execute_server_start()
        else:
            logger.info("Skipping website building and server management (using external URL)")
            results['website_builder'] = "Skipped - using external URL"
            # Generate empty static analysis result for external URLs
            from datetime import datetime
            context.static_analysis_result = {
                "run_id": context.run_id,
                "timestamp": datetime.now().isoformat(),
                "website_dir": None,
                "tools": [],
                "summary": {
                    "total_vulnerabilities": 0,
                    "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                    "by_tool": {}
                },
                "vulnerabilities": []
            }
            results['static_analysis'] = "Skipped - using external URL (no code to analyze)"
            results['server_start'] = "Skipped - using external URL"
        
        # Task 4: Red team testing
        logger.info("Task 4: Running red team testing...")
        results['red_team'] = executor.execute_red_team()
        
        if not using_external_url:
            # Task 5: Stop server
            logger.info("Task 5: Stopping server...")
            results['server_stop'] = executor.execute_server_stop()
        else:
            logger.info("Skipping server stop (using external URL)")
            results['server_stop'] = "Skipped - using external URL"
        
        # Task 6: Website builder evaluation (conditional)
        if context.website_builder_ground_truth_path:
            logger.info("Task 6: Evaluating website builder...")
            results['website_builder_eval'] = executor.execute_website_builder_eval()
        
        # Task 7: Red team evaluation (conditional)
        if context.red_team_ground_truth_path:
            logger.info("Task 7: Evaluating red team findings...")
            results['red_team_eval'] = executor.execute_red_team_eval()
        
        # Task 8: Final report
        logger.info("Task 8: Generating final report...")
        results['final_report'] = executor.execute_final_report()
        
        logger.info("CrewAI workflow completed successfully")
        return results
        
    except Exception as e:
        logger.error(f"Error in CrewAI workflow: {e}")
        raise


def create_crew(context: OrchestratorContext, enable_observability: bool = True):
    """
    Create a CrewAI crew wrapper that executes our workflow.
    
    This is a compatibility wrapper that allows us to use CrewAI structure
    while executing our existing node functions.
    
    Args:
        context: Orchestrator context
        enable_observability: Enable CrewAI observability (Weave integration)
        
    Returns:
        Crew wrapper object
    """
    class CrewWrapper:
        """Wrapper class that mimics CrewAI Crew interface."""
        
        def __init__(self, context, enable_observability):
            self.context = context
            self.enable_observability = enable_observability
        
        def kickoff(self):
            """Execute the workflow."""
            return execute_crew_workflow(self.context, self.enable_observability)
    
    return CrewWrapper(context, enable_observability)

