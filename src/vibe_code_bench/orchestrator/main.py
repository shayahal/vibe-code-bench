#!/usr/bin/env python3
"""
Orchestrator for Website Builder and Red Team Agent Evaluation

Coordinates the complete evaluation workflow:
1. Website builder builds a website and evaluates it
2. Server manager starts the website server
3. Red team agent tests the website and evaluates findings
4. Server manager stops the website server
5. Evaluator generates final comprehensive report

Uses LangGraph's hierarchical agent teams framework for coordination.
"""

import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Any
from dotenv import load_dotenv

from vibe_code_bench.core.paths import get_repo_root, get_absolute_path
project_root = get_repo_root()

load_dotenv()


class Orchestrator:
    """Orchestrates website building, serving, and red team evaluation."""
    
    def __init__(
        self,
        website_builder_ground_truth_path: Optional[str] = None,
        red_team_ground_truth_path: Optional[str] = None,
        output_dir: Optional[Path] = None,
        website_builder_model: str = "anthropic/claude-3-haiku",
        red_team_model: str = "anthropic/claude-3-haiku"
    ):
        """
        Initialize orchestrator.
        
        Args:
            website_builder_ground_truth_path: Path to ground truth for website builder evaluation
            red_team_ground_truth_path: Path to ground truth for red team evaluation
            output_dir: Directory for output files (default: runs/orchestrator/)
            website_builder_model: Model to use for website builder
            red_team_model: Model to use for red team agent
        """
        self.website_builder_ground_truth_path = website_builder_ground_truth_path
        self.red_team_ground_truth_path = red_team_ground_truth_path
        self.output_dir = output_dir or (project_root / "runs" / "orchestrator")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.website_builder_model = website_builder_model
        self.red_team_model = red_team_model
        
        # Build LangGraph workflow
        self.graph = self._build_graph()
    
    def _build_graph(self):
        """
        Build the LangGraph workflow.
        
        Returns:
            Compiled StateGraph
        """
        # Import LangGraph components
        from langgraph.graph import StateGraph, END
        
        # Import orchestrator components
        from vibe_code_bench.orchestrator.state import OrchestratorState
        from vibe_code_bench.orchestrator.supervisor import supervisor_node
        from vibe_code_bench.orchestrator.agents.website_builder import website_builder_node
        from vibe_code_bench.orchestrator.agents.red_team import red_team_node
        from vibe_code_bench.orchestrator.agents.server_manager import server_manager_node
        from vibe_code_bench.orchestrator.agents.website_builder_evaluator import website_builder_evaluator_node
        from vibe_code_bench.orchestrator.agents.red_team_evaluator import red_team_evaluator_node
        from vibe_code_bench.orchestrator.agents.evaluator import evaluator_node
        
        # Create state graph
        workflow = StateGraph(OrchestratorState)
        
        # Add nodes
        workflow.add_node("supervisor", supervisor_node)
        workflow.add_node("website_builder", website_builder_node)
        workflow.add_node("server_manager", server_manager_node)
        workflow.add_node("red_team_agent", red_team_node)
        workflow.add_node("website_builder_evaluator", website_builder_evaluator_node)
        workflow.add_node("red_team_evaluator", red_team_evaluator_node)
        workflow.add_node("evaluator", evaluator_node)
        
        # Set entry point
        workflow.set_entry_point("supervisor")
        
        # Add supervisor routing
        workflow.add_conditional_edges(
            "supervisor",
            lambda state: state.get("next", "website_builder"),
            {
                "website_builder": "website_builder",
                "server_manager": "server_manager",
                "red_team_agent": "red_team_agent",
                "website_builder_evaluator": "website_builder_evaluator",
                "red_team_evaluator": "red_team_evaluator",
                "evaluator": "evaluator",
                "__end__": END
            }
        )
        
        # Add edges from nodes back to supervisor
        workflow.add_edge("website_builder", "supervisor")
        workflow.add_edge("server_manager", "supervisor")
        workflow.add_edge("red_team_agent", "supervisor")
        workflow.add_edge("website_builder_evaluator", "supervisor")
        workflow.add_edge("red_team_evaluator", "supervisor")
        workflow.add_edge("evaluator", "supervisor")
        
        # Compile graph
        return workflow.compile()
    
    def run_full_evaluation(self, prompt: str = None, port: int = 5000) -> Dict[str, Any]:
        """
        Run complete evaluation pipeline using LangGraph.
        
        Args:
            prompt: Website prompt (default: pizzeria)
            port: Port for website server
            
        Returns:
            Complete evaluation results
        """
        print("\n" + "="*70)
        print("ORCHESTRATOR: Full Evaluation Pipeline (LangGraph)")
        print("="*70)
        
        # Initialize state
        from vibe_code_bench.website_generator.prompts import USER_PROMPT
        from langchain_core.messages import HumanMessage
        
        initial_state = {
            "messages": [HumanMessage(content="Start evaluation workflow")],
            "run_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "prompt": prompt or USER_PROMPT,
            "port": port,
            "website_dir": None,
            "build_result": None,
            "url": None,
            "server": None,
            "red_team_result": None,
            "website_builder_eval_results": None,
            "red_team_eval_results": None,
            "final_eval_results": None,
            "website_builder_eval_report_json": None,
            "website_builder_eval_report_md": None,
            "red_team_eval_report_json": None,
            "red_team_eval_report_md": None,
            "final_report": None,
            "final_report_json": None,
            "final_report_md": None,
            "eval_results": None,  # Legacy field
            "next": "website_builder",
            "output_dir": self.output_dir,
            "website_builder_model": self.website_builder_model,
            "red_team_model": self.red_team_model,
            "website_builder_ground_truth_path": self.website_builder_ground_truth_path,
            "red_team_ground_truth_path": self.red_team_ground_truth_path
        }
        
        server = None
        
        try:
            # Run the graph - stream returns states, not (node_name, state) tuples
            final_state = None
            for state_update in self.graph.stream(initial_state):
                # state_update is a dict with node names as keys
                if isinstance(state_update, dict):
                    # Get the last node's state
                    for node_name, node_state in state_update.items():
                        final_state = node_state
                        # Track server for cleanup
                        if isinstance(node_state, dict) and "server" in node_state:
                            server = node_state.get("server")
            
            # Extract final state
            if not final_state:
                raise Exception("Graph execution did not return final state")
            
            # Extract results from final state
            run_id = final_state.get("run_id")
            url = final_state.get("url")
            build_result = final_state.get("build_result")
            red_team_result = final_state.get("red_team_result")
            final_report = final_state.get("final_report")
            website_builder_eval = final_state.get("website_builder_eval_results")
            red_team_eval = final_state.get("red_team_eval_results")
            
            # Core results are required, but evaluations are optional
            if not all([run_id, url, build_result, red_team_result, final_report]):
                missing = []
                if not run_id: missing.append("run_id")
                if not url: missing.append("url")
                if not build_result: missing.append("build_result")
                if not red_team_result: missing.append("red_team_result")
                if not final_report: missing.append("final_report")
                raise Exception(f"Incomplete evaluation - missing required results: {', '.join(missing)}")
            
            print("\n" + "="*70)
            print("EVALUATION COMPLETE")
            print("="*70)
            print(f"Run ID: {run_id}")
            print(f"URL: {url}")
            
            if website_builder_eval:
                print(f"\nWebsite Builder Evaluation:")
                print(f"  Security Score: {website_builder_eval['metrics']['overall_security_score']:.2%}")
                print(f"  Vulnerabilities Found: {website_builder_eval['metrics']['vulnerabilities_found']}/{website_builder_eval['metrics']['vulnerabilities_total']}")
            
            if red_team_eval:
                print(f"\nRed Team Evaluation:")
                print(f"  Detection Rate: {red_team_eval['metrics']['overall_detection_rate']:.2%}")
                print(f"  Found: {red_team_eval['metrics']['found']}/{red_team_eval['metrics']['total_vulnerabilities']}")
            
            final_report_json = final_state.get("final_report_json")
            final_report_md = final_state.get("final_report_md")
            print(f"\nFinal Reports:")
            if final_report_json:
                print(f"  JSON: {final_report_json}")
            if final_report_md:
                print(f"  Markdown: {final_report_md}")
            
            return final_report
            
        except Exception as e:
            print(f"\n❌ Error during evaluation: {e}")
            import traceback
            traceback.print_exc()
            raise
            
        finally:
            # Always stop server if it's still running
            if server and hasattr(server, 'is_running') and server.is_running():
                print("\nShutting down website server...")
                server.stop()


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Orchestrate website building and red team evaluation"
    )
    parser.add_argument(
        "--website-builder-ground-truth",
        type=str,
        default=None,
        help="Path to ground truth vulnerabilities JSON for website builder evaluation"
    )
    parser.add_argument(
        "--red-team-ground-truth",
        type=str,
        default=None,
        help="Path to ground truth vulnerabilities JSON for red team evaluation"
    )
    parser.add_argument(
        "--ground-truth",
        type=str,
        default=None,
        help="Path to ground truth vulnerabilities JSON (used for both if separate paths not provided)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Output directory for runs"
    )
    parser.add_argument(
        "--website-model",
        type=str,
        default="anthropic/claude-3-haiku",
        help="Model for website builder"
    )
    parser.add_argument(
        "--red-team-model",
        type=str,
        default="anthropic/claude-3-haiku",
        help="Model for red team agent"
    )
    parser.add_argument(
        "--prompt",
        type=str,
        help="Custom website prompt (default: pizzeria)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port for website server"
    )
    
    args = parser.parse_args()
    
    # Determine ground truth paths
    website_builder_ground_truth = args.website_builder_ground_truth or args.ground_truth
    red_team_ground_truth = args.red_team_ground_truth or args.ground_truth
    
    # Validate ground truth paths if provided
    if website_builder_ground_truth:
        website_builder_ground_truth = get_absolute_path(website_builder_ground_truth)
        if not website_builder_ground_truth.exists():
            print(f"Error: Website builder ground truth file not found: {website_builder_ground_truth}")
            sys.exit(1)
        website_builder_ground_truth = str(website_builder_ground_truth)
    
    if red_team_ground_truth:
        red_team_ground_truth = get_absolute_path(red_team_ground_truth)
        if not red_team_ground_truth.exists():
            print(f"Error: Red team ground truth file not found: {red_team_ground_truth}")
            sys.exit(1)
        red_team_ground_truth = str(red_team_ground_truth)
    
    # Run orchestrator
    orchestrator = Orchestrator(
        website_builder_ground_truth_path=website_builder_ground_truth,
        red_team_ground_truth_path=red_team_ground_truth,
        output_dir=args.output_dir,
        website_builder_model=args.website_model,
        red_team_model=args.red_team_model
    )
    
    try:
        results = orchestrator.run_full_evaluation(
            prompt=args.prompt,
            port=args.port
        )
        
        print("\n✓ Orchestration completed successfully!")
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Orchestration failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

