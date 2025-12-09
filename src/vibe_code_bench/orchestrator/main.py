#!/usr/bin/env python3
"""
Orchestrator for Website Builder and Red Team Agent Evaluation

Coordinates the complete evaluation workflow:
1. Website builder builds a website and evaluates it
2. Server manager starts the website server
3. Red team agent tests the website and evaluates findings
4. Server manager stops the website server
5. Evaluator generates final comprehensive report

Uses CrewAI framework for multi-agent orchestration with built-in observability.
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
        
        # CrewAI crew will be created when needed (requires context)
        self.crew = None
    
    def run_full_evaluation(self, prompt: str = None, port: int = 5000, url: Optional[str] = None) -> Dict[str, Any]:
        """
        Run complete evaluation pipeline using CrewAI.
        
        Args:
            prompt: Website prompt (default: pizzeria) - ignored if url is provided
            port: Port for website server - ignored if url is provided
            url: External URL to test (if provided, skips website building and server management)
            
        Returns:
            Complete evaluation results
        """
        print("\n" + "="*70)
        print("ORCHESTRATOR: Full Evaluation Pipeline (CrewAI)")
        print("="*70)
        
        # Initialize context
        from vibe_code_bench.website_generator.prompts import USER_PROMPT
        from vibe_code_bench.core.paths import create_run_structure
        from vibe_code_bench.orchestrator.crew_context import OrchestratorContext
        from vibe_code_bench.orchestrator.crew_setup import create_crew

        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create new run directory structure
        run_paths = create_run_structure(
            run_id=run_id,
            website_builder_model=self.website_builder_model,
            red_team_model=self.red_team_model
        )

        # Create CrewAI context
        context = OrchestratorContext(
            run_id=run_id,
            prompt=prompt or USER_PROMPT,
            port=port,
            run_dir=run_paths['run_dir'],
            website_dir=run_paths['website_dir'],
            logs_dir=run_paths['logs_dir'],
            reports_dir=run_paths.get('reports_dir'),
            agent_dirs=run_paths.get('agent_dirs'),
            run_json=run_paths['run_json'],
            report_md=run_paths['report_md'],
            red_team_report_file=run_paths['red_team_report_md'],
            output_dir=self.output_dir,
            website_builder_model=self.website_builder_model,
            red_team_model=self.red_team_model,
            website_builder_ground_truth_path=self.website_builder_ground_truth_path,
            red_team_ground_truth_path=self.red_team_ground_truth_path
        )
        
        # If external URL is provided, set it in context and skip building
        if url:
            context.url = url
            print(f"\nUsing external URL: {url}")
            print("Skipping website building and server management")
        
        server = None
        
        try:
            # Create CrewAI crew
            crew = create_crew(context, enable_observability=True)
            
            # Execute crew (this runs all tasks sequentially)
            print("\nExecuting CrewAI workflow...")
            result = crew.kickoff()
            
            # Extract results from context
            run_id = context.run_id
            url = context.url
            build_result = context.build_result
            red_team_result = context.red_team_result
            final_report = context.final_report
            website_builder_eval = context.website_builder_eval_results
            red_team_eval = context.red_team_eval_results
            server = context.server
            
            # Core results are required, but evaluations are optional
            # build_result is only required if we built a website (not using external URL)
            required_results = [run_id, url, red_team_result, final_report]
            if not url:
                required_results.append(build_result)
            
            if not all(required_results):
                missing = []
                if not run_id: missing.append("run_id")
                if not url: missing.append("url")
                if not url and not build_result: missing.append("build_result")
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
                print(f"  Quality Score: {website_builder_eval['metrics']['overall_quality_score']:.2%}")
                print(f"  Criteria Met: {website_builder_eval['criteria_summary']['met_criteria']}/{website_builder_eval['criteria_summary']['total_criteria']}")
            
            if red_team_eval:
                print(f"\nRed Team Evaluation:")
                print(f"  Detection Rate: {red_team_eval['metrics']['overall_detection_rate']:.2%}")
                print(f"  Found: {red_team_eval['metrics']['found']}/{red_team_eval['metrics']['total_vulnerabilities']}")
            
            print(f"\nFinal Reports:")
            if context.run_json:
                print(f"  JSON: {context.run_json}")
            if context.report_md:
                print(f"  Markdown: {context.report_md}")
            
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
        help="Port for website server (ignored if --url is provided)"
    )
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help="External URL to test (if provided, skips website building and server management)"
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
            port=args.port,
            url=args.url
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

