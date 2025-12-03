#!/usr/bin/env python3
"""
Orchestrator for Website Builder and Red Team Agent Evaluation

For each run:
1. Runs website builder to create a webpage
2. Starts a local server to serve the website
3. Runs red team agent on the website
4. Evaluates red team agent findings against ground truth
5. Outputs JSON report with all 20 vulnerabilities and found status
"""

import os
import sys
import json
import time
import subprocess
import signal
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Any
import requests
from dotenv import load_dotenv

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

load_dotenv()

# Import evaluation framework
from red_team_agent.eval.eval_framework import VulnerabilityEvaluator


class WebsiteServer:
    """Manages a Flask server for the generated website."""
    
    def __init__(self, website_dir: Path, port: int = 5000):
        """
        Initialize website server.
        
        Args:
            website_dir: Directory containing website files (including main.py)
            port: Port to run server on
        """
        self.website_dir = Path(website_dir)
        self.port = port
        self.process = None
        self.url = f"http://localhost:{port}"
    
    def start(self, timeout: int = 30) -> bool:
        """
        Start the Flask server.
        
        Args:
            timeout: Maximum time to wait for server to start
            
        Returns:
            True if server started successfully
        """
        main_py = self.website_dir / "main.py"
        if not main_py.exists():
            print(f"Error: main.py not found in {self.website_dir}")
            return False
        
        # Change to website directory and start Flask
        env = os.environ.copy()
        env['FLASK_APP'] = 'main.py'
        env['FLASK_ENV'] = 'development'
        
        try:
            self.process = subprocess.Popen(
                [sys.executable, str(main_py)],
                cwd=str(self.website_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for server to start
            for _ in range(timeout):
                try:
                    response = requests.get(self.url, timeout=1)
                    if response.status_code == 200:
                        print(f"✓ Website server started on {self.url}")
                        return True
                except requests.exceptions.RequestException:
                    pass
                time.sleep(1)
            
            print(f"⚠ Server did not start within {timeout} seconds")
            return False
            
        except Exception as e:
            print(f"Error starting server: {e}")
            return False
    
    def stop(self):
        """Stop the Flask server."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                print("✓ Website server stopped")
            except subprocess.TimeoutExpired:
                self.process.kill()
                print("✓ Website server force stopped")
            except Exception as e:
                print(f"Error stopping server: {e}")
    
    def is_running(self) -> bool:
        """Check if server is running."""
        try:
            response = requests.get(self.url, timeout=1)
            return response.status_code == 200
        except:
            return False


class Orchestrator:
    """Orchestrates website building, serving, and red team evaluation."""
    
    def __init__(
        self,
        ground_truth_path: str,
        output_dir: Path = None,
        website_builder_model: str = "anthropic/claude-3-haiku",
        red_team_model: str = "anthropic/claude-3-haiku"
    ):
        """
        Initialize orchestrator.
        
        Args:
            ground_truth_path: Path to ground truth vulnerabilities JSON
            output_dir: Directory for output files (default: orchestrator_runs/)
            website_builder_model: Model to use for website builder
            red_team_model: Model to use for red team agent
        """
        self.ground_truth_path = Path(ground_truth_path)
        self.output_dir = output_dir or (project_root / "orchestrator_runs")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.website_builder_model = website_builder_model
        self.red_team_model = red_team_model
        
        # Initialize evaluator
        self.evaluator = VulnerabilityEvaluator(str(self.ground_truth_path))
    
    def build_website(self, prompt: str = None) -> Dict[str, Any]:
        """
        Build a website using the website builder.
        
        Args:
            prompt: Custom prompt (default: pizzeria website)
            
        Returns:
            Dictionary with build results
        """
        from website_generator.agent import SimpleWebsiteCreatorAgent
        
        print("\n" + "="*60)
        print("STEP 1: Building Website")
        print("="*60)
        
        # Create run directory
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = self.output_dir / f"run_{run_id}"
        website_dir = run_dir / "website"
        
        # Initialize builder
        builder = SimpleWebsiteCreatorAgent(
            provider="openrouter",
            model_name=self.website_builder_model,
            run_dir=run_dir,
            output_dir=website_dir
        )
        
        # Build website
        website_prompt = prompt or "build a website for my pizzeria"
        result = builder.create_website(custom_prompt=website_prompt)
        
        if result['status'] == 'error':
            raise Exception(f"Website build failed: {result.get('error', 'Unknown error')}")
        
        print(f"✓ Website built successfully")
        print(f"  Output directory: {result['output_directory']}")
        print(f"  Files created: {result['total_files']}")
        
        return {
            'run_id': run_id,
            'run_dir': run_dir,
            'website_dir': website_dir,
            'result': result
        }
    
    def run_red_team_agent(self, url: str, run_id: str) -> Dict[str, Any]:
        """
        Run red team agent on the website.
        
        Args:
            url: URL to test
            run_id: Run ID for this evaluation
            
        Returns:
            Dictionary with red team results
        """
        print("\n" + "="*60)
        print("STEP 2: Running Red Team Agent")
        print("="*60)
        
        # Import red team agent components
        from red_team_agent.agent_common import (
            initialize_langfuse,
            initialize_llm,
            create_and_run_agent,
            flush_langfuse,
            save_report
        )
        from red_team_agent.tools import get_all_tools
        from red_team_agent.report_generator import generate_run_report
        from red_team_agent.red_team_prompt import RED_TEAM_AGENT_PROMPT
        
        # Initialize LangFuse
        langfuse_client, langfuse_handler = initialize_langfuse()
        
        # Initialize LLM
        llm = initialize_llm(
            model_name=self.red_team_model,
            api_key=None,
            langfuse_handler=langfuse_handler,
            title="Red Team Agent"
        )
        
        print(f"✓ Using model: {self.red_team_model}")
        
        # Get tools
        all_tools = get_all_tools()
        print(f"✓ Loaded {len(all_tools)} security testing tools")
        
        # Run agent
        red_team_run_id = f"{run_id}_redteam"
        output, execution_time, trace_id = create_and_run_agent(
            llm=llm,
            all_tools=all_tools,
            system_prompt=RED_TEAM_AGENT_PROMPT,
            url=url,
            langfuse_handler=langfuse_handler,
            langfuse_client=langfuse_client,
            model_name=self.red_team_model,
            run_id=red_team_run_id
        )
        
        # Generate report
        report = generate_run_report(
            llm=llm,
            langfuse_client=langfuse_client,
            url=url,
            output=output,
            execution_time=execution_time,
            langfuse_handler=langfuse_handler,
            run_id=red_team_run_id,
            model_name=self.red_team_model
        )
        
        # Save report
        report_dir = self.output_dir / run_id / "red_team_reports"
        report_file = save_report(report, red_team_run_id, str(report_dir))
        
        print(f"✓ Red team assessment completed")
        print(f"  Execution time: {execution_time:.2f}s")
        print(f"  Report saved: {report_file}")
        
        return {
            'output': output,
            'report': report,
            'report_file': report_file,
            'execution_time': execution_time,
            'trace_id': trace_id
        }
    
    def evaluate_findings(self, report_content: str, url: str, run_id: str) -> Dict[str, Any]:
        """
        Evaluate red team findings against ground truth.
        
        Args:
            report_content: Red team agent report content
            url: URL that was tested
            run_id: Run ID
            
        Returns:
            Evaluation results
        """
        print("\n" + "="*60)
        print("STEP 3: Evaluating Findings")
        print("="*60)
        
        results = self.evaluator.evaluate(
            report_content=report_content,
            url=url,
            model_name=self.red_team_model
        )
        
        # Save evaluation results
        eval_file = self.output_dir / run_id / "evaluation_results.json"
        self.evaluator.save_evaluation_results(results, str(eval_file))
        
        print(f"✓ Evaluation completed")
        print(f"  Overall detection rate: {results['metrics']['overall_detection_rate']:.2%}")
        print(f"  Found: {results['metrics']['found']}/{results['metrics']['total_vulnerabilities']}")
        print(f"  Results saved: {eval_file}")
        
        return results
    
    def run_full_evaluation(self, prompt: str = None, port: int = 5000) -> Dict[str, Any]:
        """
        Run complete evaluation pipeline.
        
        Args:
            prompt: Website prompt (default: pizzeria)
            port: Port for website server
            
        Returns:
            Complete evaluation results
        """
        print("\n" + "="*70)
        print("ORCHESTRATOR: Full Evaluation Pipeline")
        print("="*70)
        
        server = None
        
        try:
            # Step 1: Build website
            build_result = self.build_website(prompt)
            run_id = build_result['run_id']
            website_dir = build_result['website_dir']
            
            # Step 2: Start server
            print("\n" + "="*60)
            print("STEP 2: Starting Website Server")
            print("="*60)
            
            server = WebsiteServer(website_dir, port=port)
            if not server.start():
                raise Exception("Failed to start website server")
            
            url = server.url
            
            # Step 3: Run red team agent
            red_team_result = self.run_red_team_agent(url, run_id)
            
            # Step 4: Evaluate findings
            eval_results = self.evaluate_findings(
                report_content=red_team_result['report'],
                url=url,
                run_id=run_id
            )
            
            # Step 5: Create final report
            final_report = {
                'run_id': run_id,
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'website_builder_model': self.website_builder_model,
                'red_team_model': self.red_team_model,
                'build_result': {
                    'status': build_result['result']['status'],
                    'files_created': build_result['result']['total_files'],
                    'output_directory': str(build_result['website_dir'])
                },
                'red_team_result': {
                    'execution_time': red_team_result['execution_time'],
                    'report_file': str(red_team_result['report_file'])
                },
                'evaluation': eval_results
            }
            
            # Save final report
            final_report_file = self.output_dir / run_id / "final_report.json"
            with open(final_report_file, 'w', encoding='utf-8') as f:
                json.dump(final_report, f, indent=2, ensure_ascii=False)
            
            print("\n" + "="*70)
            print("EVALUATION COMPLETE")
            print("="*70)
            print(f"Run ID: {run_id}")
            print(f"URL: {url}")
            print(f"\nVulnerabilities Found: {eval_results['metrics']['found']}/{eval_results['metrics']['total_vulnerabilities']}")
            print(f"Detection Rate: {eval_results['metrics']['overall_detection_rate']:.2%}")
            print(f"\nFinal Report: {final_report_file}")
            
            return final_report
            
        except Exception as e:
            print(f"\n❌ Error during evaluation: {e}")
            import traceback
            traceback.print_exc()
            raise
            
        finally:
            # Always stop server
            if server:
                server.stop()


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Orchestrate website building and red team evaluation"
    )
    parser.add_argument(
        "--ground-truth",
        type=str,
        default="red_team_agent/eval/ground_truth_vulnerabilities.json",
        help="Path to ground truth vulnerabilities JSON"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="orchestrator_runs",
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
    
    # Validate ground truth path
    ground_truth_path = Path(args.ground_truth)
    if not ground_truth_path.exists():
        print(f"Error: Ground truth file not found: {ground_truth_path}")
        sys.exit(1)
    
    # Run orchestrator
    orchestrator = Orchestrator(
        ground_truth_path=str(ground_truth_path),
        output_dir=Path(args.output_dir),
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

