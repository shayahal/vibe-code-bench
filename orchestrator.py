#!/usr/bin/env python3
"""
Orchestrator for Website Builder and Red Team Agent Evaluation

For each run:
1. Runs website builder to create a webpage
2. Starts a local server to serve the website
3. Runs red team agent on the website
4. Puts website to sleep (stops server)
5. Evaluates red team agent findings against ground truth
6. Outputs JSON report with all 20 vulnerabilities and found status

Uses LangGraph's hierarchical agent teams framework for coordination.
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
        from orchestrator.state import OrchestratorState
        from orchestrator.supervisor import supervisor_node
        from orchestrator.agents.website_builder import website_builder_node
        from orchestrator.agents.red_team import red_team_node
        from orchestrator.agents.server_manager import server_manager_node
        from orchestrator.agents.evaluator import evaluator_node
        
        # Create state graph
        workflow = StateGraph(OrchestratorState)
        
        # Add nodes
        workflow.add_node("supervisor", supervisor_node)
        workflow.add_node("website_builder", website_builder_node)
        workflow.add_node("server_manager", server_manager_node)
        workflow.add_node("red_team_agent", red_team_node)
        
        # Evaluator node needs access to evaluator instance
        def evaluator_wrapper(state: OrchestratorState) -> OrchestratorState:
            return evaluator_node(state, self.evaluator)
        
        workflow.add_node("evaluator", evaluator_wrapper)
        
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
                "evaluator": "evaluator",
                "__end__": END
            }
        )
        
        # Add edges from nodes back to supervisor
        workflow.add_edge("website_builder", "supervisor")
        workflow.add_edge("server_manager", "supervisor")
        workflow.add_edge("red_team_agent", "supervisor")
        workflow.add_edge("evaluator", "supervisor")
        
        # Compile graph
        return workflow.compile()
    
    def build_website(self, prompt: str = None) -> Dict[str, Any]:
        """
        Build a website using main.py's approach (which works great).
        
        Args:
            prompt: Custom prompt (default: pizzeria website)
            
        Returns:
            Dictionary with build results
        """
        # Use main.py's approach instead of the agent
        from langchain_core.messages import HumanMessage, SystemMessage
        from core.llm_setup import initialize_llm
        from website_generator.prompts import SYSTEM_PROMPT, USER_PROMPT
        from website_generator.main import parse_json_response, write_files, ensure_main_py
        import time
        
        print("\n" + "="*60)
        print("STEP 1: Building Website")
        print("="*60)
        
        # Create run directory
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = self.output_dir / f"run_{run_id}"
        website_dir = run_dir / "website"
        website_dir.mkdir(parents=True, exist_ok=True)
        
        # Use main.py's approach: SYSTEM_PROMPT + USER_PROMPT
        system_prompt = SYSTEM_PROMPT
        user_prompt = prompt or USER_PROMPT
        
        # Initialize LLM (same as main.py)
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise Exception("OPENROUTER_API_KEY not found")
        
        llm, model_name = initialize_llm(
            provider="openrouter",
            model_name=self.website_builder_model,
            temperature=0.7,
            api_key=api_key
        )
        
        # Increase max_tokens for website generation (like main.py does)
        if hasattr(llm, 'max_tokens'):
            llm.max_tokens = 8000
        
        print(f"✓ Using model: {model_name}")
        
        # Invoke LLM (with LangFuse like main.py does)
        print("Generating website code...")
        start_time = time.time()
        try:
            from langfuse.langchain import CallbackHandler as LangfuseCallbackHandler
            langfuse_handler = LangfuseCallbackHandler()
            response = llm.invoke(
                [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)],
                config={"callbacks": [langfuse_handler]}
            )
        except:
            # Fallback if LangFuse not available
            response = llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
        
        # Extract content
        if hasattr(response, 'content'):
            response_text = response.content
        else:
            response_text = str(response)
        
        execution_time = time.time() - start_time
        print(f"✓ Generated {len(response_text)} characters in {execution_time:.2f}s")
        
        # Parse JSON response - extract JSON first if there's text before it
        print("Parsing JSON response...")
        # Find JSON object starting with {"files":
        json_start = response_text.find('{"files"')
        if json_start < 0:
            json_start = response_text.find('{\n"files"')
        if json_start < 0:
            json_start = response_text.find('{')
        
        if json_start >= 0:
            # Extract JSON by finding matching closing brace
            # Need to handle braces inside strings, so track string state
            in_string = False
            escape_next = False
            brace_count = 0
            json_end = json_start
            
            for i in range(json_start, len(response_text)):
                char = response_text[i]
                
                if escape_next:
                    escape_next = False
                    continue
                
                if char == '\\':
                    escape_next = True
                    continue
                
                if char == '"' and not escape_next:
                    in_string = not in_string
                    continue
                
                if not in_string:
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_end = i + 1
                            break
            
            if json_end > json_start:
                json_text = response_text[json_start:json_end]
                files = parse_json_response(json_text)
            else:
                # Fallback to main.py's function
                files = parse_json_response(response_text)
        else:
            # No JSON found, try main.py's function
            files = parse_json_response(response_text)
        print(f"✓ Parsed {len(files)} files")
        
        # Ensure main.py exists
        files = ensure_main_py(files)
        
        # Write files using main.py's function
        print("Writing files...")
        created_files = write_files(files, website_dir)
        
        print(f"✓ Website built successfully")
        print(f"  Output directory: {website_dir}")
        print(f"  Files created: {len(created_files)}")
        
        return {
            'run_id': run_id,
            'run_dir': run_dir,
            'website_dir': website_dir,
            'result': {
                'status': 'success',
                'output_directory': str(website_dir),
                'created_files': created_files,
                'total_files': len(created_files)
            }
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
    
    def _create_structured_report(
        self,
        run_id: str,
        url: str,
        build_result: Dict[str, Any],
        red_team_result: Dict[str, Any],
        eval_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a well-structured final report.
        
        Args:
            run_id: Run identifier
            url: Target URL
            build_result: Website build results
            red_team_result: Red team agent results
            eval_results: Evaluation results
            
        Returns:
            Structured report dictionary
        """
        # Organize vulnerabilities by status and severity
        vulnerabilities_found = [v for v in eval_results.get('vulnerabilities', []) if v.get('found', False)]
        vulnerabilities_not_found = [v for v in eval_results.get('vulnerabilities', []) if not v.get('found', False)]
        
        # Group found vulnerabilities by severity
        found_by_severity = {
            'Critical': [v for v in vulnerabilities_found if v.get('severity') == 'Critical'],
            'High': [v for v in vulnerabilities_found if v.get('severity') == 'High'],
            'Medium': [v for v in vulnerabilities_found if v.get('severity') == 'Medium'],
            'Low': [v for v in vulnerabilities_found if v.get('severity') == 'Low']
        }
        
        return {
            'metadata': {
                'run_id': run_id,
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'models': {
                    'website_builder': self.website_builder_model,
                    'red_team_agent': self.red_team_model
                }
            },
            'execution': {
                'website_build': {
                    'status': build_result['result']['status'],
                    'files_created': build_result['result']['total_files'],
                    'output_directory': str(build_result['website_dir']),
                    'files': build_result['result'].get('created_files', [])
                },
                'red_team_assessment': {
                    'execution_time_seconds': round(red_team_result['execution_time'], 2),
                    'report_file': str(red_team_result['report_file']),
                    'trace_id': red_team_result.get('trace_id')
                }
            },
            'evaluation': {
                'summary': {
                    'total_vulnerabilities': eval_results['metrics']['total_vulnerabilities'],
                    'found_count': eval_results['metrics']['found'],
                    'not_found_count': eval_results['metrics']['not_found'],
                    'overall_detection_rate': round(eval_results['metrics']['overall_detection_rate'], 4)
                },
                'metrics_by_severity': eval_results['metrics'].get('by_severity', {}),
                'vulnerabilities': {
                    'found': {
                        'total': len(vulnerabilities_found),
                        'by_severity': {
                            severity: {
                                'count': len(vulns),
                                'vulnerabilities': [
                                    {
                                        'id': v['id'],
                                        'name': v['name'],
                                        'type': v.get('type', 'Unknown'),
                                        'description': v.get('description', ''),
                                        'agent_description': v.get('agent_description'),
                                        'match_confidence': v.get('match_confidence', 0.0)
                                    }
                                    for v in vulns
                                ]
                            }
                            for severity, vulns in found_by_severity.items()
                            if vulns
                        },
                        'all': [
                            {
                                'id': v['id'],
                                'name': v['name'],
                                'severity': v.get('severity', 'Unknown'),
                                'type': v.get('type', 'Unknown'),
                                'description': v.get('description', ''),
                                'match_confidence': v.get('match_confidence', 0.0)
                            }
                            for v in vulnerabilities_found
                        ]
                    },
                    'not_found': {
                        'total': len(vulnerabilities_not_found),
                        'by_severity': {
                            severity: [
                                {
                                    'id': v['id'],
                                    'name': v['name'],
                                    'type': v.get('type', 'Unknown'),
                                    'description': v.get('description', '')
                                }
                                for v in vulnerabilities_not_found
                                if v.get('severity') == severity
                            ]
                            for severity in ['Critical', 'High', 'Medium', 'Low']
                        },
                        'all': [
                            {
                                'id': v['id'],
                                'name': v['name'],
                                'severity': v.get('severity', 'Unknown'),
                                'type': v.get('type', 'Unknown'),
                                'description': v.get('description', '')
                            }
                            for v in vulnerabilities_not_found
                        ]
                    }
                }
            }
        }
    
    def _generate_markdown_report(self, report: Dict[str, Any]) -> str:
        """
        Generate a human-readable Markdown report from structured report.
        
        Args:
            report: Structured report dictionary
            
        Returns:
            Markdown formatted report string
        """
        md = []
        
        # Header
        md.append("# Security Evaluation Report")
        md.append("")
        md.append("---")
        md.append("")
        
        # Metadata
        metadata = report['metadata']
        md.append("## Metadata")
        md.append("")
        md.append(f"- **Run ID:** `{metadata['run_id']}`")
        md.append(f"- **Timestamp:** {metadata['timestamp']}")
        md.append(f"- **Target URL:** {metadata['url']}")
        md.append(f"- **Website Builder Model:** {metadata['models']['website_builder']}")
        md.append(f"- **Red Team Model:** {metadata['models']['red_team_agent']}")
        md.append("")
        
        # Execution Summary
        md.append("## Execution Summary")
        md.append("")
        exec_data = report['execution']
        
        md.append("### Website Build")
        md.append(f"- **Status:** {exec_data['website_build']['status']}")
        md.append(f"- **Files Created:** {exec_data['website_build']['files_created']}")
        md.append(f"- **Output Directory:** `{exec_data['website_build']['output_directory']}`")
        md.append("")
        
        md.append("### Red Team Assessment")
        md.append(f"- **Execution Time:** {exec_data['red_team_assessment']['execution_time_seconds']} seconds")
        md.append(f"- **Report File:** `{exec_data['red_team_assessment']['report_file']}`")
        if exec_data['red_team_assessment'].get('trace_id'):
            md.append(f"- **Trace ID:** `{exec_data['red_team_assessment']['trace_id']}`")
        md.append("")
        
        # Evaluation Summary
        md.append("## Evaluation Summary")
        md.append("")
        eval_summary = report['evaluation']['summary']
        md.append(f"- **Total Vulnerabilities:** {eval_summary['total_vulnerabilities']}")
        md.append(f"- **Found:** {eval_summary['found_count']}")
        md.append(f"- **Not Found:** {eval_summary['not_found_count']}")
        md.append(f"- **Detection Rate:** {eval_summary['overall_detection_rate']:.2%}")
        md.append("")
        
        # Metrics by Severity
        md.append("### Detection Rate by Severity")
        md.append("")
        metrics_by_severity = report['evaluation']['metrics_by_severity']
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in metrics_by_severity:
                metrics = metrics_by_severity[severity]
                md.append(f"**{severity}:**")
                md.append(f"- Found: {metrics['found']}/{metrics['total']}")
                md.append(f"- Detection Rate: {metrics['detection_rate']:.2%}")
                md.append("")
        
        # Found Vulnerabilities
        md.append("## Found Vulnerabilities")
        md.append("")
        found_vulns = report['evaluation']['vulnerabilities']['found']
        md.append(f"**Total Found: {found_vulns['total']}**")
        md.append("")
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in found_vulns['by_severity']:
                severity_data = found_vulns['by_severity'][severity]
                md.append(f"### {severity} Severity ({severity_data['count']})")
                md.append("")
                for vuln in severity_data['vulnerabilities']:
                    md.append(f"#### {vuln['id']}: {vuln['name']}")
                    md.append(f"- **Type:** {vuln['type']}")
                    md.append(f"- **Description:** {vuln['description']}")
                    if vuln.get('agent_description'):
                        md.append(f"- **Agent Finding:** {vuln['agent_description']}")
                    md.append(f"- **Match Confidence:** {vuln['match_confidence']:.2%}")
                    md.append("")
        
        # Not Found Vulnerabilities
        md.append("## Not Found Vulnerabilities")
        md.append("")
        not_found_vulns = report['evaluation']['vulnerabilities']['not_found']
        md.append(f"**Total Not Found: {not_found_vulns['total']}**")
        md.append("")
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            vulns = not_found_vulns['by_severity'][severity]
            if vulns:
                md.append(f"### {severity} Severity ({len(vulns)})")
                md.append("")
                for vuln in vulns:
                    md.append(f"- **{vuln['id']}:** {vuln['name']} ({vuln['type']})")
                    md.append(f"  - {vuln['description']}")
                md.append("")
        
        # Footer
        md.append("---")
        md.append("")
        md.append(f"*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\n".join(md)
    
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
        from website_generator.prompts import USER_PROMPT
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
            "eval_results": None,
            "final_report": None,
            "next": "website_builder",
            "output_dir": self.output_dir,
            "website_builder_model": self.website_builder_model,
            "red_team_model": self.red_team_model
        }
        
        server = None
        
        try:
            # Run the graph
            final_state = None
            for node_name, node_state in self.graph.stream(initial_state):
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
            eval_results = final_state.get("eval_results")
            
            if not all([run_id, url, build_result, red_team_result, eval_results]):
                raise Exception("Incomplete evaluation - missing required results")
            
            # Step 6: Create final report with clear structure
            final_report = self._create_structured_report(
                run_id=run_id,
                url=url,
                build_result=build_result,
                red_team_result=red_team_result,
                eval_results=eval_results
            )
            
            # Save final report (JSON and Markdown)
            final_report_json = self.output_dir / run_id / "final_report.json"
            final_report_md = self.output_dir / run_id / "final_report.md"
            
            with open(final_report_json, 'w', encoding='utf-8') as f:
                json.dump(final_report, f, indent=2, ensure_ascii=False)
            
            # Generate and save Markdown report
            markdown_report = self._generate_markdown_report(final_report)
            with open(final_report_md, 'w', encoding='utf-8') as f:
                f.write(markdown_report)
            
            print("\n" + "="*70)
            print("EVALUATION COMPLETE")
            print("="*70)
            print(f"Run ID: {run_id}")
            print(f"URL: {url}")
            print(f"\nVulnerabilities Found: {eval_results['metrics']['found']}/{eval_results['metrics']['total_vulnerabilities']}")
            if 'overall_detection_rate' in eval_results['metrics']:
                print(f"Detection Rate: {eval_results['metrics']['overall_detection_rate']:.2%}")
            print(f"\nFinal Reports:")
            print(f"  JSON: {final_report_json}")
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

