"""
State schema for LangGraph orchestrator.

Defines the shared state that flows through the agent graph.
"""

from typing import TypedDict, List, Optional, Dict, Any
from pathlib import Path
from langchain_core.messages import BaseMessage


class OrchestratorState(TypedDict):
    """
    State schema for the orchestrator workflow.

    This state is passed between agents and nodes in the LangGraph.
    """
    # Messages for agent communication
    messages: List[BaseMessage]

    # Run metadata
    run_id: Optional[str]
    prompt: Optional[str]
    port: int

    # Directory paths (new structure)
    run_dir: Optional[Path]  # Main run directory (YYYYMMDD/HHMMSS_model_model/)
    website_dir: Optional[Path]  # Website files subdirectory
    logs_dir: Optional[Path]  # Logs subdirectory

    # Website build results
    build_result: Optional[Dict[str, Any]]

    # Server management
    url: Optional[str]
    server: Optional[Any]  # WebsiteServer instance

    # Red team results
    red_team_result: Optional[Dict[str, Any]]
    red_team_report_file: Optional[Path]  # Original red team markdown report

    # Static analysis results
    static_analysis_result: Optional[Dict[str, Any]]

    # Evaluation results (separate for each component)
    website_builder_eval_results: Optional[Dict[str, Any]]
    red_team_eval_results: Optional[Dict[str, Any]]
    final_eval_results: Optional[Dict[str, Any]]

    # Report paths (new consolidated structure)
    run_json: Optional[Path]  # Consolidated run.json
    report_md: Optional[Path]  # Consolidated report.md

    # Legacy report paths (for backward compatibility)
    website_builder_eval_report_json: Optional[Path]
    website_builder_eval_report_md: Optional[Path]
    red_team_eval_report_json: Optional[Path]
    red_team_eval_report_md: Optional[Path]
    final_report_json: Optional[Path]
    final_report_md: Optional[Path]

    # Legacy field (for backward compatibility)
    eval_results: Optional[Dict[str, Any]]

    # Final report
    final_report: Optional[Dict[str, Any]]

    # Next agent to execute (supervisor routing)
    next: str

    # Configuration
    output_dir: Optional[Path]
    website_builder_model: Optional[str]
    red_team_model: Optional[str]
    website_builder_ground_truth_path: Optional[str]
    red_team_ground_truth_path: Optional[str]

