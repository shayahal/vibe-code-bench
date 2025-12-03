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
    
    # Website build results
    website_dir: Optional[Path]
    build_result: Optional[Dict[str, Any]]
    
    # Server management
    url: Optional[str]
    server: Optional[Any]  # WebsiteServer instance
    
    # Red team results
    red_team_result: Optional[Dict[str, Any]]
    
    # Evaluation results
    eval_results: Optional[Dict[str, Any]]
    
    # Final report
    final_report: Optional[Dict[str, Any]]
    
    # Next agent to execute (supervisor routing)
    next: str
    
    # Configuration
    output_dir: Optional[Path]
    website_builder_model: Optional[str]
    red_team_model: Optional[str]

