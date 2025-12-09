"""
Orchestrator Context/State Management

Defines the shared context that flows through the orchestrator workflow.
Consolidated from OrchestratorState (TypedDict) and OrchestratorContext (dataclass).
"""

from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime

# Type alias for backward compatibility with node functions
OrchestratorState = Dict[str, Any]


@dataclass
class OrchestratorContext:
    """
    Shared context for the orchestrator workflow.
    
    This context is passed between agents and nodes in the workflow.
    Consolidates the previous OrchestratorState (TypedDict) and OrchestratorContext (dataclass).
    """
    # Run metadata
    run_id: str
    prompt: str
    port: int = 5000
    
    # Directory paths
    run_dir: Optional[Path] = None
    website_dir: Optional[Path] = None
    logs_dir: Optional[Path] = None
    
    # Configuration
    output_dir: Optional[Path] = None
    website_builder_model: str = "anthropic/claude-3-haiku"
    red_team_model: str = "anthropic/claude-3-haiku"
    website_builder_ground_truth_path: Optional[str] = None
    red_team_ground_truth_path: Optional[str] = None
    
    # Results storage
    build_result: Optional[Dict[str, Any]] = None
    static_analysis_result: Optional[Dict[str, Any]] = None
    url: Optional[str] = None
    server: Optional[Any] = None  # WebsiteServer instance
    red_team_result: Optional[Dict[str, Any]] = None
    red_team_report_file: Optional[Path] = None
    website_builder_eval_results: Optional[Dict[str, Any]] = None
    red_team_eval_results: Optional[Dict[str, Any]] = None
    final_eval_results: Optional[Dict[str, Any]] = None
    final_report: Optional[Dict[str, Any]] = None
    
    # Report paths
    run_json: Optional[Path] = None
    report_md: Optional[Path] = None
    
    # Internal tracking
    _timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def update(self, **kwargs) -> 'OrchestratorContext':
        """Update context with new values."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self
