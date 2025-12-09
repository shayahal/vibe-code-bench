"""
CrewAI Context Management

Manages shared state/context for CrewAI workflows.
Provides CrewAI-compatible context passing for the orchestrator.
"""

from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class OrchestratorContext:
    """
    Shared context for CrewAI orchestrator workflow.
    
    This context is passed between tasks and agents in the CrewAI workflow.
    """
    # Run metadata
    run_id: str
    prompt: str
    port: int = 5000
    
    # Directory paths
    run_dir: Optional[Path] = None
    website_dir: Optional[Path] = None
    logs_dir: Optional[Path] = None
    reports_dir: Optional[Path] = None
    agent_dirs: Optional[Dict[str, Path]] = None
    
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
    website_builder_eval_results: Optional[Dict[str, Any]] = None
    red_team_eval_results: Optional[Dict[str, Any]] = None
    final_report: Optional[Dict[str, Any]] = None
    
    # Report paths
    run_json: Optional[Path] = None
    report_md: Optional[Path] = None
    red_team_report_file: Optional[Path] = None
    
    # Internal tracking
    _timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for compatibility with existing code."""
        return {
            'run_id': self.run_id,
            'prompt': self.prompt,
            'port': self.port,
            'run_dir': self.run_dir,
            'website_dir': self.website_dir,
            'logs_dir': self.logs_dir,
            'reports_dir': self.reports_dir,
            'agent_dirs': self.agent_dirs,
            'output_dir': self.output_dir,
            'website_builder_model': self.website_builder_model,
            'red_team_model': self.red_team_model,
            'website_builder_ground_truth_path': self.website_builder_ground_truth_path,
            'red_team_ground_truth_path': self.red_team_ground_truth_path,
            'build_result': self.build_result,
            'static_analysis_result': self.static_analysis_result,
            'url': self.url,
            'server': self.server,
            'red_team_result': self.red_team_result,
            'website_builder_eval_results': self.website_builder_eval_results,
            'red_team_eval_results': self.red_team_eval_results,
            'final_report': self.final_report,
            'run_json': self.run_json,
            'report_md': self.report_md,
            'red_team_report_file': self.red_team_report_file,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OrchestratorContext':
        """Create context from dictionary."""
        return cls(**data)
    
    def update(self, **kwargs) -> 'OrchestratorContext':
        """Update context with new values."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self

