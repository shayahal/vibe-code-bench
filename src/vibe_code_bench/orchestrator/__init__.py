"""
Orchestrator Package

Orchestrates website building and red team evaluation using CrewAI
framework for multi-agent coordination with built-in observability.

Modules:
- crew_agents: Agent definitions
- crew_tasks: Task definitions
- crew_tools: Tool organization
- crew_setup: CrewAI workflow setup
- crew_context: Context management
"""

from vibe_code_bench.orchestrator.main import Orchestrator, main

__all__ = ["Orchestrator", "main"]

