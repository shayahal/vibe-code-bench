"""
Vibe Code Bench - Benchmark for the security of vibe coded apps.

A comprehensive security testing framework with:
- Red Team Agent for automated vulnerability assessment
- Website Generator for creating test targets
- Orchestrator for coordinating evaluation workflows
"""

__version__ = "0.1.0"

# Lazy imports to avoid dependency issues at import time
# Import modules only when accessed
__all__ = [
    "core",
    "orchestrator",
    "red_team_agent",
    "website_generator",
]

