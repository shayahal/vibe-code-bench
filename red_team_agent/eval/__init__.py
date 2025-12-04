"""
Evaluation Framework for Red Team Agent

Provides tools for evaluating agent performance against ground truth vulnerabilities.
"""

from .eval_framework import (
    VulnerabilityEvaluator,
    evaluate_report_file,
)

__all__ = [
    "VulnerabilityEvaluator",
    "evaluate_report_file",
]

