"""
Inspect-based Evaluation Framework for Website Builder Agents

Uses Python's inspect module to analyze website builder code and evaluate
the security of generated websites.
"""

from .inspect_eval_framework import (
    WebsiteBuilderInspector,
    WebsiteSecurityAnalyzer,
    WebsiteBuilderEvaluator,
    evaluate_website_builder,
)

__all__ = [
    "WebsiteBuilderInspector",
    "WebsiteSecurityAnalyzer",
    "WebsiteBuilderEvaluator",
    "evaluate_website_builder",
]

