"""
Unified Evaluation Framework

Provides a unified interface for evaluating both website builder agents
and red team agents against ground truth data.
"""

from pathlib import Path
from typing import Dict, Optional, Any
from datetime import datetime

from vibe_code_bench.core.logging_setup import get_logger
from vibe_code_bench.core.paths import get_absolute_path

logger = get_logger(__name__)


class WebsiteBuilderEvaluator:
    """Evaluates website builder agents by analyzing generated websites."""
    
    def __init__(self, ground_truth_path: str):
        """
        Initialize website builder evaluator.
        
        Args:
            ground_truth_path: Path to ground truth vulnerabilities JSON file
        """
        self.ground_truth_path = get_absolute_path(ground_truth_path)
        if not self.ground_truth_path.exists():
            raise FileNotFoundError(f"Ground truth file not found: {self.ground_truth_path}")
    
    def evaluate(
        self,
        builder_module_path: str,
        website_dir: Path,
        builder_name: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Evaluate a website builder by analyzing its generated website.
        
        Args:
            builder_module_path: Path to builder module (e.g., 'website_generator.main')
            website_dir: Directory containing generated website files
            builder_name: Name/version of the builder
            
        Returns:
            Evaluation results dictionary
        """
        from vibe_code_bench.website_generator.eval.inspect_eval_framework import (
            evaluate_website_builder
        )
        
        website_dir = Path(website_dir)
        if not website_dir.exists():
            raise FileNotFoundError(f"Website directory not found: {website_dir}")
        
        logger.info(f"Evaluating website builder: {builder_name}")
        logger.info(f"  Builder module: {builder_module_path}")
        logger.info(f"  Website directory: {website_dir}")
        logger.info(f"  Ground truth: {self.ground_truth_path}")
        
        results = evaluate_website_builder(
            builder_module_path=builder_module_path,
            website_dir=website_dir,
            ground_truth_path=str(self.ground_truth_path),
            builder_name=builder_name
        )
        
        logger.info(f"Website builder evaluation completed")
        logger.info(f"  Security score: {results['metrics']['overall_security_score']:.2%}")
        logger.info(f"  Vulnerabilities found: {results['metrics']['vulnerabilities_found']}/{results['metrics']['vulnerabilities_total']}")
        
        return results
    
    def save_results(self, results: Dict[str, Any], output_path: str) -> Path:
        """
        Save evaluation results to JSON file.
        
        Args:
            results: Evaluation results dictionary
            output_path: Path to save JSON file
            
        Returns:
            Path to saved file
        """
        from vibe_code_bench.website_generator.eval.inspect_eval_framework import (
            WebsiteBuilderEvaluator as WBEvaluator
        )
        
        output_file = get_absolute_path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Use the evaluator's save method
        evaluator = WBEvaluator(
            builder_module_path="",  # Not needed for saving
            website_dir=Path(""),  # Not needed for saving
            ground_truth_path=str(self.ground_truth_path)
        )
        evaluator.save_results(results, str(output_file))
        
        logger.info(f"Website builder evaluation results saved to: {output_file}")
        return output_file


class RedTeamEvaluator:
    """Evaluates red team agents by comparing findings against ground truth."""
    
    def __init__(self, ground_truth_path: str):
        """
        Initialize red team evaluator.
        
        Args:
            ground_truth_path: Path to ground truth vulnerabilities JSON file
        """
        self.ground_truth_path = get_absolute_path(ground_truth_path)
        if not self.ground_truth_path.exists():
            raise FileNotFoundError(f"Ground truth file not found: {self.ground_truth_path}")
        
        from vibe_code_bench.red_team_agent.eval.eval_framework import VulnerabilityEvaluator
        self.evaluator = VulnerabilityEvaluator(str(self.ground_truth_path))
    
    def evaluate(
        self,
        report_content: str,
        url: str,
        model_name: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Evaluate red team agent findings against ground truth.
        
        Args:
            report_content: Markdown report content from red team agent
            url: URL that was tested
            model_name: Name of the model used
            
        Returns:
            Evaluation results dictionary
        """
        logger.info(f"Evaluating red team agent findings")
        logger.info(f"  URL: {url}")
        logger.info(f"  Model: {model_name}")
        logger.info(f"  Report length: {len(report_content)} characters")
        
        results = self.evaluator.evaluate(
            report_content=report_content,
            url=url,
            model_name=model_name
        )
        
        logger.info(f"Red team evaluation completed")
        logger.info(f"  Detection rate: {results['metrics']['overall_detection_rate']:.2%}")
        logger.info(f"  Found: {results['metrics']['found']}/{results['metrics']['total_vulnerabilities']}")
        
        return results
    
    def save_results(self, results: Dict[str, Any], output_path: str) -> Path:
        """
        Save evaluation results to JSON file.
        
        Args:
            results: Evaluation results dictionary
            output_path: Path to save JSON file
            
        Returns:
            Path to saved file
        """
        output_file = get_absolute_path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.evaluator.save_evaluation_results(results, str(output_file))
        
        logger.info(f"Red team evaluation results saved to: {output_file}")
        return output_file


class UnifiedEvaluator:
    """Unified interface for all evaluations."""
    
    def __init__(
        self,
        website_builder_ground_truth_path: Optional[str] = None,
        red_team_ground_truth_path: Optional[str] = None
    ):
        """
        Initialize unified evaluator.
        
        Args:
            website_builder_ground_truth_path: Path to ground truth for website builder evaluation
            red_team_ground_truth_path: Path to ground truth for red team evaluation
        """
        self.website_builder_evaluator = None
        self.red_team_evaluator = None
        
        if website_builder_ground_truth_path:
            self.website_builder_evaluator = WebsiteBuilderEvaluator(website_builder_ground_truth_path)
        
        if red_team_ground_truth_path:
            self.red_team_evaluator = RedTeamEvaluator(red_team_ground_truth_path)
    
    def evaluate_website_builder(
        self,
        builder_module_path: str,
        website_dir: Path,
        builder_name: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Evaluate website builder.
        
        Args:
            builder_module_path: Path to builder module
            website_dir: Directory containing generated website
            builder_name: Name of the builder
            
        Returns:
            Evaluation results
        """
        if not self.website_builder_evaluator:
            raise ValueError("Website builder evaluator not initialized")
        
        return self.website_builder_evaluator.evaluate(
            builder_module_path=builder_module_path,
            website_dir=website_dir,
            builder_name=builder_name
        )
    
    def evaluate_red_team(
        self,
        report_content: str,
        url: str,
        model_name: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Evaluate red team agent.
        
        Args:
            report_content: Markdown report content
            url: URL that was tested
            model_name: Name of the model used
            
        Returns:
            Evaluation results
        """
        if not self.red_team_evaluator:
            raise ValueError("Red team evaluator not initialized")
        
        return self.red_team_evaluator.evaluate(
            report_content=report_content,
            url=url,
            model_name=model_name
        )

