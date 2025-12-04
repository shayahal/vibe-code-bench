"""
Evaluation Framework for Red Team Agent

Evaluates red team agent performance by comparing found vulnerabilities
against a ground truth dataset.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime


class VulnerabilityEvaluator:
    """Evaluates agent findings against ground truth vulnerabilities."""
    
    def __init__(self, ground_truth_path: str):
        """
        Initialize evaluator with ground truth data.
        
        Args:
            ground_truth_path: Path to ground truth JSON file
        """
        self.ground_truth_path = Path(ground_truth_path)
        self.ground_truth = self._load_ground_truth()
        self.vuln_index = self._build_vulnerability_index()
    
    def _load_ground_truth(self) -> Dict:
        """Load ground truth vulnerabilities from JSON file."""
        with open(self.ground_truth_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _build_vulnerability_index(self) -> Dict[str, Dict]:
        """Build index of vulnerabilities by ID for quick lookup."""
        return {vuln['id']: vuln for vuln in self.ground_truth['vulnerabilities']}
    
    def extract_vulnerabilities_from_report(self, report_content: str) -> List[Dict]:
        """
        Extract vulnerabilities from agent report.
        
        Parses markdown report to find vulnerability IDs and descriptions.
        
        Args:
            report_content: Markdown report content
            
        Returns:
            List of found vulnerabilities with IDs and descriptions
        """
        found_vulns = []
        
        # Pattern to match VULN-XXX format
        vuln_pattern = r'\*\*VULN-(\d+)\*\*[:\s]*(.*?)(?=\*\*VULN-|\n##|\Z)'
        
        matches = re.finditer(vuln_pattern, report_content, re.DOTALL | re.IGNORECASE)
        
        for match in matches:
            vuln_id = f"VULN-{match.group(1).zfill(3)}"
            description = match.group(2).strip()
            
            # Clean up description (remove Fix: sections, etc.)
            description = re.sub(r'\*\*Fix:\*\*.*', '', description, flags=re.IGNORECASE)
            description = description.strip()
            
            found_vulns.append({
                'id': vuln_id,
                'description': description,
                'raw_match': match.group(0)
            })
        
        # Also search for vulnerabilities mentioned without VULN-XXX format
        # by checking for keywords
        for vuln in self.ground_truth['vulnerabilities']:
            if vuln['id'] not in [v['id'] for v in found_vulns]:
                # Check if vulnerability keywords appear in report
                for keyword in vuln['keywords']:
                    if keyword.lower() in report_content.lower():
                        # Additional check: make sure it's actually about this vulnerability
                        if self._is_vulnerability_mentioned(report_content, vuln):
                            found_vulns.append({
                                'id': vuln['id'],
                                'description': vuln['name'],
                                'raw_match': f"Found via keyword: {keyword}"
                            })
                            break
        
        return found_vulns
    
    def _is_vulnerability_mentioned(self, report_content: str, vuln: Dict) -> bool:
        """
        Check if a vulnerability is mentioned in the report.
        
        Uses multiple keywords and context to determine if vulnerability is found.
        """
        content_lower = report_content.lower()
        
        # Check if at least 2 keywords match
        matching_keywords = sum(1 for kw in vuln['keywords'] if kw.lower() in content_lower)
        
        # Also check for vulnerability name
        name_match = vuln['name'].lower() in content_lower
        
        return matching_keywords >= 2 or name_match
    
    def evaluate(self, report_content: str, url: str, model_name: str = "unknown") -> Dict:
        """
        Evaluate agent report against ground truth.
        
        Args:
            report_content: Markdown report content from agent
            url: URL that was tested
            model_name: Name of the model used
            
        Returns:
            Evaluation results dictionary
        """
        found_vulns = self.extract_vulnerabilities_from_report(report_content)
        found_ids = {v['id'] for v in found_vulns}
        
        # Build evaluation results
        results = {
            'url': url,
            'model': model_name,
            'evaluation_date': datetime.now().isoformat(),
            'ground_truth_total': len(self.ground_truth['vulnerabilities']),
            'found_count': len(found_vulns),
            'vulnerabilities': []
        }
        
        # Evaluate each ground truth vulnerability
        for vuln in self.ground_truth['vulnerabilities']:
            vuln_id = vuln['id']
            is_found = vuln_id in found_ids
            
            # Get found vulnerability details if it was found
            found_details = next((v for v in found_vulns if v['id'] == vuln_id), None)
            
            results['vulnerabilities'].append({
                'id': vuln_id,
                'name': vuln['name'],
                'description': vuln['description'],
                'severity': vuln['severity'],
                'type': vuln['type'],
                'found': is_found,
                'agent_description': found_details['description'] if found_details else None,
                'match_confidence': self._calculate_confidence(found_details, vuln) if found_details else 0.0
            })
        
        # Calculate metrics
        results['metrics'] = self._calculate_metrics(results['vulnerabilities'])
        
        return results
    
    def _calculate_confidence(self, found_details: Dict, ground_truth: Dict) -> float:
        """
        Calculate confidence score for a match.
        
        Returns a value between 0.0 and 1.0 indicating how confident
        we are that the agent found this specific vulnerability.
        """
        if not found_details:
            return 0.0
        
        confidence = 0.5  # Base confidence
        
        # Check if VULN-XXX ID was explicitly mentioned
        if found_details.get('id') == ground_truth['id']:
            confidence += 0.4
        
        # Check keyword overlap
        found_desc = found_details.get('description', '').lower()
        keyword_matches = sum(1 for kw in ground_truth['keywords'] 
                            if kw.lower() in found_desc)
        confidence += min(0.1 * keyword_matches, 0.1)
        
        return min(confidence, 1.0)
    
    def _calculate_metrics(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate evaluation metrics."""
        total = len(vulnerabilities)
        found = sum(1 for v in vulnerabilities if v['found'])
        not_found = total - found
        
        # Group by severity
        by_severity = {}
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            severity_vulns = [v for v in vulnerabilities if v['severity'] == severity]
            found_severity = sum(1 for v in severity_vulns if v['found'])
            by_severity[severity] = {
                'total': len(severity_vulns),
                'found': found_severity,
                'not_found': len(severity_vulns) - found_severity,
                'detection_rate': found_severity / len(severity_vulns) if severity_vulns else 0.0
            }
        
        return {
            'overall_detection_rate': found / total if total > 0 else 0.0,
            'total_vulnerabilities': total,
            'found': found,
            'not_found': not_found,
            'by_severity': by_severity
        }
    
    def save_evaluation_results(self, results: Dict, output_path: str):
        """
        Save evaluation results to JSON file.
        
        Args:
            results: Evaluation results dictionary
            output_path: Path to save JSON file
        """
        from vibe_code_bench.core.paths import get_reports_dir, get_absolute_path
        
        if output_path:
            output_file = get_absolute_path(output_path)
        else:
            # Default: use standard reports directory
            output_file = get_reports_dir() / "evaluation_results.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        return output_file


def evaluate_report_file(
    report_path: str,
    ground_truth_path: str,
    url: str,
    model_name: str = "unknown",
    output_path: Optional[str] = None
) -> Dict:
    """
    Evaluate a report file against ground truth.
    
    Args:
        report_path: Path to markdown report file
        ground_truth_path: Path to ground truth JSON file
        url: URL that was tested
        model_name: Name of the model used
        output_path: Optional path to save evaluation results
        
    Returns:
        Evaluation results dictionary
    """
    evaluator = VulnerabilityEvaluator(ground_truth_path)
    
    # Read report file
    with open(report_path, 'r', encoding='utf-8') as f:
        report_content = f.read()
    
    # Evaluate
    results = evaluator.evaluate(report_content, url, model_name)
    
    # Save if output path provided
    if output_path:
        evaluator.save_evaluation_results(results, output_path)
    
    return results


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python eval_framework.py <report_path> <url> [model_name] [output_path]")
        sys.exit(1)
    
    report_path = sys.argv[1]
    url = sys.argv[2]
    model_name = sys.argv[3] if len(sys.argv) > 3 else "unknown"
    output_path = sys.argv[4] if len(sys.argv) > 4 else None
    
    from vibe_code_bench.core.paths import get_repo_root
    ground_truth_path = get_repo_root() / "src" / "vibe_code_bench" / "red_team_agent" / "eval" / "ground_truth_vulnerabilities.json"
    
    results = evaluate_report_file(
        report_path=report_path,
        ground_truth_path=str(ground_truth_path),
        url=url,
        model_name=model_name,
        output_path=output_path
    )
    
    # Print summary
    print("\n" + "="*60)
    print("EVALUATION RESULTS")
    print("="*60)
    print(f"URL: {results['url']}")
    print(f"Model: {results['model']}")
    print(f"\nOverall Detection Rate: {results['metrics']['overall_detection_rate']:.2%}")
    print(f"Found: {results['metrics']['found']}/{results['metrics']['total_vulnerabilities']}")
    print("\nBy Severity:")
    for severity, metrics in results['metrics']['by_severity'].items():
        if metrics['total'] > 0:
            print(f"  {severity}: {metrics['found']}/{metrics['total']} ({metrics['detection_rate']:.2%})")
    
    if output_path:
        print(f"\nResults saved to: {output_path}")

