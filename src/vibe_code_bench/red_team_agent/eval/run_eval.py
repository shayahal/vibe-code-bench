#!/usr/bin/env python3
"""
Run evaluation on a red team agent report.

Usage:
    python run_eval.py <report_path> <url> [model_name] [output_path]
"""

import sys
import argparse
from pathlib import Path
from vibe_code_bench.red_team_agent.eval.eval_framework import evaluate_report_file


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate red team agent report against ground truth vulnerabilities"
    )
    parser.add_argument(
        "report_path",
        type=str,
        help="Path to markdown report file"
    )
    parser.add_argument(
        "url",
        type=str,
        help="URL that was tested"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="unknown",
        help="Name of the model used (default: unknown)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to save evaluation results JSON (optional)"
    )
    parser.add_argument(
        "--ground-truth",
        type=str,
        default=None,
        help="Path to ground truth JSON file (default: ground_truth_vulnerabilities.json in same directory)"
    )
    
    args = parser.parse_args()
    
    # Determine ground truth path
    from vibe_code_bench.core.paths import get_absolute_path, get_repo_root
    
    if args.ground_truth:
        ground_truth_path = get_absolute_path(args.ground_truth)
    else:
        # Default: use standard location in repo
        ground_truth_path = get_repo_root() / "src" / "vibe_code_bench" / "red_team_agent" / "eval" / "ground_truth_vulnerabilities.json"
    
    if not ground_truth_path.exists():
        print(f"Error: Ground truth file not found: {ground_truth_path}")
        sys.exit(1)
    
    if not Path(args.report_path).exists():
        print(f"Error: Report file not found: {args.report_path}")
        sys.exit(1)
    
    # Run evaluation
    try:
        results = evaluate_report_file(
            report_path=args.report_path,
            ground_truth_path=str(ground_truth_path),
            url=args.url,
            model_name=args.model,
            output_path=args.output
        )
        
        # Print summary
        print("\n" + "="*60)
        print("EVALUATION RESULTS")
        print("="*60)
        print(f"URL: {results['url']}")
        print(f"Model: {results['model']}")
        print(f"Evaluation Date: {results['evaluation_date']}")
        print(f"\nOverall Detection Rate: {results['metrics']['overall_detection_rate']:.2%}")
        print(f"Found: {results['metrics']['found']}/{results['metrics']['total_vulnerabilities']}")
        print(f"Not Found: {results['metrics']['not_found']}/{results['metrics']['total_vulnerabilities']}")
        
        print("\nDetection Rate by Severity:")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            metrics = results['metrics']['by_severity'][severity]
            if metrics['total'] > 0:
                print(f"  {severity:8s}: {metrics['found']:2d}/{metrics['total']:2d} ({metrics['detection_rate']:5.1%})")
        
        print("\nFound Vulnerabilities:")
        found_vulns = [v for v in results['vulnerabilities'] if v['found']]
        for vuln in found_vulns:
            print(f"  ✓ {vuln['id']}: {vuln['name']} ({vuln['severity']})")
        
        print("\nNot Found Vulnerabilities:")
        not_found_vulns = [v for v in results['vulnerabilities'] if not v['found']]
        for vuln in not_found_vulns[:10]:  # Show first 10
            print(f"  ✗ {vuln['id']}: {vuln['name']} ({vuln['severity']})")
        if len(not_found_vulns) > 10:
            print(f"  ... and {len(not_found_vulns) - 10} more")
        
        if args.output:
            print(f"\n✓ Results saved to: {args.output}")
        
    except Exception as e:
        print(f"Error during evaluation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

