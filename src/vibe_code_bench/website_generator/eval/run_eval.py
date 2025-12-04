#!/usr/bin/env python3
"""
Run evaluation on a website builder and its generated website.

Usage:
    python run_eval.py <builder_module> <website_dir> <ground_truth_path> [builder_name] [output_path]
    
Example:
    python run_eval.py website_generator.agent runs/run_20251203_130725/website ../red_team_agent/eval/ground_truth_vulnerabilities.json SimpleWebsiteCreatorAgent eval_results.json
"""

import sys
import argparse
from pathlib import Path

# Import paths utility
from vibe_code_bench.core.paths import get_repo_root, get_absolute_path
project_root = get_repo_root()

from vibe_code_bench.website_generator.eval.inspect_eval_framework import evaluate_website_builder


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate website builder using inspect and security analysis"
    )
    parser.add_argument(
        "builder_module",
        type=str,
        help="Python module path to website builder (e.g., 'website_generator.agent')"
    )
    parser.add_argument(
        "website_dir",
        type=str,
        help="Directory containing generated website files"
    )
    parser.add_argument(
        "ground_truth_path",
        type=str,
        help="Path to ground truth vulnerabilities JSON file"
    )
    parser.add_argument(
        "--builder-name",
        type=str,
        default="unknown",
        help="Name/version of the builder (default: unknown)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to save evaluation results JSON (optional)"
    )
    
    args = parser.parse_args()
    
    # Validate paths (resolve to absolute)
    website_dir = get_absolute_path(args.website_dir)
    if not website_dir.exists():
        print(f"Error: Website directory not found: {website_dir}")
        sys.exit(1)
    
    ground_truth_path = get_absolute_path(args.ground_truth_path)
    if not ground_truth_path.exists():
        print(f"Error: Ground truth file not found: {ground_truth_path}")
        sys.exit(1)
    
    # Run evaluation
    try:
        results = evaluate_website_builder(
            builder_module_path=args.builder_module,
            website_dir=website_dir,
            ground_truth_path=str(ground_truth_path),
            builder_name=args.builder_name,
            output_path=get_absolute_path(args.output) if args.output else None
        )
        
        # Print summary
        print("\n" + "="*60)
        print("WEBSITE BUILDER EVALUATION RESULTS")
        print("="*60)
        print(f"Builder: {results['builder_name']}")
        print(f"Evaluation Date: {results['evaluation_date']}")
        print(f"\nBuilder Analysis:")
        print(f"  Class: {results['builder_analysis']['class']}")
        print(f"  Methods: {len(results['builder_analysis']['analysis']['methods'])}")
        print(f"  Security-related methods: {len(results['builder_analysis']['analysis']['security_related_methods'])}")
        
        print(f"\nSecurity Analysis:")
        print(f"  Files analyzed: {results['security_analysis']['files_analyzed']}")
        print(f"  Vulnerabilities found: {len(results['security_analysis']['vulnerabilities_found'])}")
        
        print(f"\nOverall Security Score: {results['metrics']['overall_security_score']:.2%}")
        print(f"  (Lower is better - indicates fewer vulnerabilities)")
        print(f"Vulnerabilities Found: {results['metrics']['vulnerabilities_found']}/{results['metrics']['vulnerabilities_total']}")
        
        print("\nVulnerabilities by Severity:")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            metrics = results['metrics']['by_severity'][severity]
            if metrics['total'] > 0:
                print(f"  {severity:8s}: Found {metrics['found']}/{metrics['total']} vulnerabilities")
        
        print("\nFound Vulnerabilities:")
        found_vulns = [v for v in results['vulnerabilities'] if v['found']]
        if found_vulns:
            for vuln in found_vulns[:10]:  # Show first 10
                print(f"  ✗ {vuln['id']}: {vuln['name']} ({vuln['severity']})")
            if len(found_vulns) > 10:
                print(f"  ... and {len(found_vulns) - 10} more")
        else:
            print("  ✓ No vulnerabilities found!")
        
        print("\nNot Found (Secure):")
        not_found_vulns = [v for v in results['vulnerabilities'] if not v['found']]
        print(f"  ✓ {len(not_found_vulns)}/{len(results['vulnerabilities'])} vulnerabilities not present (good!)")
        
        if args.output:
            print(f"\n✓ Results saved to: {args.output}")
        
    except Exception as e:
        print(f"Error during evaluation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

