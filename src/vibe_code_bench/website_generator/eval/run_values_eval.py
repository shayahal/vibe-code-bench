#!/usr/bin/env python3
"""
Run values evaluation on a website builder agent.

Usage:
    python run_values_eval.py <agent_module> <values_ground_truth_path> [--output-dir OUTPUT_DIR] [--run-dir RUN_DIR] [--agent-name NAME] [--output OUTPUT_PATH]
    
Example:
    python run_values_eval.py website_generator.agent values_ground_truth.json --output-dir runs/run_123/website --run-dir runs/run_123 --agent-name SimpleWebsiteCreatorAgent --output values_eval_results.json
"""

import sys
import argparse
from pathlib import Path

# Add parent directories to path for imports
from vibe_code_bench.core.paths import get_repo_root, get_absolute_path
project_root = get_repo_root()
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from vibe_code_bench.website_generator.eval.values_eval_framework import evaluate_website_builder_values


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate website builder agent values adherence"
    )
    parser.add_argument(
        "agent_module",
        type=str,
        help="Python module path to website builder (e.g., 'website_generator.agent')"
    )
    parser.add_argument(
        "values_ground_truth_path",
        type=str,
        help="Path to values ground truth JSON file"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        help="Directory containing generated website files (optional)"
    )
    parser.add_argument(
        "--run-dir",
        type=str,
        help="Directory containing run artifacts/logs (optional)"
    )
    parser.add_argument(
        "--agent-name",
        type=str,
        default="unknown",
        help="Name/version of the agent (default: unknown)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to save evaluation results JSON (optional)"
    )
    
    args = parser.parse_args()
    
    # Validate paths (resolve to absolute)
    values_ground_truth_path = get_absolute_path(args.values_ground_truth_path)
    if not values_ground_truth_path.exists():
        print(f"Error: Values ground truth file not found: {values_ground_truth_path}")
        sys.exit(1)
    
    output_dir = get_absolute_path(args.output_dir) if args.output_dir else None
    if output_dir and not output_dir.exists():
        print(f"Warning: Output directory not found: {output_dir}")
        print("  Continuing without output analysis...")
        output_dir = None
    
    run_dir = get_absolute_path(args.run_dir) if args.run_dir else None
    if run_dir and not run_dir.exists():
        print(f"Warning: Run directory not found: {run_dir}")
        print("  Continuing without runtime analysis...")
        run_dir = None
    
    # Run evaluation
    try:
        results = evaluate_website_builder_values(
            agent_module_path=args.agent_module,
            values_ground_truth_path=str(values_ground_truth_path),
            output_dir=output_dir,
            run_dir=run_dir,
            agent_name=args.agent_name,
            output_path=get_absolute_path(args.output) if args.output else None
        )
        
        # Print summary
        print("\n" + "="*60)
        print("WEBSITE BUILDER VALUES EVALUATION RESULTS")
        print("="*60)
        print(f"Agent: {results['agent_name']}")
        print(f"Evaluation Date: {results['evaluation_date']}")
        print(f"Values Ground Truth: {results['values_ground_truth']}")
        
        print(f"\nOverall Adherence Score: {results['metrics']['overall_adherence_score']:.2%}")
        print(f"Values Adhered: {results['metrics']['adhered']}/{results['metrics']['total_values']}")
        print(f"Values Not Adhered: {results['metrics']['not_adhered']}/{results['metrics']['total_values']}")
        
        print("\nBy Category:")
        for category, metrics in results['metrics']['by_category'].items():
            print(f"  {category:20s}: {metrics['adhered']:2d}/{metrics['total']:2d} ({metrics['adherence_rate']:5.1%})")
        
        print("\nBy Severity:")
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in results['metrics']['by_severity']:
                metrics = results['metrics']['by_severity'][severity]
                print(f"  {severity:20s}: {metrics['adhered']:2d}/{metrics['total']:2d} ({metrics['adherence_rate']:5.1%})")
        
        print("\nValues Not Adhered (Critical/High Severity):")
        not_adhered_critical = [
            v for v in results['values']
            if not v['adhered'] and v['severity'] in ['critical', 'high']
        ]
        if not_adhered_critical:
            for value in not_adhered_critical[:10]:  # Show first 10
                print(f"  ✗ {value['id']}: {value['name']} ({value['severity']})")
                if value['evidence']:
                    print(f"      Evidence: {', '.join(value['evidence'][:2])}")
            if len(not_adhered_critical) > 10:
                print(f"  ... and {len(not_adhered_critical) - 10} more")
        else:
            print("  ✓ All critical/high severity values are adhered to!")
        
        print("\nValues Adhered:")
        adhered_values = [v for v in results['values'] if v['adhered']]
        print(f"  ✓ {len(adhered_values)}/{len(results['values'])} values adhered to")
        
        if args.output:
            print(f"\n✓ Results saved to: {args.output}")
        
    except Exception as e:
        print(f"Error during evaluation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

