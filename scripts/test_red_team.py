"""Test script to run red team agent on a browsing report."""

import logging
import sys
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

try:
    from vibe_code_bench.red_team_agent import RedTeamAgent
    
    # Find the browsing report for shayahal.com
    from vibe_code_bench.core.paths import get_reports_dir
    reports_dir = get_reports_dir()
    
    # Find the most recent browsing report
    import glob
    report_files = list(reports_dir.glob("browsing_discovery_*_comprehensive.json"))
    if not report_files:
        report_files = list(reports_dir.glob("browsing_discovery_*.json"))
    
    if not report_files:
        print(f"Error: No browsing reports found in {reports_dir}")
        print("Please run the browsing agent first to generate a report.")
        sys.exit(1)
    
    # Use the most recent report
    report_path = max(report_files, key=lambda p: p.stat().st_mtime)
    
    if not report_path.exists():
        print(f"Error: Browsing report not found. Expected: {report_path}")
        print("Please run the browsing agent first to generate a report.")
        sys.exit(1)
    
    print(f"Using browsing report: {report_path}")
    print("\nInitializing red team agent...")
    
    # Initialize red team agent
    agent = RedTeamAgent(
        browsing_report_path=str(report_path),
        enable_automated_scanning=True,  # Use nuclei, wapiti3, nikto if available
        enable_llm_testing=True,          # Use LLM agent with Anchor Browser
        enable_anchor_browser=True,        # Use Anchor Browser tools
        max_parallel_workers=10           # Parallel execution limit
    )
    
    # Run security testing
    print("\n" + "="*60)
    print("Running Security Testing on shayahal.com")
    print("="*60)
    print("\nThis may take several minutes...")
    print("Check the logs in data/runs/red_team_agent/ for detailed progress.\n")
    
    report = agent.test()
    
    # Print summary
    print("\n" + "="*60)
    print("Security Assessment Complete!")
    print("="*60)
    print(f"\nBase URL: {report.base_url}")
    print(f"Total Findings: {report.total_findings}")
    print(f"\nFindings by Severity:")
    for severity, count in report.findings_by_severity.items():
        print(f"  {severity}: {count}")
    
    print(f"\nFindings by Type:")
    for vuln_type, count in sorted(report.findings_by_type.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {vuln_type}: {count}")
    
    if report.vulnerabilities:
        print(f"\nTop Vulnerabilities:")
        for i, vuln in enumerate(report.vulnerabilities[:5], 1):
            print(f"\n{i}. {vuln.vulnerability_type} ({vuln.severity})")
            print(f"   URL: {vuln.affected_url}")
            print(f"   Description: {vuln.description[:100]}...")
    
    print(f"\n\nReport saved to: data/reports/{agent.run_id}.json")
    print(f"Logs saved to: data/runs/red_team_agent/{agent.run_id}/logs/")
    print("\n" + "="*60)
    
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure the package is installed: pip install -e .")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
