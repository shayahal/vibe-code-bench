"""Test script to run browsing and red team agents on pizza-pal-reservations.lovable.app."""

import logging
import sys
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

try:
    from vibe_code_bench.browsing_agent import BrowsingAgent
    from vibe_code_bench.red_team_agent import RedTeamAgent
    from vibe_code_bench.core.combined_report import generate_combined_report
    from vibe_code_bench.core.paths import get_reports_dir
    from datetime import datetime
    
    target_url = "https://v0-blog-with-hidden-vulnerability-bsjmjq27s-shayahals-projects.vercel.app/"
    
    # Step 1: Run browsing agent
    print("="*60)
    print("STEP 1: Running Browsing Agent")
    print("="*60)
    print(f"Target: {target_url}\n")
    
    # Run browsing agent with LLM
    agent = BrowsingAgent(
        max_pages=30,
        respect_robots=False,
        enable_javascript=True,
        headless=True
    )
    
    print("Discovering pages...")
    result = agent.discover(target_url)
    
    print(f"\nDiscovery Complete!")
    print(f"Base URL: {result.base_url}")
    print(f"Total Pages Discovered: {result.total_pages}")
    print(f"Authentication Required: {result.authentication_required}")
    print(f"Sitemap Used: {result.sitemap_used}")
    
    # Save results with run_id
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"browsing_{timestamp}"
    report_paths = agent.save_results(result, save_summary=True, run_id=run_id)
    
    print(f"\nReports saved:")
    print(f"  - Comprehensive JSON: {report_paths['comprehensive']}")
    if 'summary' in report_paths:
        print(f"  - Summary JSON: {report_paths['summary']}")
    if 'markdown' in report_paths:
        print(f"  - Markdown Report: {report_paths['markdown']}")
    if 'detailed' in report_paths:
        print(f"  - Detailed Report: {report_paths['detailed']}")
    
    # Find the comprehensive JSON report for red team agent
    browsing_report_path = report_paths['comprehensive']
    
    # Step 2: Run red team agent
    print("\n" + "="*60)
    print("STEP 2: Running Red Team Agent")
    print("="*60)
    print(f"Using browsing report: {browsing_report_path}\n")
    
    red_team_agent = RedTeamAgent(
        browsing_report_path=browsing_report_path,
        enable_automated_scanning=True,
        enable_llm_testing=True,
        enable_anchor_browser=True,
        max_parallel_workers=10
    )
    
    print("Running security tests...")
    print("This may take several minutes...\n")
    
    red_team_report = red_team_agent.test()
    
    print(f"\nRed Team Testing Complete!")
    print(f"Total Findings: {red_team_report.total_findings}")
    print(f"Findings by Severity: {red_team_report.findings_by_severity}")
    
    # The red team agent already saves reports, but let's verify
    # Reports are now in day-based folders with run folders
    from vibe_code_bench.core.paths import get_reports_dir_for_date
    from datetime import datetime
    date_str = datetime.now().strftime("%Y-%m-%d")
    reports_dir = get_reports_dir_for_date(date_str)
    run_folder = reports_dir / red_team_agent.run_id
    red_team_json_files = list(run_folder.glob(f"{red_team_agent.run_id}.json")) if run_folder.exists() else []
    red_team_md_files = list(run_folder.glob(f"{red_team_agent.run_id}.md")) if run_folder.exists() else []
    
    print(f"\nRed Team Reports:")
    if red_team_json_files:
        print(f"  - JSON Report: {red_team_json_files[0]}")
    if red_team_md_files:
        print(f"  - Markdown Report: {red_team_md_files[0]}")
    
    # Step 3: Generate combined report
    print("\n" + "="*60)
    print("STEP 3: Generating Combined Report")
    print("="*60)
    
    combined_run_id = f"combined_{timestamp}"
    red_team_report_path = str(red_team_json_files[0]) if red_team_json_files else None
    try:
        combined_report_path = generate_combined_report(
            browsing_report_path=browsing_report_path,
            red_team_report_path=red_team_report_path,
            run_id=combined_run_id,
            browsing_tools_used=["browser_crawl", "javascript_rendering"]
        )
        print(f"Combined report saved to: {combined_report_path}")
    except Exception as e:
        print(f"Warning: Failed to generate combined report: {e}")
        combined_report_path = None
    
    # Summary
    print("\n" + "="*60)
    print("TEST COMPLETE - All Reports Generated")
    print("="*60)
    print(f"\nBrowsing Reports:")
    print(f"  - Concise: {report_paths.get('markdown', 'N/A')}")
    if 'detailed' in report_paths:
        print(f"  - Detailed: {report_paths['detailed']}")
    print(f"\nRed Team Reports:")
    if red_team_md_files:
        print(f"  - Concise: {red_team_md_files[0]}")
        # Check for detailed report
        detailed_red_team = list(reports_dir.glob(f"2025-12-*/{red_team_agent.run_id}/{red_team_agent.run_id}_detailed.md"))
        if detailed_red_team:
            print(f"  - Detailed: {detailed_red_team[0]}")
    if combined_report_path:
        print(f"\nCombined Report: {combined_report_path}")
    
    # Check for error logs
    print(f"\nError Logs:")
    error_logs = list(reports_dir.glob(f"2025-12-*/{run_id}/errors.log"))
    if error_logs:
        print(f"  - Browsing errors: {error_logs[0]}")
    if red_team_json_files:
        red_team_error_logs = list(reports_dir.glob(f"2025-12-*/{red_team_agent.run_id}/errors.log"))
        if red_team_error_logs:
            print(f"  - Red team errors: {red_team_error_logs[0]}")
    
    print(f"\nAll reports saved to: {reports_dir}")
    
except ImportError as e:
    print(f"Import error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
