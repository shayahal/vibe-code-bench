#!/usr/bin/env python3
"""Test script for the refactored Red Team Agent v2.

This script demonstrates the new simplified API:
- Single entry point: scan(url) or RedTeamAgent().scan(url)
- Langfuse tracing (if configured)
- Proper error handling (no silent failures)

Usage:
    python scripts/test_red_team_v2.py [URL]
    
    If no URL provided, defaults to testing a safe target.

Environment Variables:
    Required (one of):
        OPENAI_API_KEY
        ANTHROPIC_API_KEY
        OPENROUTER_API_KEY
    
    Optional:
        LANGFUSE_PUBLIC_KEY
        LANGFUSE_SECRET_KEY
"""

import sys
import os

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dotenv import load_dotenv
load_dotenv()


def main():
    """Run the red team agent test."""
    from vibe_code_bench.red_team_agent import scan, RedTeamAgent, ScanReport
    
    # Get URL from command line or use default
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = "https://example.com"  # Safe default for testing
    
    print("=" * 60)
    print("Red Team Agent v2 - Security Scanner")
    print("=" * 60)
    print(f"\nTarget URL: {url}")
    print()
    
    # Check for API keys
    has_openai = bool(os.getenv("OPENAI_API_KEY"))
    has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY"))
    has_openrouter = bool(os.getenv("OPENROUTER_API_KEY"))
    has_langfuse = bool(os.getenv("LANGFUSE_SECRET_KEY"))
    
    print("Configuration:")
    print(f"  OpenAI API Key: {'✓' if has_openai else '✗'}")
    print(f"  Anthropic API Key: {'✓' if has_anthropic else '✗'}")
    print(f"  OpenRouter API Key: {'✓' if has_openrouter else '✗'}")
    print(f"  Langfuse Tracing: {'✓' if has_langfuse else '✗'}")
    print()
    
    if not any([has_openai, has_anthropic, has_openrouter]):
        print("WARNING: No LLM API key found. Running in tool-only mode.")
        print("Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPENROUTER_API_KEY for LLM features.")
        print()
    
    # Method 1: Simple one-liner
    print("Running scan...")
    print("-" * 60)
    
    try:
        # Create agent for more control
        agent = RedTeamAgent()
        
        # Run scan
        report: ScanReport = agent.scan(url)
        
        # Print results
        print()
        print("=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"\nTarget: {report.target_url}")
        print(f"Scan ID: {report.scan_id}")
        print(f"Duration: {report.started_at} -> {report.completed_at}")
        print(f"\nTools Used: {', '.join(report.tools_used) or 'None'}")
        print(f"Tools Available: {', '.join(report.tools_available) or 'None'}")
        
        print(f"\n{'─' * 40}")
        print(f"TOTAL FINDINGS: {report.total_findings}")
        print(f"{'─' * 40}")
        
        if report.findings_by_severity:
            print("\nBy Severity:")
            for severity, count in sorted(report.findings_by_severity.items()):
                emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "⚪"}.get(severity, "")
                print(f"  {emoji} {severity}: {count}")
        
        if report.findings_by_type:
            print("\nBy Type:")
            for vuln_type, count in sorted(report.findings_by_type.items(), key=lambda x: -x[1]):
                print(f"  • {vuln_type}: {count}")
        
        if report.vulnerabilities:
            print(f"\n{'─' * 40}")
            print("TOP VULNERABILITIES")
            print(f"{'─' * 40}")
            
            # Sort by severity
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            sorted_vulns = sorted(
                report.vulnerabilities,
                key=lambda v: severity_order.get(v.severity, 5)
            )
            
            for i, vuln in enumerate(sorted_vulns[:10], 1):
                print(f"\n{i}. [{vuln.severity}] {vuln.vulnerability_type}")
                print(f"   URL: {vuln.url}")
                print(f"   {vuln.description[:100]}...")
                if vuln.remediation:
                    print(f"   Fix: {vuln.remediation[:80]}...")
        
        # Save report
        report_path = agent.save_report(report)
        print(f"\n{'─' * 40}")
        print(f"Report saved to: {report_path}")
        
        # Cleanup
        agent.cleanup()
        
        print("\n" + "=" * 60)
        print("Scan complete!")
        print("=" * 60)
        
        # Return exit code based on findings
        if report.get_critical_findings():
            return 2  # Critical findings
        elif report.get_high_findings():
            return 1  # High findings
        return 0
        
    except Exception as e:
        print(f"\nERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 3


if __name__ == "__main__":
    sys.exit(main())
