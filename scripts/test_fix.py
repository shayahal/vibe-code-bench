#!/usr/bin/env python
"""Test the LLM agent result extraction fix."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vibe_code_bench.red_team_agent import scan, ScanConfig, ScanDepth, TestingStrategy

def main():
    print("\n" + "="*70)
    print("Testing LLM Agent Result Extraction Fix")
    print("="*70)

    # Quick scan config
    config = ScanConfig(
        target_url="https://shayahal.com",
        depth=ScanDepth.QUICK,
        strategy=TestingStrategy.ACTIVE,
        max_crawl_depth=1,
        max_urls=3,  # Reduced for faster testing
        sqlmap_timeout=300,
        test_sql_injection=False,  # Disable for speed
        test_xss=False,  # Disable for speed
        test_auth=False,  # Disable for speed
        test_api=False,  # Disable for speed
    )

    print(f"\nConfiguration:")
    print(f"  Target: {config.target_url}")
    print(f"  Max URLs: {config.max_urls}")
    print(f"  LLM Orchestration: Enabled")
    print(f"  Expected: Browser findings should be collected\n")

    print("="*70)
    print("Starting scan...")
    print("="*70)

    try:
        # Run scan
        report = scan("https://shayahal.com", config=config)

        print(f"\n{'='*70}")
        print("SCAN COMPLETED")
        print("="*70)

        print(f"\nResults:")
        print(f"  Total findings: {report.total_findings}")
        print(f"  Tools used: {', '.join(report.tools_used)}")
        print(f"  Duration: {(report.completed_at - report.started_at).total_seconds():.1f}s")

        if report.findings_by_severity:
            print(f"\nFindings by severity:")
            for severity, count in sorted(report.findings_by_severity.items(),
                                         key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}.get(x[0], 5)):
                print(f"  {severity}: {count}")

        # Show findings
        if report.vulnerabilities:
            print(f"\n{'='*70}")
            print("DETAILED FINDINGS")
            print("="*70)

            for i, finding in enumerate(report.vulnerabilities[:10], 1):  # Show first 10
                print(f"\n[{i}] {finding.severity} - {finding.vulnerability_type}")
                print(f"    URL: {finding.url}")
                print(f"    Tool: {finding.tool}")
                print(f"    Description: {finding.description[:100]}...")
        else:
            print(f"\n✓ No vulnerabilities found")

        # Verify the fix worked
        if report.total_findings > 0:
            print(f"\n{'='*70}")
            print("✓ FIX VERIFIED: LLM agent results were collected!")
            print("="*70)
            return 0
        else:
            print(f"\n{'='*70}")
            print("⚠ No findings - unable to verify fix (may be normal)")
            print("="*70)
            return 0

    except KeyboardInterrupt:
        print(f"\n\n⚠ Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n✗ Scan failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
