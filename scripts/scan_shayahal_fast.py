#!/usr/bin/env python
"""Fast scan of shayahal.com - Skip Nuclei, use only Wapiti + Nikto."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vibe_code_bench.red_team_agent import scan, ScanConfig, ScanDepth, TestingStrategy

def main():
    print("\n" + "="*70)
    print("Red Team Agent v3 - Fast Scan of shayahal.com")
    print("(Skipping Nuclei to avoid timeout)")
    print("="*70)

    # Custom config without Nuclei
    config = ScanConfig(
        target_url="https://shayahal.com",
        depth=ScanDepth.QUICK,
        strategy=TestingStrategy.ACTIVE,
        max_crawl_depth=1,
        max_urls=5,
        sqlmap_timeout=300,
        sqlmap_level=5,
        sqlmap_risk=3,
        test_sql_injection=True,
        test_xss=True,
        test_auth=True,
        test_api=True,
    )

    print(f"\nConfiguration:")
    print(f"  Target: {config.target_url}")
    print(f"  Tools: Wapiti, Nikto (Nuclei disabled)")
    print(f"  SQLMap: level={config.sqlmap_level}, risk={config.sqlmap_risk}")
    print(f"  Estimated: 3-5 minutes")

    print(f"\n{'='*70}")
    print("Starting scan...")
    print("="*70)

    try:
        # Run scan
        report = scan("https://shayahal.com", config=config)

        print(f"\n{'='*70}")
        print("SCAN COMPLETED SUCCESSFULLY")
        print("="*70)

        print(f"\nSummary:")
        print(f"  Total findings: {report.total_findings}")
        print(f"  Tools used: {', '.join(report.tools_used)}")
        print(f"  Duration: {(report.completed_at - report.started_at).total_seconds():.1f}s")

        if report.findings_by_severity:
            print(f"\nFindings by severity:")
            for severity, count in sorted(report.findings_by_severity.items(),
                                         key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}.get(x[0], 5)):
                print(f"  {severity}: {count}")

        # Show all findings
        if report.vulnerabilities:
            print(f"\n{'='*70}")
            print("DETAILED FINDINGS")
            print("="*70)

            for i, finding in enumerate(report.vulnerabilities, 1):
                print(f"\n[{i}] {finding.severity} - {finding.vulnerability_type}")
                print(f"    URL: {finding.url}")
                if finding.parameter:
                    print(f"    Parameter: {finding.parameter}")
                print(f"    Tool: {finding.tool}")
                print(f"    Description: {finding.description[:150]}...")
                if finding.remediation:
                    print(f"    Fix: {finding.remediation[:150]}...")
        else:
            print(f"\n✓ No critical vulnerabilities found!")
            print(f"  (This is good - your site appears secure)")

        print(f"\n{'='*70}")
        print("Report saved to:")
        print(f"  Run ID: {report.scan_id}")
        print(f"  Langfuse: https://cloud.langfuse.com")
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
