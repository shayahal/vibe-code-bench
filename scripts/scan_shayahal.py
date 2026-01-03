#!/usr/bin/env python
"""Scan shayahal.com for vulnerabilities."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vibe_code_bench.red_team_agent import scan, ScanConfig

def main():
    print("\n" + "="*70)
    print("Red Team Agent v3 - Scanning shayahal.com")
    print("="*70)

    # Use quick scan (5-10 minutes)
    config = ScanConfig.quick_scan("https://shayahal.com")

    print(f"\nConfiguration:")
    print(f"  Target: {config.target_url}")
    print(f"  Depth: {config.depth}")
    print(f"  Strategy: {config.strategy}")
    print(f"  Max URLs: {config.max_urls}")
    print(f"  SQLMap: level={config.sqlmap_level}, risk={config.sqlmap_risk}, timeout={config.sqlmap_timeout}s")
    print(f"  Estimated duration: {config.get_estimated_duration_minutes()} minutes")

    print(f"\n{'='*70}")
    print("Starting scan...")
    print("="*70)

    try:
        # Run scan
        report = scan("https://shayahal.com", config=config)

        print(f"\n{'='*70}")
        print("SCAN COMPLETED")
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
                print(f"    Description: {finding.description}")
                if finding.evidence:
                    print(f"    Evidence: {finding.evidence[:200]}...")
                if finding.remediation:
                    print(f"    Remediation: {finding.remediation[:200]}...")
        else:
            print(f"\n✓ No vulnerabilities found!")

        print(f"\n{'='*70}")
        print("Scan report saved to:")
        print(f"  {report.scan_id}")
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
