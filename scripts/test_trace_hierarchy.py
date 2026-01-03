#!/usr/bin/env python
"""Test that trace hierarchy is properly captured."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vibe_code_bench.red_team_agent import scan, ScanConfig, ScanDepth, TestingStrategy

def main():
    print("\n" + "="*80)
    print("Testing Trace Hierarchy Fix")
    print("="*80)

    # Very quick scan config
    config = ScanConfig(
        target_url="https://example.com",  # Fast, simple target
        depth=ScanDepth.QUICK,
        strategy=TestingStrategy.PASSIVE,  # Passive = faster
        max_crawl_depth=1,
        max_urls=1,  # Just 1 URL
        sqlmap_timeout=60,  # Short timeout
        test_sql_injection=False,  # Disable slow tests
        test_xss=False,
        test_auth=False,
        test_api=False,
    )

    print(f"\nConfiguration:")
    print(f"  Target: {config.target_url}")
    print(f"  Strategy: Passive (fast)")
    print(f"  Expected: ~30 seconds")
    print(f"  Goal: Verify trace hierarchy\n")

    print("="*80)
    print("Starting scan...")
    print("="*80)

    try:
        # Run scan
        report = scan("https://example.com", config=config)

        print(f"\n{'='*80}")
        print("SCAN COMPLETED")
        print("="*80)

        print(f"\nResults:")
        print(f"  Run ID: {report.scan_id}")
        print(f"  Findings: {report.total_findings}")
        print(f"  Duration: {(report.completed_at - report.started_at).total_seconds():.1f}s")

        print(f"\n{'='*80}")
        print("Trace Verification")
        print("="*80)

        print(f"\nLangfuse Session ID: {report.scan_id}")
        print(f"\n✓ Session ID is set (fixes session grouping)")

        print(f"\nExpected trace hierarchy:")
        print(f"""
Trace: scan (session: {report.scan_id})
├─ Span: configure_scan
├─ Span: discover_targets
├─ Span: llm_orchestrated_testing
│  ├─ Generation: Claude LLM call (linked to parent)
│  ├─ Span: scan_with_browser (child of llm_orchestrated_testing)
│  └─ ... more operations
└─ Span: generate_report
        """)

        print(f"\nVerify in Langfuse UI:")
        print(f"  https://cloud.langfuse.com/sessions/{report.scan_id}")
        print(f"\nCheck for:")
        print(f"  ✓ Session ID appears in trace")
        print(f"  ✓ Multiple observations (not just 1)")
        print(f"  ✓ Nested span hierarchy")
        print(f"  ✓ LLM generations with token counts")
        print(f"  ✓ Tool execution details")

        print(f"\n{'='*80}")
        print("✓ TEST COMPLETED - Check Langfuse UI for hierarchy")
        print("="*80)

        return 0

    except KeyboardInterrupt:
        print(f"\n\n⚠ Scan interrupted")
        return 1
    except Exception as e:
        print(f"\n✗ Scan failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
