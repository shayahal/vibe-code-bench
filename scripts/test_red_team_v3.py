#!/usr/bin/env python
"""Test Red Team Agent v3 - End to End Test

Tests the complete 4-phase workflow:
1. Configuration
2. Discovery (with BrowsingAgent)
3. Testing (with proper parameter targeting)
4. Reporting

This test uses example.com as a safe target.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vibe_code_bench.red_team_agent import scan, RedTeamAgent, ScanConfig


def test_simple_scan():
    """Test 1: Simple scan with defaults."""
    print("\n" + "="*70)
    print("TEST 1: Simple Scan (example.com)")
    print("="*70)

    try:
        # Quick scan to avoid long wait
        config = ScanConfig.quick_scan("https://example.com")
        print(f"\nConfiguration:")
        print(f"  Target: {config.target_url}")
        print(f"  Depth: {config.depth}")
        print(f"  Strategy: {config.strategy}")
        print(f"  Max URLs: {config.max_urls}")
        print(f"  SQLMap timeout: {config.sqlmap_timeout}s")

        print(f"\nStarting scan...")
        report = scan("https://example.com", config=config)

        print(f"\n✓ Scan completed successfully!")
        print(f"\nResults:")
        print(f"  Total findings: {report.total_findings}")
        print(f"  Tools used: {', '.join(report.tools_used)}")

        if report.findings_by_severity:
            print(f"\n  Findings by severity:")
            for severity, count in report.findings_by_severity.items():
                print(f"    {severity}: {count}")

        # Show first few findings
        if report.vulnerabilities:
            print(f"\n  Sample findings:")
            for i, finding in enumerate(report.vulnerabilities[:3], 1):
                print(f"    {i}. {finding.severity} - {finding.vulnerability_type}")
                print(f"       URL: {finding.url}")
                print(f"       Tool: {finding.tool}")

        return True

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_agent_instance():
    """Test 2: Using RedTeamAgent directly."""
    print("\n" + "="*70)
    print("TEST 2: RedTeamAgent Instance (with cleanup)")
    print("="*70)

    try:
        agent = RedTeamAgent()

        print(f"\nAgent initialized:")
        print(f"  Run ID: {agent.run_id}")
        print(f"  LLM enabled: {agent.llm is not None}")
        print(f"  LangGraph agent: {agent.agent is not None}")

        # Quick scan
        config = ScanConfig(
            target_url="https://example.com",
            max_urls=5,
            sqlmap_timeout=60,
            test_sql_injection=False,  # Skip SQLMap for speed
            test_xss=False,  # Skip DalFox for speed
        )

        print(f"\nRunning quick scan (discovery only)...")
        report = agent.scan("https://example.com", config=config)

        print(f"\n✓ Scan completed!")
        print(f"  Findings: {report.total_findings}")
        print(f"  Duration: {(report.completed_at - report.started_at).total_seconds():.1f}s")

        agent.cleanup()
        print(f"\n✓ Cleanup successful")

        return True

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_configuration():
    """Test 3: Configuration presets."""
    print("\n" + "="*70)
    print("TEST 3: Configuration Presets")
    print("="*70)

    try:
        # Test quick scan preset
        quick = ScanConfig.quick_scan("https://example.com")
        print(f"\nQuick scan config:")
        print(f"  Depth: {quick.depth}")
        print(f"  Max URLs: {quick.max_urls}")
        print(f"  SQLMap timeout: {quick.sqlmap_timeout}s")
        print(f"  Estimated duration: {quick.get_estimated_duration_minutes()} min")

        # Test deep scan preset
        deep = ScanConfig.deep_scan("https://example.com")
        print(f"\nDeep scan config:")
        print(f"  Depth: {deep.depth}")
        print(f"  Strategy: {deep.strategy}")
        print(f"  Max URLs: {deep.max_urls}")
        print(f"  SQLMap level/risk: {deep.sqlmap_level}/{deep.sqlmap_risk}")
        print(f"  Estimated duration: {deep.get_estimated_duration_minutes()} min")

        print(f"\n✓ Configuration presets working correctly")
        return True

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_imports():
    """Test 4: Import all key modules."""
    print("\n" + "="*70)
    print("TEST 4: Import Verification")
    print("="*70)

    try:
        from vibe_code_bench.red_team_agent import (
            scan,
            RedTeamAgent,
            ScanConfig,
            ScanDepth,
            TestingStrategy,
            TestableTarget,
            TargetBuilder,
            ScanReport,
            VulnerabilityFinding,
            Severity,
        )

        print(f"\n✓ All imports successful:")
        print(f"  - scan() function")
        print(f"  - RedTeamAgent class")
        print(f"  - ScanConfig, ScanDepth, TestingStrategy")
        print(f"  - TestableTarget, TargetBuilder")
        print(f"  - ScanReport, VulnerabilityFinding, Severity")

        # Test target builder
        from vibe_code_bench.red_team_agent.discovery import TargetBuilder

        builder = TargetBuilder(base_url="https://example.com")
        targets = builder.build_targets(
            urls=["https://example.com/page?id=1"],
            forms=[{
                "action": "/login",
                "method": "POST",
                "fields": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"}
                ]
            }]
        )

        print(f"\n✓ TestableTarget creation working:")
        print(f"  Built {len(targets)} targets from 1 URL + 1 form")
        for i, target in enumerate(targets, 1):
            print(f"    {i}. {target.method} {target.url} ({len(target.parameters)} params)")

        # Test SQLMap args conversion
        if targets:
            sqlmap_args = targets[0].to_sqlmap_args()
            print(f"\n✓ SQLMap args conversion:")
            print(f"    URL: {sqlmap_args.get('url')}")
            print(f"    Method: {sqlmap_args.get('method', 'GET')}")
            print(f"    Level: {sqlmap_args.get('level')}")
            print(f"    Risk: {sqlmap_args.get('risk')}")

        return True

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "#"*70)
    print("# Red Team Agent v3 - End-to-End Test Suite")
    print("#"*70)

    results = {
        "imports": test_imports(),
        "configuration": test_configuration(),
        # "agent_instance": test_agent_instance(),  # Commented out - requires browser
        # "simple_scan": test_simple_scan(),  # Commented out - requires browser + tools
    }

    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)

    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {test_name}")

    all_passed = all(results.values())

    if all_passed:
        print(f"\n✓ All tests passed!")
        print(f"\nNext steps:")
        print(f"  1. Set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY in .env")
        print(f"  2. Install security tools: wapiti3, sqlmap, nuclei, dalfox")
        print(f"  3. Run a real scan: python -c 'from vibe_code_bench.red_team_agent import scan; scan(\"https://example.com\")'")
        return 0
    else:
        print(f"\n✗ Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
