#!/usr/bin/env python
"""Setup Validation Script - Checks Red Team Agent v3 readiness.

This script validates:
1. Core imports and models
2. Security tool availability
3. API key configuration
4. Langfuse setup
5. TestableTarget functionality
"""

import sys
import os
from pathlib import Path
import subprocess

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def check_imports():
    """Validate all core imports work."""
    print("\n" + "="*70)
    print("VALIDATION 1: Core Imports")
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

        print("\n✓ All core imports successful")
        print("  - scan() function")
        print("  - RedTeamAgent class")
        print("  - ScanConfig, ScanDepth, TestingStrategy")
        print("  - TestableTarget, TargetBuilder")
        print("  - ScanReport, VulnerabilityFinding, Severity")
        return True

    except ImportError as e:
        print(f"\n✗ Import failed: {e}")
        return False


def check_security_tools():
    """Check which security tools are installed."""
    print("\n" + "="*70)
    print("VALIDATION 2: Security Tools")
    print("="*70)

    tools = {
        "sqlmap": "SQL injection testing",
        "wapiti": "Web vulnerability scanner",
        "nikto": "Web server scanner",
        "nuclei": "Template-based scanner",
        "dalfox": "XSS scanner",
    }

    installed = []
    missing = []

    for tool, description in tools.items():
        result = subprocess.run(
            ["which", tool],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            path = result.stdout.strip()
            installed.append(tool)
            print(f"\n✓ {tool:12} - {description}")
            print(f"  Path: {path}")
        else:
            missing.append(tool)
            print(f"\n✗ {tool:12} - {description}")
            print(f"  Status: NOT INSTALLED")

    print(f"\nSummary: {len(installed)}/{len(tools)} tools installed")

    if missing:
        print(f"\nMissing tools:")
        for tool in missing:
            if tool == "nuclei":
                print(f"  - {tool}: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            elif tool == "dalfox":
                print(f"  - {tool}: go install github.com/hahwul/dalfox/v2@latest")

    return len(installed) >= 1  # At least one tool needed


def check_api_keys():
    """Check API key configuration."""
    print("\n" + "="*70)
    print("VALIDATION 3: API Keys")
    print("="*70)

    llm_keys = {
        "OPENAI_API_KEY": "OpenAI (GPT-4)",
        "ANTHROPIC_API_KEY": "Anthropic (Claude)",
        "OPENROUTER_API_KEY": "OpenRouter",
    }

    observability_keys = {
        "LANGFUSE_PUBLIC_KEY": "Langfuse tracing",
        "LANGFUSE_SECRET_KEY": "Langfuse tracing",
    }

    # Check LLM keys
    print("\nLLM Keys (at least one required for intelligent orchestration):")
    llm_configured = False
    for key, description in llm_keys.items():
        value = os.getenv(key)
        if value:
            masked = value[:8] + "..." if len(value) > 8 else "***"
            print(f"  ✓ {key:25} - {description:20} ({masked})")
            llm_configured = True
        else:
            print(f"  ✗ {key:25} - {description:20} (NOT SET)")

    # Check observability keys
    print("\nObservability Keys (optional but recommended):")
    observability_configured = True
    for key, description in observability_keys.items():
        value = os.getenv(key)
        if value:
            masked = value[:8] + "..." if len(value) > 8 else "***"
            print(f"  ✓ {key:25} - {description:20} ({masked})")
        else:
            print(f"  ✗ {key:25} - {description:20} (NOT SET)")
            observability_configured = False

    if not llm_configured:
        print("\n⚠ WARNING: No LLM API keys configured")
        print("  Agent will fall back to sequential mode (less intelligent)")
        print("  Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPENROUTER_API_KEY")

    if not observability_configured:
        print("\n⚠ WARNING: Langfuse not configured")
        print("  Tracing disabled, but logging still works")
        print("  Set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY for full observability")

    return True  # Not blocking, just informational


def check_langfuse():
    """Check Langfuse installation."""
    print("\n" + "="*70)
    print("VALIDATION 4: Langfuse Installation")
    print("="*70)

    try:
        from langfuse import Langfuse
        from langfuse.callback import CallbackHandler
        print("\n✓ Langfuse installed")
        print("  - Langfuse client available")
        print("  - CallbackHandler available")
        return True
    except ImportError:
        print("\n✗ Langfuse not installed")
        print("  Install with: pip install langfuse")
        return False


def test_testable_target():
    """Test TestableTarget functionality."""
    print("\n" + "="*70)
    print("VALIDATION 5: TestableTarget Functionality")
    print("="*70)

    try:
        from vibe_code_bench.red_team_agent.discovery import TestableTarget, TargetBuilder

        # Test 1: Form conversion
        print("\nTest 1: Form → TestableTarget")
        form = {
            "action": "/login",
            "method": "POST",
            "fields": [
                {"name": "username", "type": "text"},
                {"name": "password", "type": "password"}
            ]
        }

        builder = TargetBuilder(base_url="https://example.com")
        targets = builder.build_targets(urls=[], forms=[form])

        if len(targets) == 1:
            target = targets[0]
            print(f"  ✓ Created TestableTarget:")
            print(f"    URL: {target.url}")
            print(f"    Method: {target.method}")
            print(f"    Parameters: {target.parameters}")
        else:
            print(f"  ✗ Expected 1 target, got {len(targets)}")
            return False

        # Test 2: SQLMap args conversion
        print("\nTest 2: TestableTarget → SQLMap args")
        sqlmap_args = target.to_sqlmap_args()

        print(f"  ✓ SQLMap arguments generated:")
        print(f"    URL: {sqlmap_args.get('url')}")
        print(f"    Method: {sqlmap_args.get('method', 'GET')}")
        print(f"    Data: {sqlmap_args.get('data', 'N/A')}")
        print(f"    Level: {sqlmap_args.get('level')}")
        print(f"    Risk: {sqlmap_args.get('risk')}")

        if sqlmap_args.get('level') == 5 and sqlmap_args.get('risk') == 3:
            print(f"  ✓ Correct aggressive settings (level 5, risk 3)")
        else:
            print(f"  ✗ Incorrect settings (expected level 5, risk 3)")
            return False

        # Test 3: URL with parameters
        print("\nTest 3: URL with params → TestableTarget")
        urls_with_params = ["https://example.com/search?q=test&category=all"]
        targets = builder.build_targets(urls=urls_with_params, forms=[])

        if len(targets) == 1:
            target = targets[0]
            print(f"  ✓ Created TestableTarget from URL:")
            print(f"    URL: {target.url}")
            print(f"    Parameters: {target.parameters}")
        else:
            print(f"  ✗ Expected 1 target, got {len(targets)}")
            return False

        print("\n✓ All TestableTarget tests passed")
        return True

    except Exception as e:
        print(f"\n✗ TestableTarget test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_scan_config():
    """Test ScanConfig presets."""
    print("\n" + "="*70)
    print("VALIDATION 6: ScanConfig Presets")
    print("="*70)

    try:
        from vibe_code_bench.red_team_agent import ScanConfig, ScanDepth, TestingStrategy

        # Test quick scan
        quick = ScanConfig.quick_scan("https://example.com")
        print("\n✓ Quick scan preset:")
        print(f"  Depth: {quick.depth}")
        print(f"  Max URLs: {quick.max_urls}")
        print(f"  SQLMap timeout: {quick.sqlmap_timeout}s")
        print(f"  SQLMap level: {quick.sqlmap_level}")
        print(f"  SQLMap risk: {quick.sqlmap_risk}")
        print(f"  Estimated duration: {quick.get_estimated_duration_minutes()} min")

        # Test deep scan
        deep = ScanConfig.deep_scan("https://example.com")
        print("\n✓ Deep scan preset:")
        print(f"  Depth: {deep.depth}")
        print(f"  Strategy: {deep.strategy}")
        print(f"  Max URLs: {deep.max_urls}")
        print(f"  SQLMap level: {deep.sqlmap_level}")
        print(f"  SQLMap risk: {deep.sqlmap_risk}")
        print(f"  Estimated duration: {deep.get_estimated_duration_minutes()} min")

        # Validate settings
        if deep.sqlmap_level == 5 and deep.sqlmap_risk == 3:
            print("\n✓ Deep scan has aggressive SQLMap settings")
        else:
            print(f"\n✗ Deep scan has incorrect settings (expected level=5, risk=3)")
            return False

        return True

    except Exception as e:
        print(f"\n✗ ScanConfig test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all validation checks."""
    print("\n" + "#"*70)
    print("# Red Team Agent v3 - Setup Validation")
    print("#"*70)

    results = {
        "imports": check_imports(),
        "security_tools": check_security_tools(),
        "api_keys": check_api_keys(),
        "langfuse": check_langfuse(),
        "testable_target": test_testable_target(),
        "scan_config": test_scan_config(),
    }

    # Summary
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)

    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {test_name}")

    all_passed = all(results.values())

    # Next steps
    print("\n" + "="*70)
    print("NEXT STEPS")
    print("="*70)

    if all_passed:
        print("\n✓ All critical validations passed!")
        print("\nReady for testing:")
        print("  1. Set API keys in .env (copy from .env.example)")
        print("  2. Install missing security tools (nuclei, dalfox)")
        print("  3. Run test scan:")
        print("     python -c \"from vibe_code_bench.red_team_agent import scan; scan('https://example.com')\"")
    else:
        print("\n⚠ Some validations failed")
        print("\nFix the issues above, then re-run this script")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
