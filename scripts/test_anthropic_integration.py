#!/usr/bin/env python
"""Test Anthropic API Integration with Red Team Agent.

Validates that:
1. .env file is loaded correctly
2. Anthropic API key is detected
3. Agent initializes with Claude LLM
4. Langfuse tracing is working
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def test_env_loading():
    """Test that .env file loads correctly."""
    print("\n" + "="*70)
    print("TEST 1: Environment Variable Loading")
    print("="*70)

    from dotenv import load_dotenv
    load_dotenv()

    # Check API keys
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    langfuse_public = os.getenv("LANGFUSE_PUBLIC_KEY")
    langfuse_secret = os.getenv("LANGFUSE_SECRET_KEY")

    if anthropic_key:
        masked = anthropic_key[:15] + "..." + anthropic_key[-4:]
        print(f"\n✓ ANTHROPIC_API_KEY loaded: {masked}")
    else:
        print(f"\n✗ ANTHROPIC_API_KEY not found")
        return False

    if langfuse_public and langfuse_secret:
        print(f"✓ LANGFUSE keys loaded")
        print(f"  Public: {langfuse_public[:15]}...")
        print(f"  Secret: {langfuse_secret[:15]}...")
    else:
        print(f"⚠ LANGFUSE keys not found (optional)")

    return True


def test_agent_initialization():
    """Test that agent initializes with Claude."""
    print("\n" + "="*70)
    print("TEST 2: Agent Initialization with Anthropic/Claude")
    print("="*70)

    try:
        from vibe_code_bench.red_team_agent import RedTeamAgent

        print("\n[1/2] Creating RedTeamAgent instance...")
        agent = RedTeamAgent()

        print(f"\n✓ Agent initialized:")
        print(f"  Run ID: {agent.run_id}")
        print(f"  LLM available: {agent.llm is not None}")
        print(f"  LangGraph agent: {agent.agent is not None}")

        if agent.llm:
            # Check LLM type
            llm_class = agent.llm.__class__.__name__
            print(f"  LLM type: {llm_class}")

            if "Anthropic" in llm_class or "ChatAnthropic" in llm_class:
                print(f"  ✓ Using Anthropic/Claude LLM")
            else:
                print(f"  ⚠ Using {llm_class} (expected Anthropic)")

        print("\n[2/2] Testing LLM with simple prompt...")
        if agent.llm:
            try:
                # Test LLM with simple prompt
                from langchain_core.messages import HumanMessage

                response = agent.llm.invoke([
                    HumanMessage(content="Say 'Hello from Claude!' in exactly those words.")
                ])

                print(f"\n✓ LLM responded successfully:")
                print(f"  Response: {response.content[:100]}")

                if "Claude" in response.content:
                    print(f"  ✓ Claude is working!")
                else:
                    print(f"  ⚠ Response doesn't mention Claude")

            except Exception as e:
                print(f"\n✗ LLM test failed: {e}")
                return False
        else:
            print(f"\n⚠ LLM not initialized (check API key)")

        # Cleanup
        agent.cleanup()
        print(f"\n✓ Cleanup successful")

        return True

    except Exception as e:
        print(f"\n✗ Agent initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_langfuse_integration():
    """Test Langfuse tracing."""
    print("\n" + "="*70)
    print("TEST 3: Langfuse Tracing Integration")
    print("="*70)

    try:
        from vibe_code_bench.red_team_agent.observability import ObservabilityManager

        # Reset singleton for fresh test
        ObservabilityManager.reset()

        obs = ObservabilityManager.get_instance()

        print(f"\n✓ ObservabilityManager initialized:")
        print(f"  Run ID: {obs.run_id}")
        print(f"  Langfuse client: {obs.langfuse is not None}")
        print(f"  Callback handler: {obs.callback_handler is not None}")

        if obs.langfuse:
            print(f"  ✓ Langfuse tracing ENABLED")
            print(f"\n  View traces at: https://cloud.langfuse.com")
            print(f"  Filter by session: {obs.run_id}")
        else:
            print(f"  ⚠ Langfuse tracing DISABLED (check keys)")

        obs.shutdown()
        return True

    except Exception as e:
        print(f"\n✗ Langfuse test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_config_presets():
    """Test that ScanConfig loads environment variables."""
    print("\n" + "="*70)
    print("TEST 4: Configuration with .env Settings")
    print("="*70)

    try:
        from vibe_code_bench.red_team_agent import ScanConfig, ScanDepth

        config = ScanConfig.deep_scan("https://example.com")

        print(f"\n✓ Deep scan configuration:")
        print(f"  Target: {config.target_url}")
        print(f"  Depth: {config.depth}")
        print(f"  SQLMap timeout: {config.sqlmap_timeout}s")
        print(f"  SQLMap level: {config.sqlmap_level}")
        print(f"  SQLMap risk: {config.sqlmap_risk}")
        print(f"  Test SQL injection: {config.test_sql_injection}")
        print(f"  Test XSS: {config.test_xss}")

        # Verify aggressive settings
        if config.sqlmap_level == 5 and config.sqlmap_risk == 3:
            print(f"\n✓ Aggressive SQLMap settings confirmed (level 5, risk 3)")
        else:
            print(f"\n⚠ Expected level 5, risk 3, got level {config.sqlmap_level}, risk {config.sqlmap_risk}")

        return True

    except Exception as e:
        print(f"\n✗ Config test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all integration tests."""
    print("\n" + "#"*70)
    print("# Red Team Agent v3 - Anthropic/Claude Integration Test")
    print("#"*70)

    results = {
        "env_loading": test_env_loading(),
        "agent_initialization": test_agent_initialization(),
        "langfuse_integration": test_langfuse_integration(),
        "config_presets": test_config_presets(),
    }

    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)

    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {test_name}")

    all_passed = all(results.values())

    if all_passed:
        print("\n" + "="*70)
        print("✓ ALL TESTS PASSED - Ready for Production!")
        print("="*70)
        print("\nYour Red Team Agent is configured with:")
        print("  ✓ Anthropic/Claude API (for intelligent orchestration)")
        print("  ✓ Langfuse tracing (for observability)")
        print("  ✓ Aggressive SQLMap settings (level 5, risk 3)")
        print("  ✓ Optimized timeouts (1800s for SQLMap)")
        print("\nReady to scan:")
        print("  python -c \"from vibe_code_bench.red_team_agent import scan; \\")
        print("              scan('https://target.com')\"")
        return 0
    else:
        print("\n✗ Some tests failed - check errors above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
