#!/usr/bin/env python3
"""Test that the package can be imported after installation."""

def test_imports():
    """Test all critical imports."""
    print("Testing imports...")
    
    try:
        from vibe_code_bench.core.llm_setup import initialize_llm
        print("✓ core.llm_setup")
    except Exception as e:
        print(f"✗ core.llm_setup: {e}")
        return False
    
    try:
        from vibe_code_bench.red_team_agent.agent_common import initialize_langfuse
        print("✓ red_team_agent.agent_common")
    except Exception as e:
        print(f"✗ red_team_agent.agent_common: {e}")
        return False
    
    try:
        from vibe_code_bench.orchestrator.state import OrchestratorState
        print("✓ orchestrator.state")
    except Exception as e:
        print(f"✗ orchestrator.state: {e}")
        return False
    
    try:
        from vibe_code_bench.website_generator.prompts import SYSTEM_PROMPT
        print("✓ website_generator.prompts")
    except Exception as e:
        print(f"✗ website_generator.prompts: {e}")
        return False
    
    try:
        from vibe_code_bench.red_team_agent.tools import get_all_tools
        tools = get_all_tools()
        print(f"✓ red_team_agent.tools ({len(tools)} tools)")
    except Exception as e:
        print(f"✗ red_team_agent.tools: {e}")
        return False
    
    print("\n✓ All imports successful!")
    return True

if __name__ == "__main__":
    import sys
    success = test_imports()
    sys.exit(0 if success else 1)

