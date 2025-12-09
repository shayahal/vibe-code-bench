"""Test script to verify Anchor Browser integration."""

import sys
import os
from pathlib import Path

# Add src to path - scripts are in /scripts, so go up one level to repo root
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "src"))

def test_imports():
    """Test that all imports work correctly."""
    print("Testing imports...")
    
    try:
        from vibe_code_bench.browsing_agent.browser import BrowserWrapper
        print("✓ BrowserWrapper imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import BrowserWrapper: {e}")
        return False
    
    try:
        from vibe_code_bench.browsing_agent.agent import create_browsing_agent_tools
        print("✓ create_browsing_agent_tools imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import create_browsing_agent_tools: {e}")
        return False
    
    try:
        from vibe_code_bench.browsing_agent import BrowsingAgent
        print("✓ BrowsingAgent imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import BrowsingAgent: {e}")
        return False
    
    return True

def test_anchor_browser_availability():
    """Test if Anchor Browser tools are available."""
    print("\nTesting Anchor Browser availability...")
    
    try:
        from langchain_anchorbrowser import (
            AnchorContentTool,
            AnchorScreenshotTool,
            SimpleAnchorWebTaskTool,
        )
        print("✓ langchain-anchorbrowser package is installed")
        print("  - AnchorContentTool available")
        print("  - AnchorScreenshotTool available")
        print("  - SimpleAnchorWebTaskTool available")
        return True
    except ImportError as e:
        print(f"✗ langchain-anchorbrowser not installed: {e}")
        print("  Install with: pip install langchain-anchorbrowser")
        return False

def test_browser_wrapper_init():
    """Test BrowserWrapper initialization."""
    print("\nTesting BrowserWrapper initialization...")
    
    try:
        from vibe_code_bench.browsing_agent.browser import BrowserWrapper, ANCHOR_BROWSER_AVAILABLE
        
        if not ANCHOR_BROWSER_AVAILABLE:
            print("⚠ Anchor Browser tools not available (package not installed)")
            print("  BrowserWrapper will raise ImportError on initialization")
            return True  # This is expected behavior
        
        # Check for API key
        has_api_key = bool(os.environ.get("ANCHORBROWSER_API_KEY"))
        if not has_api_key:
            print("⚠ ANCHORBROWSER_API_KEY not set (will show warning)")
        
        # Try to initialize (will fail if package not installed)
        try:
            browser = BrowserWrapper(headless=True)
            print("✓ BrowserWrapper initialized successfully")
            if has_api_key:
                print("  - API key is set")
            else:
                print("  - API key not set (will need it for actual usage)")
            return True
        except ImportError as e:
            print(f"✗ BrowserWrapper initialization failed: {e}")
            return False
            
    except Exception as e:
        print(f"✗ Error testing BrowserWrapper: {e}")
        return False

def test_agent_tools():
    """Test agent tools creation."""
    print("\nTesting agent tools creation...")
    
    try:
        from vibe_code_bench.browsing_agent.browser import BrowserWrapper, ANCHOR_BROWSER_AVAILABLE
        from vibe_code_bench.browsing_agent.discovery import DiscoveryEngine
        from vibe_code_bench.browsing_agent.analyzer import PageAnalyzer
        from vibe_code_bench.browsing_agent.auth import AuthenticationHandler
        from vibe_code_bench.browsing_agent.agent import create_browsing_agent_tools
        
        if not ANCHOR_BROWSER_AVAILABLE:
            print("⚠ Anchor Browser tools not available - skipping agent tools test")
            return True
        
        # Initialize components
        browser = BrowserWrapper(headless=True)
        discovery = DiscoveryEngine(respect_robots=False)
        analyzer = PageAnalyzer()
        auth_handler = AuthenticationHandler()
        
        # Create tools
        tools = create_browsing_agent_tools(browser, discovery, analyzer, auth_handler)
        
        tool_names = [tool.name for tool in tools]
        print(f"✓ Created {len(tools)} tools:")
        for name in tool_names:
            print(f"  - {name}")
        
        # Check if Anchor Browser tools are included
        anchor_tools = [name for name in tool_names if 'anchor' in name.lower() or 'screenshot' in name.lower()]
        if anchor_tools:
            print(f"✓ Anchor Browser tools included: {', '.join(anchor_tools)}")
        else:
            print("⚠ No Anchor Browser tools found in tool list")
        
        return True
        
    except ImportError as e:
        print(f"⚠ Cannot test agent tools: {e}")
        return True  # Expected if package not installed
    except Exception as e:
        print(f"✗ Error testing agent tools: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("Anchor Browser Integration Test")
    print("=" * 60)
    
    results = []
    
    results.append(("Imports", test_imports()))
    results.append(("Anchor Browser Availability", test_anchor_browser_availability()))
    results.append(("BrowserWrapper", test_browser_wrapper_init()))
    results.append(("Agent Tools", test_agent_tools()))
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {name}")
    
    all_passed = all(result[1] for result in results)
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All tests passed!")
        print("\nNext steps:")
        print("1. Install langchain-anchorbrowser: pip install langchain-anchorbrowser")
        print("2. Set ANCHORBROWSER_API_KEY environment variable")
        print("3. Use BrowsingAgent as before - it now uses Anchor Browser tools!")
    else:
        print("✗ Some tests failed. Check the output above.")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
