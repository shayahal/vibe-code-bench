"""Test script to browse a website."""

import logging
import sys

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

try:
    from vibe_code_bench.browsing_agent import BrowsingAgent
    
    # Initialize agent
    print("Initializing browsing agent...")
    agent = BrowsingAgent(
        max_pages=50,
        respect_robots=True,
        enable_javascript=True,
        headless=True
    )
    
    # Discover pages
    print(f"\nDiscovering pages on https://shayahal.com...")
    result = agent.discover("https://shayahal.com")
    
    # Print results
    print(f"\n{'='*60}")
    print(f"Discovery Complete!")
    print(f"{'='*60}")
    print(f"Base URL: {result.base_url}")
    print(f"Total Pages Discovered: {result.total_pages}")
    print(f"Authentication Required: {result.authentication_required}")
    print(f"Sitemap Used: {result.sitemap_used}")
    print(f"Robots Respected: {result.robots_respected}")
    print(f"\nDiscovered Pages:")
    print(f"{'-'*60}")
    
    for i, page in enumerate(result.pages[:20], 1):  # Show first 20
        print(f"{i}. {page.url}")
        if page.title:
            print(f"   Title: {page.title}")
        if page.status_code:
            print(f"   Status: {page.status_code}")
        if page.discovered_via:
            print(f"   Discovered via: {page.discovered_via}")
        if page.links:
            print(f"   Links found: {len(page.links)}")
        print()
    
    if len(result.pages) > 20:
        print(f"... and {len(result.pages) - 20} more pages")
    
    # Save results
    output_path = agent.save_results(result)
    print(f"\nResults saved to: {output_path}")
    
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure the package is installed: pip install -e .")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
