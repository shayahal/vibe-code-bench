"""
Example usage of the Web Security Red-Teaming Agent.

This script demonstrates how to use the agent for web security testing.
"""

from red_team_agent import RedTeamAgent
import os


def example_basic_web_test():
    """Basic web security testing example."""
    print("=" * 60)
    print("Example 1: Basic Web Security Test")
    print("=" * 60)
    
    # Initialize agent with target URL
    agent = RedTeamAgent(
        target_url="https://example.com",
        model_name="gpt-4"
    )
    
    # Run comprehensive test suite
    print("\nRunning comprehensive web security test suite...")
    report = agent.run_test_suite()
    
    print(f"\nReport generated: {len(report)} characters")
    print("\nFirst 500 characters of report:")
    print(report[:500])


def example_single_url_test():
    """Example of testing a single URL."""
    print("\n" + "=" * 60)
    print("Example 2: Single URL Test")
    print("=" * 60)
    
    agent = RedTeamAgent(
        target_url="https://example.com/page?id=123",
        model_name="gpt-4"
    )
    
    # Test for XSS vulnerabilities
    result = agent.test_single_url(
        "https://example.com/page?id=123",
        test_type="xss"
    )
    
    print(f"\nTest Result: {result.get('output', 'N/A')[:200]}...")


def example_custom_scenarios():
    """Example with custom test scenarios."""
    print("\n" + "=" * 60)
    print("Example 3: Custom Test Scenarios")
    print("=" * 60)
    
    agent = RedTeamAgent(
        target_url="https://example.com",
        model_name="gpt-4"
    )
    
    custom_scenarios = [
        "Fetch and analyze the target page structure",
        "Test all forms for XSS vulnerabilities",
        "Test all URL parameters for SQL injection",
        "Analyze responses for missing security headers",
    ]
    
    report = agent.run_test_suite(test_scenarios=custom_scenarios)
    print(f"\nReport generated: {len(report)} characters")


def example_with_headers():
    """Example with custom HTTP headers."""
    print("\n" + "=" * 60)
    print("Example 4: Testing with Custom Headers")
    print("=" * 60)
    
    custom_headers = {
        "User-Agent": "RedTeamAgent/1.0",
        "Authorization": "Bearer your-token-here"
    }
    
    agent = RedTeamAgent(
        target_url="https://example.com",
        model_name="gpt-4",
        headers=custom_headers
    )
    
    # Fetch page with custom headers
    result = agent.agent.invoke({
        "input": "Fetch and analyze the target page",
        "chat_history": []
    })
    
    print(f"\nResult: {result.get('output', 'N/A')[:200]}...")


if __name__ == "__main__":
    # Check for OpenAI API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Warning: OPENAI_API_KEY not found in environment variables.")
        print("Please set it in a .env file or export it.")
        exit(1)
    
    try:
        # Run examples
        example_basic_web_test()
        example_single_url_test()
        example_custom_scenarios()
        example_with_headers()
        
        print("\n" + "=" * 60)
        print("All examples completed!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback
        traceback.print_exc()

