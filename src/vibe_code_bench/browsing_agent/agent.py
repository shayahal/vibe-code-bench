"""LangChain agent setup for browsing decisions."""

import logging
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# LangChain 1.0+ compatible imports
from langchain_core.tools import Tool, StructuredTool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

# Import agent creation from langgraph (LangChain 1.0+)
try:
    from langgraph.prebuilt import create_react_agent
    LANGGRAPH_AVAILABLE = True
except ImportError as e:
    LANGGRAPH_AVAILABLE = False
    raise ImportError(
        "langgraph is required for agent creation. Install with: pip install langgraph"
    ) from e

# Try to import Anchor Browser tools
try:
    from langchain_anchorbrowser import (
        AnchorContentTool,
        AnchorScreenshotTool,
        SimpleAnchorWebTaskTool,
    )
    ANCHOR_BROWSER_TOOLS_AVAILABLE = True
except ImportError:
    ANCHOR_BROWSER_TOOLS_AVAILABLE = False

from vibe_code_bench.browsing_agent.browser import BrowserWrapper
from vibe_code_bench.browsing_agent.discovery import DiscoveryEngine
from vibe_code_bench.browsing_agent.analyzer import PageAnalyzer
from vibe_code_bench.browsing_agent.auth import AuthenticationHandler

logger = logging.getLogger(__name__)


def create_browsing_agent_tools(
    browser: BrowserWrapper,
    discovery: DiscoveryEngine,
    analyzer: PageAnalyzer,
    auth_handler: AuthenticationHandler,
) -> List[Tool]:
    """
    Create LangChain tools for the browsing agent.

    Args:
        browser: BrowserWrapper instance
        discovery: DiscoveryEngine instance
        analyzer: PageAnalyzer instance
        auth_handler: AuthenticationHandler instance

    Returns:
        List of LangChain tools
    """
    def fetch_page_tool(url: str) -> str:
        """Fetch a page and return its HTML content."""
        result = browser.fetch_page(url)
        if result.get("success"):
            return f"Page fetched successfully. Status: {result.get('status_code')}. Title: {result.get('title', 'N/A')}"
        else:
            error_msg = result.get('error', 'Unknown error')
            raise RuntimeError(f"Failed to fetch page {url}: {error_msg}")

    def extract_links_tool(html: str, base_url: str) -> str:
        """Extract links from HTML content."""
        links = discovery.extract_links(html, base_url)
        return f"Found {len(links)} links: {', '.join(links[:10])}" + ("..." if len(links) > 10 else "")

    def analyze_navigation_tool(html: str, base_url: str) -> str:
        """Analyze page navigation structure."""
        result = analyzer.analyze_navigation(html, base_url)
        nav_count = len(result.get("navigation_links", []))
        content_count = len(result.get("content_links", []))
        return f"Navigation links: {nav_count}, Content links: {content_count}. Has nav menu: {result.get('has_nav_menu', False)}"

    def check_sitemap_tool(base_url: str) -> str:
        """Check for sitemap.xml and return URLs."""
        urls = discovery.check_sitemap(base_url)
        if urls:
            return f"Found sitemap with {len(urls)} URLs: {', '.join(urls[:5])}" + ("..." if len(urls) > 5 else "")
        else:
            return "No sitemap found"

    def parse_robots_tool(base_url: str) -> str:
        """Parse robots.txt file."""
        result = discovery.parse_robots(base_url)
        sitemaps = result.get("sitemap_urls", [])
        crawl_delay = result.get("crawl_delay")
        return f"Robots.txt parsed. Sitemaps: {len(sitemaps)}, Crawl delay: {crawl_delay}"

    def authenticate_tool(login_url: str, username: str, password: str) -> str:
        """Authenticate with login credentials."""
        result = auth_handler.authenticate(
            browser, login_url, {"username": username, "password": password}
        )
        if result.get("success"):
            return "Authentication successful"
        else:
            error_msg = result.get('error', 'Unknown error')
            raise RuntimeError(f"Authentication failed for {login_url}: {error_msg}")

    # Define Pydantic models for structured tools
    class ExtractLinksInput(BaseModel):
        html: str = Field(description="HTML content to extract links from")
        base_url: str = Field(description="Base URL for resolving relative links")

    class AnalyzeNavigationInput(BaseModel):
        html: str = Field(description="HTML content to analyze")
        base_url: str = Field(description="Base URL of the page")

    class AuthenticateInput(BaseModel):
        login_url: str = Field(description="URL of the login page")
        username: str = Field(description="Username for authentication")
        password: str = Field(description="Password for authentication")

    tools = [
        Tool(
            name="fetch_page",
            func=fetch_page_tool,
            description="Fetch a web page by URL. Returns page content and metadata. Use this to load pages before analyzing them.",
        ),
        StructuredTool.from_function(
            func=extract_links_tool,
            name="extract_links",
            description="Extract all links from HTML content. Returns list of URLs found on the page.",
            args_schema=ExtractLinksInput,
        ),
        StructuredTool.from_function(
            func=analyze_navigation_tool,
            name="analyze_navigation",
            description="Analyze page structure to identify navigation menus and content links. Helps prioritize which links to follow.",
            args_schema=AnalyzeNavigationInput,
        ),
        Tool(
            name="check_sitemap",
            func=check_sitemap_tool,
            description="Check if website has a sitemap.xml file. If found, returns list of URLs from sitemap. Use this first to discover pages efficiently.",
        ),
        Tool(
            name="parse_robots",
            func=parse_robots_tool,
            description="Parse robots.txt file to understand crawling rules and find sitemap URLs. Should be checked first.",
        ),
        StructuredTool.from_function(
            func=authenticate_tool,
            name="authenticate",
            description="Authenticate with a login form. Use when a page requires authentication.",
            args_schema=AuthenticateInput,
        ),
    ]

    # Add Anchor Browser tools directly if available
    if ANCHOR_BROWSER_TOOLS_AVAILABLE:
        try:
            anchor_content_tool = AnchorContentTool()
            anchor_screenshot_tool = AnchorScreenshotTool()
            anchor_web_task_tool = SimpleAnchorWebTaskTool()
            
            tools.extend([
                anchor_content_tool,
                anchor_screenshot_tool,
                anchor_web_task_tool,
            ])
            logger.info("Added Anchor Browser tools to agent")
        except Exception as e:
            raise RuntimeError(
                f"Failed to initialize Anchor Browser tools: {e}. "
                "Ensure ANCHORBROWSER_API_KEY is valid and langchain-anchorbrowser is properly installed."
            ) from e

    return tools


def create_langchain_agent(llm, tools: List[Tool], max_iterations: int = 100):
    """
    Create LangChain ReAct agent using langgraph.

    Args:
        llm: LangChain LLM instance
        tools: List of tools for the agent
        max_iterations: Maximum number of agent iterations

    Returns:
        LangGraphExecutor instance that can invoke the agent

    Raises:
        ImportError: If langgraph is not available
        RuntimeError: If agent creation fails
    """
    if not LANGGRAPH_AVAILABLE:
        raise ImportError(
            "langgraph is required for agent creation. Install with: pip install langgraph"
        )

    if not tools:
        raise ValueError("At least one tool is required to create an agent")

    system_prompt = """You are a web browsing agent tasked with discovering all pages on a website.
Your goal is to find up to 50 unique pages efficiently.

Strategy:
1. First check for sitemap.xml - if available, use it as starting point
2. Respect robots.txt rules
3. Prioritize navigation links over content links
4. Avoid duplicate pages
5. Stop when you've found 50 pages or no more valuable links exist

You have access to tools to fetch pages, extract links, and analyze content.
Use your reasoning to decide which pages to visit next.
Always check robots.txt and sitemap first before starting to crawl.
Track which URLs you've already visited to avoid duplicates."""

    try:
        # Create the agent graph using langgraph
        # prompt parameter accepts SystemMessage, str, or None
        agent = create_react_agent(llm, tools, prompt=system_prompt)
        logger.info("Successfully created LangGraph agent")
        return LangGraphExecutor(agent, max_iterations)
    except Exception as e:
        raise RuntimeError(
            f"Failed to create LangGraph agent: {e}. "
            "Ensure langgraph is properly installed and all dependencies are available."
        ) from e


class LangGraphExecutor:
    """Wrapper for LangGraph agent executor."""

    def __init__(self, agent_graph, max_iterations: int):
        """
        Initialize LangGraph executor.

        Args:
            agent_graph: The graph returned by create_react_agent
            max_iterations: Maximum number of agent iterations
        """
        self.agent = agent_graph
        self.max_iterations = max_iterations

    def invoke(self, input_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoke the agent with the given input.

        Args:
            input_dict: Dictionary with either:
                - 'messages' key containing list of messages (langgraph format)
                - 'input' key containing string input (converted to messages)

        Returns:
            Dictionary with 'messages' key containing agent response

        Raises:
            RuntimeError: If invocation fails
            ValueError: If input format is invalid
        """
        if not isinstance(input_dict, dict):
            raise ValueError("input_dict must be a dictionary")
        
        # Convert input format if needed
        if "input" in input_dict and "messages" not in input_dict:
            # Convert string input to messages format
            from langchain_core.messages import HumanMessage
            messages = [HumanMessage(content=str(input_dict["input"]))]
            langgraph_input = {"messages": messages}
        elif "messages" in input_dict:
            langgraph_input = input_dict
        else:
            raise ValueError(
                "input_dict must contain either 'input' (string) or 'messages' (list) key"
            )

        try:
            # Configure the agent with max_iterations
            config = {"recursion_limit": self.max_iterations}
            
            # Invoke the agent graph
            result = self.agent.invoke(langgraph_input, config=config)
            
            if not isinstance(result, dict) or "messages" not in result:
                raise RuntimeError(
                    f"Agent returned unexpected result type: {type(result)}. "
                    "Expected dict with 'messages' key."
                )
            
            # Extract the last message as output for backward compatibility
            if result["messages"]:
                last_message = result["messages"][-1]
                if hasattr(last_message, "content"):
                    result["output"] = last_message.content
                elif isinstance(last_message, dict) and "content" in last_message:
                    result["output"] = last_message["content"]
            
            return result
        except Exception as e:
            raise RuntimeError(
                f"Failed to invoke LangGraph agent: {e}. "
                "Ensure the agent graph is properly configured and the input format is correct."
            ) from e
