"""LangChain agent setup for browsing decisions."""

import logging
from typing import List, Dict, Any, Optional

# LangChain 1.0+ compatible imports
from langchain_core.tools import Tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

# Try to import agent creation - may vary by LangChain version
try:
    from langchain.agents import create_react_agent, AgentExecutor
except ImportError:
    try:
        # LangChain 1.0+ may use langgraph
        from langgraph.prebuilt import create_react_agent
        from langgraph.prebuilt import ToolExecutor
        AgentExecutor = None  # Will use ToolExecutor instead
    except ImportError:
        # Fallback: create a simple wrapper
        create_react_agent = None
        AgentExecutor = None

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
        try:
            result = browser.fetch_page(url)
            if result.get("success"):
                return f"Page fetched successfully. Status: {result.get('status_code')}. Title: {result.get('title', 'N/A')}"
            else:
                return f"Failed to fetch page: {result.get('error', 'Unknown error')}"
        except Exception as e:
            return f"Error fetching page: {str(e)}"

    def extract_links_tool(html: str, base_url: str) -> str:
        """Extract links from HTML content."""
        try:
            links = discovery.extract_links(html, base_url)
            return f"Found {len(links)} links: {', '.join(links[:10])}" + ("..." if len(links) > 10 else "")
        except Exception as e:
            return f"Error extracting links: {str(e)}"

    def analyze_navigation_tool(html: str, base_url: str) -> str:
        """Analyze page navigation structure."""
        try:
            result = analyzer.analyze_navigation(html, base_url)
            nav_count = len(result.get("navigation_links", []))
            content_count = len(result.get("content_links", []))
            return f"Navigation links: {nav_count}, Content links: {content_count}. Has nav menu: {result.get('has_nav_menu', False)}"
        except Exception as e:
            return f"Error analyzing navigation: {str(e)}"

    def check_sitemap_tool(base_url: str) -> str:
        """Check for sitemap.xml and return URLs."""
        try:
            urls = discovery.check_sitemap(base_url)
            if urls:
                return f"Found sitemap with {len(urls)} URLs: {', '.join(urls[:5])}" + ("..." if len(urls) > 5 else "")
            else:
                return "No sitemap found"
        except Exception as e:
            return f"Error checking sitemap: {str(e)}"

    def parse_robots_tool(base_url: str) -> str:
        """Parse robots.txt file."""
        try:
            result = discovery.parse_robots(base_url)
            sitemaps = result.get("sitemap_urls", [])
            crawl_delay = result.get("crawl_delay")
            return f"Robots.txt parsed. Sitemaps: {len(sitemaps)}, Crawl delay: {crawl_delay}"
        except Exception as e:
            return f"Error parsing robots.txt: {str(e)}"

    def authenticate_tool(login_url: str, username: str, password: str) -> str:
        """Authenticate with login credentials."""
        try:
            result = auth_handler.authenticate(
                browser, login_url, {"username": username, "password": password}
            )
            if result.get("success"):
                return "Authentication successful"
            else:
                return f"Authentication failed: {result.get('error', 'Unknown error')}"
        except Exception as e:
            return f"Error during authentication: {str(e)}"

    tools = [
        Tool(
            name="fetch_page",
            func=lambda url: fetch_page_tool(url),
            description="Fetch a web page by URL. Returns page content and metadata. Use this to load pages before analyzing them.",
        ),
        Tool(
            name="extract_links",
            func=lambda html, base_url: extract_links_tool(html, base_url),
            description="Extract all links from HTML content. Returns list of URLs found on the page.",
        ),
        Tool(
            name="analyze_navigation",
            func=lambda html, base_url: analyze_navigation_tool(html, base_url),
            description="Analyze page structure to identify navigation menus and content links. Helps prioritize which links to follow.",
        ),
        Tool(
            name="check_sitemap",
            func=lambda base_url: check_sitemap_tool(base_url),
            description="Check if website has a sitemap.xml file. If found, returns list of URLs from sitemap. Use this first to discover pages efficiently.",
        ),
        Tool(
            name="parse_robots",
            func=lambda base_url: parse_robots_tool(base_url),
            description="Parse robots.txt file to understand crawling rules and find sitemap URLs. Should be checked first.",
        ),
        Tool(
            name="authenticate",
            func=lambda login_url, username, password: authenticate_tool(login_url, username, password),
            description="Authenticate with a login form. Use when a page requires authentication. Requires login_url, username, and password.",
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
            logger.warning(f"Failed to initialize Anchor Browser tools: {e}")

    return tools


def create_langchain_agent(llm, tools: List[Tool], max_iterations: int = 100):
    """
    Create LangChain ReAct agent.

    Args:
        llm: LangChain LLM instance
        tools: List of tools for the agent
        max_iterations: Maximum number of agent iterations

    Returns:
        Agent executor instance (varies by LangChain version)
    """
    if create_react_agent is None:
        # Fallback: return a simple executor that just uses tools directly
        logger.warning("LangChain agent creation not available, using direct tool execution")
        return SimpleToolExecutor(tools)

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
        # Try LangChain 0.x style
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", system_prompt),
                MessagesPlaceholder(variable_name="chat_history"),
                ("human", "{input}"),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ]
        )
        agent = create_react_agent(llm, tools, prompt)
        if AgentExecutor:
            executor = AgentExecutor(agent=agent, tools=tools, max_iterations=max_iterations, verbose=True)
            return executor
    except Exception as e:
        logger.debug(f"Failed to create agent with LangChain 0.x style: {e}")

    # Try LangGraph style (LangChain 1.0+)
    try:
        from langgraph.prebuilt import ToolExecutor
        agent = create_react_agent(llm, tools)
        tool_executor = ToolExecutor(tools)
        # Return a simple wrapper
        return LangGraphExecutor(agent, tool_executor, max_iterations)
    except Exception as e:
        logger.debug(f"Failed to create agent with LangGraph: {e}")

    # Fallback
    return SimpleToolExecutor(tools)


class SimpleToolExecutor:
    """Simple executor that uses tools directly without agent."""

    def __init__(self, tools: List[Tool]):
        self.tools = {tool.name: tool for tool in tools}

    def invoke(self, input_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tools based on input."""
        # This is a placeholder - the main BrowsingAgent will handle tool execution
        return {"output": "Tool executor placeholder - using direct crawling instead"}


class LangGraphExecutor:
    """Wrapper for LangGraph executor."""

    def __init__(self, agent, tool_executor, max_iterations: int):
        self.agent = agent
        self.tool_executor = tool_executor
        self.max_iterations = max_iterations

    def invoke(self, input_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Invoke the agent."""
        # Simplified invocation - full implementation would use LangGraph's run method
        return {"output": "LangGraph executor - agent guidance available"}
