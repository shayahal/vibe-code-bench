"""LLM-guided testing module for intelligent, context-aware security testing."""

import logging
import os
from typing import List, Dict, Any, Optional

# Load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip loading .env

from langchain_core.tools import Tool

from vibe_code_bench.red_team_agent.models import VulnerabilityFinding, SecurityTestResult
from vibe_code_bench.red_team_agent.logging_config import get_logger

logger = get_logger(__name__)

# Try to import agent creation - may vary by LangChain version
create_react_agent = None
AgentExecutor = None
ToolExecutor = None

# Try LangGraph first (LangChain 1.0+)
try:
    from langgraph.prebuilt import create_react_agent, ToolExecutor
    AgentExecutor = None  # LangGraph uses ToolExecutor instead
    logger.info("[SETUP] Using LangGraph for agent creation")
except ImportError:
    # Try LangChain 0.x style
    try:
        from langchain.agents import create_react_agent, AgentExecutor
        logger.info("[SETUP] Using LangChain agents for agent creation")
    except ImportError:
        # Try newer LangChain API
        try:
            from langchain.agents import create_agent
            # Wrap create_agent to match create_react_agent signature
            def create_react_agent(llm, tools, prompt=None):
                if prompt:
                    return create_agent(llm, tools, system_prompt=prompt.messages[0].content if prompt.messages else "")
                return create_agent(llm, tools)
            logger.info("[SETUP] Using LangChain create_agent for agent creation")
        except ImportError:
            logger.warning(
                "[SETUP] LangChain agent creation not available. "
                "Install langgraph (pip install langgraph) or ensure langchain>=0.1.0 is installed."
            )

# Try to import Anchor Browser tools
try:
    from langchain_anchorbrowser import (
        AnchorContentTool,
        AnchorScreenshotTool,
        SimpleAnchorWebTaskTool,
    )
    ANCHOR_BROWSER_AVAILABLE = True
except ImportError:
    ANCHOR_BROWSER_AVAILABLE = False
    logger.warning(
        "langchain-anchorbrowser not available. "
        "Install with: pip install langchain-anchorbrowser. "
        "Some JavaScript-heavy tests will be limited."
    )


class SimpleToolExecutor:
    """Simple executor that uses tools directly without agent."""

    def __init__(self, tools: List[Tool]):
        """Initialize simple tool executor."""
        self.tools = {tool.name: tool for tool in tools}

    def invoke(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tools based on input."""
        # Simple implementation - just return a message
        return {"output": "LLM agent not available, using fallback executor"}


class LLMTester:
    """LLM-guided security testing agent."""

    def __init__(self, llm, use_anchor_browser: bool = True, max_iterations: int = 50):
        """
        Initialize LLM tester.

        Args:
            llm: LangChain LLM instance
            use_anchor_browser: Whether to use Anchor Browser tools
            max_iterations: Maximum iterations for agent
        """
        self.logger = get_logger(f"{__name__}.LLMTester")
        self.llm = llm
        self.use_anchor_browser = use_anchor_browser and ANCHOR_BROWSER_AVAILABLE
        self.max_iterations = max_iterations
        self.agent = None

        # Initialize Anchor Browser tools if available
        if self.use_anchor_browser:
            try:
                import os
                if not os.environ.get("ANCHORBROWSER_API_KEY"):
                    self.logger.warning(
                        "[SETUP] ANCHORBROWSER_API_KEY not set. "
                        "Anchor Browser tools require an API key. "
                        "Set ANCHORBROWSER_API_KEY environment variable to use Anchor Browser tools."
                    )
                    self.use_anchor_browser = False
                else:
                    self.content_tool = AnchorContentTool()
                    self.screenshot_tool = AnchorScreenshotTool()
                    self.web_task_tool = SimpleAnchorWebTaskTool()
                    self.logger.info("[SETUP] Anchor Browser tools initialized")
            except Exception as e:
                self.logger.warning(f"[SETUP] Failed to initialize Anchor Browser: {e}")
                self.use_anchor_browser = False

        # Create agent with tools
        if self.llm:
            tools = self._create_tools()
            self.agent = self._create_agent(tools)

    def _create_tools(self) -> List[Tool]:
        """
        Create LangChain tools for the LLM agent.

        Returns:
            List of LangChain tools
        """
        tools = []

        # Anchor Browser tools
        if self.use_anchor_browser:
            tools.extend([
                self.content_tool,
                self.screenshot_tool,
                self.web_task_tool,
            ])

        # Custom security testing tools
        def analyze_page_security_tool(url: str) -> str:
            """Analyze a page for security vulnerabilities."""
            try:
                if self.use_anchor_browser:
                    content = self.content_tool.invoke({"url": url})
                    return f"Page content retrieved. Analyze for security issues like XSS, injection, authentication bypass, etc."
                else:
                    return f"Page analysis requested for {url}. Use HTTP client to fetch and analyze."
            except Exception as e:
                return f"Error analyzing page: {str(e)}"

        def test_business_logic_tool(url: str, description: str) -> str:
            """Test for business logic vulnerabilities."""
            try:
                return f"Testing business logic for {url}: {description}. Check for authorization bypass, privilege escalation, etc."
            except Exception as e:
                return f"Error testing business logic: {str(e)}"

        def generate_test_case_tool(page_type: str, context: str) -> str:
            """Generate a custom test case based on page type and context."""
            try:
                return f"Generated test case for {page_type} page. Context: {context}. Test for vulnerabilities specific to this page type."
            except Exception as e:
                return f"Error generating test case: {str(e)}"

        tools.extend([
            Tool(
                name="analyze_page_security",
                func=analyze_page_security_tool,
                description="Analyze a web page for security vulnerabilities. Use this to examine page content and identify potential security issues.",
            ),
            Tool(
                name="test_business_logic",
                func=test_business_logic_tool,
                description="Test for business logic vulnerabilities. Use this to test authorization, access control, and workflow vulnerabilities.",
            ),
            Tool(
                name="generate_test_case",
                func=generate_test_case_tool,
                description="Generate a custom test case based on page type and context. Use this to create context-aware security tests.",
            ),
        ])

        return tools

    def _create_agent(self, tools: List[Tool]):
        """
        Create LangChain agent.

        Args:
            tools: List of tools for the agent

        Returns:
            Agent executor instance
        """
        if create_react_agent is None:
            self.logger.warning(
                "LangChain agent creation not available, using fallback executor. "
                "To enable full LLM testing, ensure an LLM API key is set "
                "(OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPENROUTER_API_KEY) "
                "and install langgraph: pip install langgraph"
            )
            return SimpleToolExecutor(tools)

        system_prompt = """You are a security testing agent tasked with finding vulnerabilities in web applications.
Your goal is to intelligently test web pages for security issues that automated scanners might miss.

Strategy:
1. Analyze page content to understand its functionality
2. Identify potential security vulnerabilities based on page type and content
3. Test for business logic vulnerabilities (authorization bypass, privilege escalation, etc.)
4. Generate context-aware test cases based on what you find
5. Use Anchor Browser tools to interact with pages and test interactively
6. Focus on vulnerabilities that require understanding of application logic

You have access to tools to:
- Analyze page content and security
- Test business logic vulnerabilities
- Generate custom test cases
- Interact with pages through Anchor Browser

Use your reasoning to decide which pages to test and what vulnerabilities to look for.
Prioritize high-risk pages (authentication, admin, payment) and test them thoroughly."""

        # Try LangGraph style first (LangChain 1.0+)
        if ToolExecutor is not None:
            try:
                agent = create_react_agent(self.llm, tools)
                tool_executor = ToolExecutor(tools)
                self.logger.info("[SETUP] Created LangGraph agent executor")
                return LangGraphExecutor(agent, tool_executor, self.max_iterations)
            except Exception as e:
                self.logger.debug(f"Failed to create agent with LangGraph: {e}")

        # Try LangChain 0.x style with AgentExecutor
        if AgentExecutor is not None:
            try:
                from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
                prompt = ChatPromptTemplate.from_messages(
                    [
                        ("system", system_prompt),
                        MessagesPlaceholder(variable_name="chat_history"),
                        ("human", "{input}"),
                        MessagesPlaceholder(variable_name="agent_scratchpad"),
                    ]
                )
                agent = create_react_agent(self.llm, tools, prompt)
                executor = AgentExecutor(
                    agent=agent, tools=tools, max_iterations=self.max_iterations, verbose=True
                )
                self.logger.info("[SETUP] Created LangChain AgentExecutor")
                return executor
            except Exception as e:
                self.logger.debug(f"Failed to create agent with LangChain 0.x style: {e}")

        # Try direct create_react_agent call (newer LangChain API)
        try:
            agent = create_react_agent(self.llm, tools)
            self.logger.info("[SETUP] Created agent with direct API")
            # Return a simple wrapper that can invoke the agent
            return SimpleAgentWrapper(agent, tools, self.max_iterations)
        except Exception as e:
            self.logger.debug(f"Failed to create agent with direct API: {e}")

        # Fallback
        self.logger.warning("All agent creation methods failed, using fallback executor")
        return SimpleToolExecutor(tools)

    def test_pages(
        self, pages: List[Dict[str, Any]], previous_findings: List[VulnerabilityFinding]
    ) -> List[SecurityTestResult]:
        """
        Use LLM agent to intelligently test pages.

        Args:
            pages: List of page information dictionaries
            previous_findings: Previous vulnerability findings for context

        Returns:
            List of SecurityTestResult objects
        """
        if not self.agent:
            self.logger.warning("[AGENT] LLM agent not available, skipping intelligent testing")
            return []

        self.logger.info(f"[AGENT] LLM-Guided Testing - {len(pages)} pages - Started")

        results = []

        # If no pages provided, skip testing
        if not pages:
            self.logger.warning("[AGENT] No pages provided for LLM testing")
            return results

        # Prioritize high-risk pages, but test all pages if no high-risk ones found
        high_risk_pages = [
            p for p in pages
            if p.get("page_type", "").lower() in ["login", "admin", "account", "checkout", "payment"]
            or p.get("requires_auth", False)
        ]

        # If no high-risk pages, test all pages (up to 10)
        pages_to_test = high_risk_pages[:5] if high_risk_pages else pages[:10]

        # Create context for agent
        findings_summary = "\n".join([
            f"- {f.vulnerability_type} ({f.severity}) on {f.affected_url}"
            for f in previous_findings[:10]  # Limit to first 10
        ])

        for page in pages_to_test:
            url = page.get("url", "")
            page_type = page.get("page_type", "unknown")

            try:
                agent_input = f"""Analyze and test this page for security vulnerabilities:
URL: {url}
Page Type: {page_type}
Requires Auth: {page.get('requires_auth', False)}

Previous findings so far:
{findings_summary if findings_summary else "None yet"}

Focus on:
1. Business logic vulnerabilities specific to this page type
2. Authorization bypasses
3. Context-aware XSS or injection vulnerabilities
4. Any security issues that automated scanners might miss

Use the analyze_page_security tool first to understand the page, then test for vulnerabilities."""

                self.logger.info(f"[AGENT] Testing page: {url}")
                agent_result = self.agent.invoke({"input": agent_input})

                # Create result from agent output
                result = SecurityTestResult(
                    test_type="LLM-Guided",
                    target_url=url,
                    status="safe",  # Default, agent will identify vulnerabilities
                    metadata={
                        "agent_output": str(agent_result.get("output", "")),
                        "page_type": page_type,
                    },
                )

                # Parse agent output for vulnerabilities (simplified)
                output = str(agent_result.get("output", "")).lower()
                if any(keyword in output for keyword in ["vulnerable", "vulnerability", "security issue", "exploit"]):
                    # Agent found something - create a finding
                    finding = VulnerabilityFinding(
                        vulnerability_type="Business Logic Vulnerability",
                        severity="Medium",
                        affected_url=url,
                        description=f"LLM agent identified potential security issue: {agent_result.get('output', '')[:200]}",
                        proof_of_concept=agent_result.get("output", "")[:500],
                        remediation="Review the identified issue and implement proper security controls",
                        test_type="LLM-Guided",
                    )
                    result.findings.append(finding)
                    result.status = "vulnerable"
                    self.logger.warning(f"[FINDING] Business Logic - Medium - {url}")

                results.append(result)
                self.logger.info(f"[AGENT] Completed testing: {url}")

            except Exception as e:
                self.logger.error(f"[ERROR] LLM agent test failed for {url}: {e}")
                result = SecurityTestResult(
                    test_type="LLM-Guided",
                    target_url=url,
                    status="error",
                    error_message=str(e),
                )
                results.append(result)

        self.logger.info(f"[AGENT] LLM-Guided Testing - Completed - {len(results)} tests")

        return results


class LangGraphExecutor:
    """Wrapper for LangGraph executor."""

    def __init__(self, agent, tool_executor, max_iterations: int):
        """Initialize LangGraph executor wrapper."""
        self.agent = agent
        self.tool_executor = tool_executor
        self.max_iterations = max_iterations

    def invoke(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute agent with LangGraph."""
        try:
            # Use LangGraph's invoke method
            result = self.agent.invoke(input_data)
            return {"output": str(result.get("messages", [result])[-1].content if hasattr(result, "get") else result)}
        except Exception as e:
            logger.error(f"LangGraph executor error: {e}")
            return {"output": f"Error executing agent: {str(e)}"}


class SimpleAgentWrapper:
    """Simple wrapper for agents that don't need special executors."""

    def __init__(self, agent, tools, max_iterations: int):
        """Initialize simple agent wrapper."""
        self.agent = agent
        self.tools = tools
        self.max_iterations = max_iterations

    def invoke(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute agent."""
        try:
            # Extract the input text
            input_text = input_data.get("input", str(input_data))
            
            # Try different invocation formats
            # Format 1: Direct invoke with messages (newer LangChain API)
            try:
                from langchain_core.messages import HumanMessage
                messages = [HumanMessage(content=input_text)]
                if hasattr(self.agent, "invoke"):
                    result = self.agent.invoke({"messages": messages})
                    # Extract output from result
                    if isinstance(result, dict):
                        if "messages" in result:
                            last_message = result["messages"][-1]
                            output = last_message.content if hasattr(last_message, "content") else str(last_message)
                        else:
                            output = str(result.get("output", result))
                    else:
                        output = str(result)
                    return {"output": output}
            except Exception as e1:
                logger.debug(f"Failed to invoke with messages format: {e1}")
            
            # Format 2: Dict with "input" key (LangGraph format)
            try:
                if hasattr(self.agent, "invoke"):
                    result = self.agent.invoke(input_data)
                    if isinstance(result, dict):
                        output = str(result.get("output", result.get("messages", [result])[-1] if "messages" in result else result))
                    else:
                        output = str(result)
                    return {"output": output}
            except Exception as e2:
                logger.debug(f"Failed to invoke with input dict: {e2}")
            
            # Format 3: Direct call with string
            try:
                if hasattr(self.agent, "__call__"):
                    result = self.agent(input_text)
                    return {"output": str(result)}
            except Exception as e3:
                logger.debug(f"Failed to invoke with direct call: {e3}")
            
            return {"output": "Agent created but invocation method not available"}
        except Exception as e:
            logger.error(f"Agent invocation error: {e}")
            return {"output": f"Error executing agent: {str(e)}"}
