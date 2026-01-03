"""LangGraph-based red team agent for security scanning.

This agent orchestrates multiple security tools to scan a URL for vulnerabilities.
All operations are traced with Langfuse for observability.
"""

import os
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool

from vibe_code_bench.red_team_agent.models import (
    ScanReport,
    ToolResult,
    VulnerabilityFinding,
)
from vibe_code_bench.red_team_agent.exceptions import (
    AgentError,
    ConfigurationError,
    ScanError,
    ValidationError,
)
from vibe_code_bench.red_team_agent.observability import (
    ObservabilityManager,
    get_callback_handler,
    get_logger,
    traced,
)
from vibe_code_bench.red_team_agent.tools import (
    BrowserTool,
    NucleiTool,
    SQLMapTool,
    DalFoxTool,
    WapitiTool,
    NiktoTool,
    ToolRegistry,
)


# System prompt for the security agent
SECURITY_AGENT_PROMPT = """You are a security expert conducting a vulnerability assessment.

Your goal is to find security vulnerabilities in the target website by using the available scanning tools.

Strategy:
1. First, use the browser tool to discover pages and forms on the target
2. Run nuclei for fast vulnerability scanning
3. Use specialized tools (sqlmap for SQL injection, dalfox for XSS) on interesting endpoints
4. Run wapiti for comprehensive web app scanning
5. Check server configuration with nikto

Report all findings accurately. Focus on high-severity vulnerabilities first.
Do not make up vulnerabilities - only report what the tools actually find.
"""


class RedTeamAgent:
    """LangGraph-based security scanning agent.
    
    This agent orchestrates multiple security tools to scan a URL and
    produces a comprehensive vulnerability report.
    
    Example:
        agent = RedTeamAgent()
        report = agent.scan("https://example.com")
        print(report.total_findings)
    """
    
    def __init__(
        self,
        llm=None,
        run_id: str | None = None,
        enable_llm_agent: bool = True,
    ):
        """Initialize the red team agent.
        
        Args:
            llm: LangChain LLM instance. If None, creates default based on env vars.
            run_id: Optional run identifier for tracing.
            enable_llm_agent: If True, use LLM for intelligent tool orchestration.
                            If False, run tools in fixed sequence.
        """
        # Initialize observability
        self.obs = ObservabilityManager.get_instance(run_id)
        self.logger = get_logger(__name__)
        self.run_id = self.obs.run_id
        
        self.enable_llm_agent = enable_llm_agent
        
        # Initialize LLM if agent mode enabled
        self.llm = None
        if enable_llm_agent:
            self.llm = llm or self._create_default_llm()
        
        # Initialize tools
        self._init_tools()
        
        # Create LangGraph agent if LLM available
        self.agent = None
        if self.llm and enable_llm_agent:
            self.agent = self._create_agent()
        
        self.logger.info(f"RedTeamAgent initialized | run_id={self.run_id}")
        self.logger.info(f"LLM Agent: {'enabled' if self.agent else 'disabled'}")
        self.logger.info(f"Available tools: {ToolRegistry.list_available()}")
        self.logger.info(f"Unavailable tools: {ToolRegistry.list_unavailable()}")
    
    def _create_default_llm(self):
        """Create default LLM based on environment variables."""
        # Try OpenAI
        if os.getenv("OPENAI_API_KEY"):
            from langchain_openai import ChatOpenAI
            self.logger.info("Using OpenAI GPT-4")
            return ChatOpenAI(model="gpt-4o", temperature=0)
        
        # Try Anthropic
        if os.getenv("ANTHROPIC_API_KEY"):
            from langchain_anthropic import ChatAnthropic
            self.logger.info("Using Anthropic Claude")
            return ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)
        
        # Try OpenRouter
        if os.getenv("OPENROUTER_API_KEY"):
            from langchain_openai import ChatOpenAI
            self.logger.info("Using OpenRouter")
            return ChatOpenAI(
                model="openai/gpt-4o",
                temperature=0,
                base_url="https://openrouter.ai/api/v1",
                api_key=os.getenv("OPENROUTER_API_KEY"),
            )
        
        self.logger.warning(
            "No LLM API key found. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPENROUTER_API_KEY. "
            "Running in tool-only mode (no LLM orchestration)."
        )
        return None
    
    def _init_tools(self) -> None:
        """Initialize and register security tools."""
        # Create tool instances
        self.browser_tool = BrowserTool(required=False)
        self.nuclei_tool = NucleiTool(required=False)
        self.sqlmap_tool = SQLMapTool(required=False)
        self.dalfox_tool = DalFoxTool(required=False)
        self.wapiti_tool = WapitiTool(required=False)
        self.nikto_tool = NiktoTool(required=False)
        
        # Register tools
        ToolRegistry.register(self.browser_tool)
        ToolRegistry.register(self.nuclei_tool)
        ToolRegistry.register(self.sqlmap_tool)
        ToolRegistry.register(self.dalfox_tool)
        ToolRegistry.register(self.wapiti_tool)
        ToolRegistry.register(self.nikto_tool)
    
    def _create_agent(self):
        """Create LangGraph ReAct agent."""
        try:
            from langgraph.prebuilt import create_react_agent
            
            # Create LangChain tools from our tool wrappers
            langchain_tools = self._create_langchain_tools()
            
            # Create agent
            agent = create_react_agent(
                self.llm,
                langchain_tools,
                state_modifier=SECURITY_AGENT_PROMPT,
            )
            
            self.logger.info("LangGraph agent created successfully")
            return agent
            
        except ImportError:
            self.logger.warning(
                "LangGraph not installed. Install with: pip install langgraph. "
                "Running in tool-only mode."
            )
            return None
        except Exception as e:
            self.logger.error(f"Failed to create LangGraph agent: {e}")
            return None
    
    def _create_langchain_tools(self) -> list:
        """Create LangChain tool wrappers for the agent."""
        tools = []
        
        @tool
        def scan_with_browser(url: str) -> str:
            """Scan a URL with the browser tool to check security headers, CSRF, and info disclosure."""
            result = self.browser_tool.scan(url)
            if result.success:
                findings = [f"{f.vulnerability_type}: {f.description}" for f in result.findings]
                return f"Found {len(result.findings)} issues: {'; '.join(findings) if findings else 'None'}"
            return f"Error: {result.error_message}"
        
        @tool
        def discover_urls(url: str) -> str:
            """Discover URLs on a website for further scanning."""
            urls = self.browser_tool.discover_urls(url)
            return f"Discovered {len(urls)} URLs: {', '.join(urls[:10])}" + ("..." if len(urls) > 10 else "")
        
        @tool
        def scan_with_nuclei(url: str) -> str:
            """Run nuclei vulnerability scanner on a URL."""
            if not self.nuclei_tool.available:
                return "Nuclei not available"
            result = self.nuclei_tool.scan(url)
            if result.success:
                findings = [f"{f.vulnerability_type} ({f.severity})" for f in result.findings]
                return f"Found {len(result.findings)} vulnerabilities: {'; '.join(findings) if findings else 'None'}"
            return f"Error: {result.error_message}"
        
        @tool
        def scan_for_sqli(url: str) -> str:
            """Run SQLMap to check for SQL injection vulnerabilities."""
            if not self.sqlmap_tool.available:
                return "SQLMap not available"
            result = self.sqlmap_tool.scan(url)
            if result.success:
                if result.findings:
                    return f"SQL INJECTION FOUND: {result.findings[0].description}"
                return "No SQL injection found"
            return f"Error: {result.error_message}"
        
        @tool
        def scan_for_xss(url: str) -> str:
            """Run DalFox to check for XSS vulnerabilities."""
            if not self.dalfox_tool.available:
                return "DalFox not available"
            result = self.dalfox_tool.scan(url)
            if result.success:
                if result.findings:
                    return f"XSS FOUND: {result.findings[0].description}"
                return "No XSS found"
            return f"Error: {result.error_message}"
        
        @tool
        def scan_with_wapiti(url: str) -> str:
            """Run Wapiti web vulnerability scanner."""
            if not self.wapiti_tool.available:
                return "Wapiti not available"
            result = self.wapiti_tool.scan(url)
            if result.success:
                findings = [f"{f.vulnerability_type}" for f in result.findings]
                return f"Found {len(result.findings)} issues: {'; '.join(findings) if findings else 'None'}"
            return f"Error: {result.error_message}"
        
        @tool
        def scan_with_nikto(url: str) -> str:
            """Run Nikto web server scanner."""
            if not self.nikto_tool.available:
                return "Nikto not available"
            result = self.nikto_tool.scan(url)
            if result.success:
                findings = [f"{f.vulnerability_type}" for f in result.findings[:5]]
                return f"Found {len(result.findings)} issues: {'; '.join(findings) if findings else 'None'}"
            return f"Error: {result.error_message}"
        
        tools = [
            scan_with_browser,
            discover_urls,
            scan_with_nuclei,
            scan_for_sqli,
            scan_for_xss,
            scan_with_wapiti,
            scan_with_nikto,
        ]
        
        return tools
    
    def _validate_url(self, url: str) -> str:
        """Validate and normalize URL.
        
        Args:
            url: URL to validate
            
        Returns:
            Normalized URL
            
        Raises:
            ValidationError: If URL is invalid
        """
        if not url:
            raise ValidationError("URL cannot be empty")
        
        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        
        # Parse and validate
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValidationError(f"Invalid URL: {url}")
        
        return url
    
    @traced("scan")
    def scan(self, url: str) -> ScanReport:
        """Scan a URL for security vulnerabilities.
        
        Args:
            url: Target URL to scan
            
        Returns:
            ScanReport with all findings
            
        Raises:
            ValidationError: If URL is invalid
            ScanError: If scan fails
            AgentError: If agent fails
        """
        # Validate URL
        url = self._validate_url(url)
        
        self.logger.info(f"Starting security scan | url={url}")
        
        # Create report
        report = ScanReport(
            target_url=url,
            scan_id=self.run_id,
            tools_available=ToolRegistry.list_available(),
        )
        
        try:
            if self.agent:
                # Use LLM agent for intelligent scanning
                report = self._scan_with_agent(url, report)
            else:
                # Run tools in fixed sequence
                report = self._scan_sequential(url, report)
            
            # Finalize report
            report = report.finalize()
            
            self.logger.info(
                f"Scan complete | findings={report.total_findings} | "
                f"critical={report.findings_by_severity.get('Critical', 0)} | "
                f"high={report.findings_by_severity.get('High', 0)}"
            )
            
            return report
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise ScanError(url, str(e)) from e
    
    def _scan_with_agent(self, url: str, report: ScanReport) -> ScanReport:
        """Run scan using LLM agent for intelligent tool orchestration."""
        self.logger.info("Running LLM-guided scan")
        
        # Get callback handler for Langfuse tracing
        callbacks = []
        handler = get_callback_handler()
        if handler:
            callbacks.append(handler)
        
        # Invoke agent
        prompt = f"Scan {url} for security vulnerabilities. Use all available tools systematically."
        
        try:
            result = self.agent.invoke(
                {"messages": [HumanMessage(content=prompt)]},
                config={"callbacks": callbacks} if callbacks else None,
            )
            
            # Extract findings from agent execution
            # The agent stores results in tool calls, we collect them
            # For now, also run tools directly to ensure we get results
            report = self._scan_sequential(url, report)
            
        except Exception as e:
            self.logger.error(f"Agent execution failed: {e}")
            # Fall back to sequential scanning
            report = self._scan_sequential(url, report)
        
        return report
    
    def _scan_sequential(self, url: str, report: ScanReport) -> ScanReport:
        """Run tools in a fixed sequence."""
        self.logger.info("Running sequential scan")
        
        # 1. Browser-based checks (always available)
        self.logger.info("Running browser checks...")
        browser_result = self.browser_tool.scan(url)
        report.tool_results.append(browser_result)
        
        # 2. Nuclei scan
        if self.nuclei_tool.available:
            self.logger.info("Running nuclei scan...")
            nuclei_result = self.nuclei_tool.scan(url)
            report.tool_results.append(nuclei_result)
        
        # 3. Discover URLs for deeper scanning
        discovered_urls = self.browser_tool.discover_urls(url)
        forms = self.browser_tool.extract_forms(url)
        
        # 4. SQLMap on forms
        if self.sqlmap_tool.available and forms:
            self.logger.info(f"Running SQLMap on {len(forms)} forms...")
            for form in forms[:3]:  # Limit to first 3 forms
                if form.get("method") == "post":
                    form_data = {f["name"]: "test" for f in form.get("fields", []) if f.get("name")}
                    if form_data:
                        sqlmap_result = self.sqlmap_tool.scan(form["action"], data="&".join(f"{k}={v}" for k, v in form_data.items()))
                        report.tool_results.append(sqlmap_result)
        
        # 5. DalFox XSS scan
        if self.dalfox_tool.available:
            self.logger.info("Running DalFox XSS scan...")
            dalfox_result = self.dalfox_tool.scan(url)
            report.tool_results.append(dalfox_result)
        
        # 6. Wapiti comprehensive scan
        if self.wapiti_tool.available:
            self.logger.info("Running Wapiti scan...")
            wapiti_result = self.wapiti_tool.scan(url)
            report.tool_results.append(wapiti_result)
        
        # 7. Nikto server scan
        if self.nikto_tool.available:
            self.logger.info("Running Nikto scan...")
            nikto_result = self.nikto_tool.scan(url)
            report.tool_results.append(nikto_result)
        
        return report
    
    def save_report(self, report: ScanReport, output_path: str | None = None) -> str:
        """Save scan report to file.
        
        Args:
            report: ScanReport to save
            output_path: Optional output path. If None, saves to default location.
            
        Returns:
            Path to saved report
        """
        import json
        from vibe_code_bench.core.paths import get_reports_dir_for_date
        
        if output_path is None:
            date_str = datetime.now().strftime("%Y-%m-%d")
            reports_dir = get_reports_dir_for_date(date_str)
            run_folder = reports_dir / f"run_{self.run_id.replace('red_team_', '')}"
            run_folder.mkdir(parents=True, exist_ok=True)
            output_path = str(run_folder / "security_report.json")
        
        with open(output_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        
        self.logger.info(f"Report saved to {output_path}")
        return output_path
    
    def cleanup(self) -> None:
        """Cleanup resources."""
        self.browser_tool.close()
        self.obs.shutdown()


def scan(url: str, **kwargs) -> ScanReport:
    """Convenience function to scan a URL.
    
    Args:
        url: Target URL to scan
        **kwargs: Additional arguments passed to RedTeamAgent
        
    Returns:
        ScanReport with findings
        
    Example:
        report = scan("https://example.com")
        print(f"Found {report.total_findings} vulnerabilities")
    """
    agent = RedTeamAgent(**kwargs)
    try:
        return agent.scan(url)
    finally:
        agent.cleanup()
