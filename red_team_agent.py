"""
LangChain Red-Teaming Agent for Web Security

This agent performs security testing and red-teaming on web pages by:
- Testing for XSS (Cross-Site Scripting) vulnerabilities
- Testing for SQL injection vulnerabilities
- Testing for CSRF (Cross-Site Request Forgery) vulnerabilities
- Testing authentication and authorization mechanisms
- Testing input validation and sanitization
- Analyzing HTML/JavaScript for security issues
- Generating comprehensive security reports
"""

import os
import logging
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Callable
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain.tools import BaseTool
from langchain_core.tools import StructuredTool
from langchain_core.messages import HumanMessage, SystemMessage
import json
from datetime import datetime
import requests

from tools.tool_factory import RedTeamToolFactory
from tools.tool_loader import load_essential_tools, load_advanced_tools, load_all_tools
from core.run_directory import setup_run_directory, _current_run_dir
from core.logging_setup import setup_file_logging
from core.llm_setup import initialize_llm
from core.test_runner import TestRunner
from core.report_generator import ReportGenerator

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Try importing LLM providers
try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None

try:
    from langchain_anthropic import ChatAnthropic
except ImportError:
    ChatAnthropic = None


def setup_run_directory(base_dir: str = "runs") -> Path:
    """
    Create a unique run directory based on timestamp.
    
    Args:
        base_dir: Base directory for runs (default: "runs")
    
    Returns:
        Path to the created run directory
    """
    global _current_run_dir
    
    # Create base runs directory if it doesn't exist
    base_path = Path(base_dir)
    base_path.mkdir(exist_ok=True)
    
    # Create timestamp-based directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"run_{timestamp}"
    run_dir = base_path / run_id
    run_dir.mkdir(exist_ok=True)
    
    # Create subdirectories
    (run_dir / "logs").mkdir(exist_ok=True)
    (run_dir / "reports").mkdir(exist_ok=True)
    
    _current_run_dir = run_dir
    return run_dir


def setup_file_logging(run_dir: Path) -> None:
    """
    Set up file logging for the current run with separate files for each log level.
    
    Args:
        run_dir: Path to the run directory
    """
    global logger
    
    # Remove existing file handlers
    for handler in logger.handlers[:]:
        if isinstance(handler, logging.FileHandler):
            logger.removeHandler(handler)
    
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(exist_ok=True)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # DEBUG log - DEBUG level only (most verbose, includes function names and line numbers)
    debug_handler = logging.FileHandler(logs_dir / "debug.log", mode='w')
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(detailed_formatter)
    debug_handler.addFilter(lambda record: record.levelno == logging.DEBUG)
    logger.addHandler(debug_handler)
    
    # INFO log - INFO level only (normal operation)
    info_handler = logging.FileHandler(logs_dir / "info.log", mode='w')
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(simple_formatter)
    info_handler.addFilter(lambda record: record.levelno == logging.INFO)
    logger.addHandler(info_handler)
    
    # WARNING log - WARNING level only (unexpected conditions, security issues)
    warning_handler = logging.FileHandler(logs_dir / "warnings.log", mode='w')
    warning_handler.setLevel(logging.WARNING)
    warning_handler.setFormatter(simple_formatter)
    warning_handler.addFilter(lambda record: record.levelno == logging.WARNING)
    logger.addHandler(warning_handler)
    
    # ERROR log - ERROR and CRITICAL only (failures, exceptions)
    error_handler = logging.FileHandler(logs_dir / "errors.log", mode='w')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    error_handler.addFilter(lambda record: record.levelno >= logging.ERROR)
    logger.addHandler(error_handler)
    
    # Combined log - all messages (for convenience)
    all_handler = logging.FileHandler(logs_dir / "agent.log", mode='w')
    all_handler.setLevel(logging.DEBUG)
    all_handler.setFormatter(simple_formatter)
    logger.addHandler(all_handler)
    
    logger.info(f"Logging configured - separate log files created in: {logs_dir}")
    logger.debug("DEBUG logging enabled with detailed formatter")


class RedTeamAgent:
    """A LangChain-based agent for red-teaming web pages."""
    
    # ============================================================================
    # INITIALIZATION & SETUP
    # ============================================================================
    
    def __init__(
        self,
        target_url: str,
        provider: str = "openrouter",
        model_name: Optional[str] = None,
        temperature: float = 0.7,
        api_key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        run_dir: Optional[Path] = None
    ):
        """
        Initialize the Red-Teaming Agent for web security testing.
        
        Args:
            target_url: The URL of the web page to test
            provider: LLM provider ('openrouter', 'anthropic', or 'openai')
            model_name: The model to use (defaults based on provider)
            temperature: Temperature for the LLM
            api_key: API key (or set OPENROUTER_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY env var)
            headers: Optional HTTP headers to include in requests
            cookies: Optional cookies to include in requests
            run_dir: Optional run directory (if None, uses global _current_run_dir)
        """
        # Store basic configuration
        self.provider = provider.lower()
        self.target_url = target_url
        self.run_dir = run_dir or _current_run_dir
        self.advanced_tools_enabled = False  # Advanced tools disabled by default
        
        logger.info(f"Initializing RedTeamAgent for target URL: {target_url}")
        logger.info(f"Using provider: {self.provider}")
        if self.run_dir:
            logger.info(f"Run directory: {self.run_dir}")
        
        # Store API key for reference
        import os
        if self.provider == "openrouter":
            self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        elif self.provider == "anthropic":
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        elif self.provider == "openai":
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        
        # Initialize LLM based on provider
        self.llm, model_name = initialize_llm(
            provider=self.provider,
            model_name=model_name,
            temperature=temperature,
            api_key=self.api_key
        )
        
        # Initialize HTTP session
        self.headers = headers or {"User-Agent": "RedTeamAgent/1.0"}
        self.cookies = cookies or {}
        self.test_results: List[Dict[str, Any]] = []
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)
        
        logger.info(f"Created session with {len(self.headers)} headers and {len(self.cookies)} cookies")
        
        # Initialize trail logging
        self._initialize_trail_logging(target_url, model_name)
        
        # Create tools and agent
        self.tools, self.tool_functions = self._create_tools()
        logger.info(f"Created {len(self.tools)} essential tools for the agent")
        
        self.agent = self._create_agent()
        logger.info("RedTeamAgent initialized successfully")
    
    def _switch_to_anthropic(self) -> None:
        """
        Switch provider from OpenRouter to Anthropic when 402 error occurs.
        Reinitializes LLM and recreates the agent.
        """
        if self.provider == "openrouter":
            logger.warning("OpenRouter returned 402 (insufficient credits). Switching to Anthropic provider...")
            self.provider = "anthropic"
            
            # Get Anthropic API key
            import os
            anthropic_key = os.getenv("ANTHROPIC_API_KEY")
            if not anthropic_key:
                raise ValueError(
                    "Cannot switch to Anthropic: ANTHROPIC_API_KEY not found in environment. "
                    "Please set ANTHROPIC_API_KEY environment variable."
                )
            
            # Reinitialize LLM with Anthropic
            self.llm, model_name = initialize_llm(
                provider="anthropic",
                model_name=None,  # Use default Anthropic model
                temperature=0.7,
                api_key=anthropic_key
            )
            
            # Recreate agent with new LLM
            self.agent = self._create_agent()
            
            logger.info(f"Successfully switched to Anthropic provider (model: {model_name})")
            self.log_trail("provider_switched", {
                "from": "openrouter",
                "to": "anthropic",
                "reason": "402_insufficient_credits",
                "model": model_name
            }, "Switched from OpenRouter to Anthropic due to insufficient credits")
        else:
            logger.warning(f"Provider switch requested but current provider is {self.provider}, not openrouter")
    
    def _initialize_trail_logging(self, target_url: str, model_name: str) -> None:
        """Initialize trail logging for agent actions."""
        self.trail_entries: List[Dict[str, Any]] = []
        self.trail_file = None
        
        if self.run_dir:
            trail_path = self.run_dir / "reports" / "trail.jsonl"
            trail_path.parent.mkdir(parents=True, exist_ok=True)
            self.trail_file = open(trail_path, 'w', encoding='utf-8')
            self.log_trail("agent_initialized", {
                "target_url": target_url,
                "provider": self.provider,
                "model": model_name,
                "headers_count": len(self.headers),
                "cookies_count": len(self.cookies)
            }, "RedTeamAgent initialized and ready for testing")
    
    # ============================================================================
    # TOOL CREATION
    # ============================================================================
        
    def _create_tools(self) -> Tuple[List[BaseTool], Dict[str, Callable]]:
        """Create tools for the web security red-teaming agent.
        
        Returns:
            Tuple of (list of tools, dict mapping tool names to functions)
        """
        # Create tool factory with shared dependencies
        tool_factory = RedTeamToolFactory(
            session=self.session,
            test_results=self.test_results,
            target_url=self.target_url,
            headers=self.headers,
            cookies=self.cookies,
            log_trail=self.log_trail
        )
        
        # Load only essential tools by default (top 5)
        # Advanced tools can be enabled with enable_advanced_tools()
        all_tools = load_essential_tools(tool_factory)
        
        # Tool descriptions for LangChain agent (only essential tools shown by default)
        tool_descriptions = {
            # Essential Tools (Top 5)
            "fetch_page": "Fetch a web page and extract forms, links, and metadata. Input: url (the URL to fetch)",
            "scan_with_nuclei": "Scan target with Nuclei - fast vulnerability scanner with 10,000+ templates. Input: url (the URL to scan), template_tags (optional comma-separated tags like 'xss,sqli')",
            "scan_with_sqlmap": "Scan target with SQLMap - automated SQL injection testing. Input: url (the URL to test), parameter (optional parameter name to test specifically)",
            "scan_xss_with_dalfox": "Scan for XSS vulnerabilities using Dalfox - advanced XSS scanner. Input: url (the URL to test), parameter (optional parameter name to test)",
            "generate_report": "Generate a comprehensive security report of all tests performed",
            
            # Advanced Tools (only available when enable_advanced_tools() is called)
            "analyze_response_security": "Analyze HTTP response for security issues like exposed sensitive data. Input: response_text (the response HTML/text to analyze)",
            "scan_xss_with_xsstrike": "Scan for XSS vulnerabilities using XSStrike. Input: url (the URL to test)",
            "scan_with_owasp_zap": "Scan target with OWASP ZAP - comprehensive web app scanner. Input: url (the URL to scan), zap_proxy (optional ZAP proxy URL, default: http://127.0.0.1:8080)",
            "scan_with_nikto": "Scan web server with Nikto - web server vulnerability scanner. Input: url (the URL to scan)",
            "scan_with_wapiti": "Scan web application with Wapiti - web vulnerability scanner. Input: url (the URL to scan)",
            "discover_subdomains": "Discover subdomains using subfinder and amass. Input: domain (the domain to enumerate subdomains for)",
            "discover_with_theharvester": "Discover emails, subdomains, and people using theHarvester. Input: domain (the domain to search), sources (comma-separated sources, default: 'all')",
            "discover_parameters": "Discover URL parameters using ParamSpider and Arjun. Input: url (the URL to discover parameters for)",
            "brute_force_directories": "Brute force directories/files using Gobuster or FFuF. Input: url (the base URL to brute force), wordlist (optional path to wordlist file)",
            "scan_with_wfuzz": "Fuzz parameters with Wfuzz - powerful web fuzzer. Input: url (the URL to fuzz), parameter (parameter name to fuzz), wordlist (optional path to wordlist file)",
            "scan_with_nmap": "Scan network target with Nmap - industry standard network mapper. Input: target (IP address or network range), scan_type (default, stealth, aggressive, vuln)",
            "scan_with_masscan": "Fast port scan with Masscan - ultra-fast port scanner. Input: target (IP address or network), ports (port range, default: '1-1000'), rate (scan rate, default: '1000')",
            "scan_with_rustscan": "Fast port scan with RustScan - modern fast port scanner. Input: target (IP address or network), ports (port range, default: '1-1000')",
            "bloodhound_ingest": "Collect data for BloodHound analysis - AD attack path mapping. Input: domain (the domain to collect data for), collection_method (default: 'all')",
            "crackmapexec_scan": "Scan with CrackMapExec - network pentesting framework for AD. Input: target (IP address or network range), scan_type (default: 'smb')",
            "metasploit_exploit": "Execute Metasploit exploit - industry standard exploitation framework. Input: target (target IP address), exploit (exploit module path), payload (optional payload, default: 'generic/shell_reverse_tcp')",
            "crack_password_hashcat": "Crack password hashes with Hashcat - fastest password recovery tool. Input: hash_file (path to hash file), wordlist (optional wordlist path), hash_type (hash type code, default: '0')",
            "crack_password_john": "Crack password hashes with John the Ripper - versatile password cracker. Input: hash_file (path to hash file), wordlist (optional wordlist path)",
            "brute_force_login_hydra": "Brute force login with Hydra - network login cracker. Input: target (target IP or hostname), service (service name like 'ssh', 'ftp', 'http'), username (username to test), password_list (optional password list path)",
            "linpeas_scan": "Run LinPEAS privilege escalation scan - Linux privilege escalation checker. Input: target (target IP address). Note: LinPEAS must be run on the target system.",
            "winpeas_scan": "Run WinPEAS privilege escalation scan - Windows privilege escalation checker. Input: target (target IP address). Note: WinPEAS must be run on the target system.",
            "scan_api_rest_attacker": "Scan REST API with REST-Attacker - REST API security testing framework. Input: api_url (the API endpoint URL to test)",
            "scan_aws_pacu": "Scan AWS environment with Pacu - AWS exploitation framework. Input: aws_key (AWS access key), aws_secret (AWS secret key), region (AWS region, default: 'us-east-1')",
            "scan_cloud_scout_suite": "Scan cloud environment with Scout Suite - multi-cloud security auditing. Input: provider (cloud provider like 'aws', 'azure', 'gcp'), credentials (dictionary of credentials)",
        }
        
        # Create LangChain tools from all loaded tools
        tools = []
        for tool_name, tool_func in all_tools.items():
            if tool_name in tool_descriptions:
                tools.append(StructuredTool.from_function(
                    func=tool_func,
                    name=tool_name,
                    description=tool_descriptions[tool_name]
                ))
        
        # Create function mapping for direct execution
        tool_functions = all_tools.copy()
        
        return tools, tool_functions
    
    def _create_agent(self):
        """Create the LangChain agent with SOTA tools."""
        system_prompt = f"""You are a web security red-teaming expert testing web pages for vulnerabilities.

Your goal is to test the following web page: {self.target_url}

You should:
1. Fetch and analyze the target web page using fetch_page
2. Run comprehensive vulnerability scans using scan_with_nuclei
3. Test for SQL injection vulnerabilities using scan_with_sqlmap
4. Test for XSS vulnerabilities using scan_xss_with_dalfox
5. Document all findings and generate a comprehensive report using generate_report

Be thorough but ethical. Your goal is to improve security, not cause harm. Only test systems you have permission to test.

Available Essential Tools (Top 5):
1. fetch_page: Fetch a web page and extract forms, links, and metadata
2. scan_with_nuclei: Fast vulnerability scanner with 10,000+ templates - comprehensive coverage
3. scan_with_sqlmap: Automated SQL injection testing
4. scan_xss_with_dalfox: Advanced XSS vulnerability scanner
5. generate_report: Generate a comprehensive security report of all tests performed

Always think step by step:
1. First, fetch the target page to understand its structure
2. Run comprehensive scans with Nuclei for broad vulnerability coverage
3. Test specific vulnerabilities (SQLi with SQLMap, XSS with Dalfox)
4. Document vulnerabilities as you find them
5. **IMPORTANT**: At the end, you MUST call generate_report to create a comprehensive security report

**CRITICAL**: After completing all tests, you MUST call the generate_report tool to create a detailed security report. This is mandatory and should be the final step of your testing process.

Note: Advanced tools (network scanning, AD tools, password cracking, etc.) are available but disabled by default. Enable them with agent.enable_advanced_tools() if needed."""
        
        # Create agent using LangChain 1.0 API
        agent = create_agent(
            model=self.llm,
            tools=self.tools,
            system_prompt=system_prompt,
            debug=True
        )
        
        return agent
    
    def enable_advanced_tools(self) -> None:
        """
        Enable advanced tools (network scanning, AD tools, password cracking, etc.).
        This reloads tools and recreates the agent with all advanced tools available.
        
        Usage:
            agent = RedTeamAgent(target_url="https://example.com")
            agent.enable_advanced_tools()  # Now all tools are available
        """
        if self.advanced_tools_enabled:
            logger.info("Advanced tools already enabled")
            return
        
        logger.info("Enabling advanced tools...")
        self.advanced_tools_enabled = True
        
        # Reload tools with advanced ones
        tool_factory = RedTeamToolFactory(
            session=self.session,
            test_results=self.test_results,
            target_url=self.target_url,
            headers=self.headers,
            cookies=self.cookies,
            log_trail=self.log_trail
        )
        
        # Load essential + advanced tools
        essential_tools = load_essential_tools(tool_factory)
        advanced_tools = load_advanced_tools(tool_factory)
        all_tools = {**essential_tools, **advanced_tools}
        
        # Recreate tools and agent
        self.tools, self.tool_functions = self._create_tools_from_dict(all_tools)
        logger.info(f"Enabled advanced tools - Total tools: {len(self.tools)}")
        
        # Recreate agent with new tools
        self.agent = self._create_agent()
        logger.info("Agent recreated with advanced tools enabled")
    
    def _create_tools_from_dict(self, tools_dict: Dict[str, Callable]) -> Tuple[List[BaseTool], Dict[str, Callable]]:
        """Create LangChain tools from a dictionary of tool functions."""
        # Use existing tool descriptions logic
        tool_descriptions = {
            # Essential tools
            "fetch_page": "Fetch a web page and extract forms, links, and metadata. Input: url (the URL to fetch)",
            "scan_with_nuclei": "Scan target with Nuclei - fast vulnerability scanner with 10,000+ templates. Input: url (the URL to scan), template_tags (optional comma-separated tags like 'xss,sqli')",
            "scan_with_sqlmap": "Scan target with SQLMap - automated SQL injection testing. Input: url (the URL to test), parameter (optional parameter name to test specifically)",
            "scan_xss_with_dalfox": "Scan for XSS vulnerabilities using Dalfox - advanced XSS scanner. Input: url (the URL to test), parameter (optional parameter name to test)",
            "generate_report": "Generate a comprehensive security report of all tests performed",
            
            # Advanced tools
            "analyze_response_security": "Analyze HTTP response for security issues like exposed sensitive data. Input: response_text (the response HTML/text to analyze)",
            "scan_xss_with_xsstrike": "Scan for XSS vulnerabilities using XSStrike. Input: url (the URL to test)",
            "scan_with_owasp_zap": "Scan target with OWASP ZAP via API. Input: url (the URL to scan), zap_proxy (optional ZAP proxy URL)",
            "scan_with_nikto": "Scan web server with Nikto. Input: url (the URL to scan)",
            "scan_with_wapiti": "Scan web application with Wapiti. Input: url (the URL to scan)",
            "discover_subdomains": "Discover subdomains using subfinder and amass. Input: domain (the domain to discover subdomains for)",
            "discover_with_theharvester": "Discover emails, subdomains, and people using theHarvester. Input: domain (the domain to discover), sources (optional, default 'all')",
            "discover_parameters": "Discover URL parameters using ParamSpider and Arjun. Input: url (the URL to discover parameters for)",
            "brute_force_directories": "Brute force directories/files using Gobuster or FFuF. Input: url (the URL to brute force), wordlist (optional wordlist path)",
            "scan_with_wfuzz": "Fuzz parameters with Wfuzz. Input: url (the URL to fuzz), parameter (the parameter name), wordlist (optional wordlist path)",
            "scan_with_nmap": "Scan network target with Nmap. Input: target (IP or hostname), scan_type (optional: 'default', 'stealth', 'aggressive', 'vuln')",
            "scan_with_masscan": "Fast port scan with Masscan. Input: target (IP or hostname), ports (optional, default '1-1000'), rate (optional, default '1000')",
            "scan_with_rustscan": "Fast port scan with RustScan. Input: target (IP or hostname), ports (optional, default '1-1000')",
            "bloodhound_ingest": "Collect data for BloodHound analysis. Input: domain (the domain), collection_method (optional, default 'all')",
            "crackmapexec_scan": "Scan with CrackMapExec. Input: target (the target), scan_type (optional, default 'smb')",
            "metasploit_exploit": "Execute Metasploit exploit. Input: target (the target), exploit (the exploit path), payload (optional)",
            "crack_password_hashcat": "Crack password hashes with Hashcat. Input: hash_file (path to hash file), hash_type (hash type code), wordlist (optional)",
            "crack_password_john": "Crack password hashes with John the Ripper. Input: hash_file (path to hash file), wordlist (optional)",
            "brute_force_login_hydra": "Brute force login with Hydra. Input: target (the target), service (service type like 'ssh', 'http'), username (username to test), password_list (optional)",
        }
        
        tools = []
        tool_functions = {}
        
        for tool_name, tool_func in tools_dict.items():
            description = tool_descriptions.get(tool_name, f"Tool: {tool_name}")
            
            tool = StructuredTool.from_function(
                func=tool_func,
                name=tool_name,
                description=description
            )
            tools.append(tool)
            tool_functions[tool_name] = tool_func
        
        return tools, tool_functions
    
    # ============================================================================
    # LLM CONNECTION
    # ============================================================================
    
    def _test_llm_connection(self) -> bool:
        """Test if LLM connection works."""
        try:
            # Quick test with minimal tokens
            test_response = self.llm.invoke("OK")
            if test_response and hasattr(test_response, 'content'):
                logger.info("✓ LLM connection test successful")
                return True
            return False
        except Exception as e:
            logger.error(f"LLM connection test failed: {str(e)}")
            return False
    
    # ============================================================================
    # TEST EXECUTION
    # ============================================================================
    
    def run_test_suite(self, test_scenarios: Optional[List[str]] = None) -> str:
        """
        Run a comprehensive web security test suite.
        
        Args:
            test_scenarios: Optional list of specific scenarios to test
        
        Returns:
            Security report as string
        """
        logger.info("=" * 60)
        logger.info("Starting Red Team test suite")
        logger.info(f"Target URL: {self.target_url}")
        logger.info("=" * 60)
        
        self.log_trail("test_suite_started", {
            "target_url": self.target_url,
            "timestamp": datetime.now().isoformat()
        }, "Starting comprehensive web security test suite")
        
        if test_scenarios is None:
            test_scenarios = [
                f"Fetch and analyze the target page: {self.target_url}",
                f"Run comprehensive vulnerability scan with Nuclei on {self.target_url}",
                f"Test for XSS vulnerabilities using Dalfox and XSStrike on {self.target_url}",
                f"Test for SQL injection vulnerabilities using SQLMap on {self.target_url}",
                f"Discover URL parameters using ParamSpider and Arjun for {self.target_url}",
                f"Analyze responses for security headers and sensitive data exposure",
            ]
        
        self.log_trail("test_scenarios_defined", {
            "scenarios": test_scenarios,
            "count": len(test_scenarios)
        }, f"Defined {len(test_scenarios)} test scenarios to execute")
        
        # Test LLM connection - required for execution
        llm_works = self._test_llm_connection()
        
        if not llm_works:
            error_msg = f"LLM connection failed. Cannot proceed without LLM agent. Please check your API key and provider configuration."
            logger.error(error_msg)
            self.log_trail("llm_connection_failed", {
                "provider": self.provider
            }, error_msg)
            raise RuntimeError(error_msg)
        
        self.log_trail("execution_mode_selected", {
            "mode": "llm_agent",
            "provider": self.provider
        }, "Using LLM agent orchestration mode")
        
        logger.info(f"Running {len(test_scenarios)} test scenarios")
        
        failed_scenarios = []
        successful_scenarios = []
        
        for i, scenario in enumerate(test_scenarios, 1):
            logger.info(f"\n{'='*60}")
            logger.info(f"Test Scenario {i}/{len(test_scenarios)}: {scenario}")
            logger.info(f"{'='*60}")
            
            self.log_trail("scenario_started", {
                "scenario_number": i,
                "total_scenarios": len(test_scenarios),
                "scenario": scenario
            }, f"Starting test scenario {i}/{len(test_scenarios)}")
            
            # Execute via LLM agent only
            try:
                logger.debug(f"Invoking agent with scenario: {scenario[:100]}...")
                self.log_trail("agent_invoked", {
                    "scenario": scenario[:200],
                    "mode": "llm_agent"
                }, f"Invoking LLM agent to execute scenario: {scenario[:100]}...")
                result = self.agent.invoke({"messages": [("human", scenario)]})
                logger.info(f"Scenario {i} completed successfully")
                logger.debug(f"Result: {str(result)[:200]}...")
                self.log_trail("scenario_completed", {
                    "scenario_number": i,
                    "success": True
                }, f"Scenario {i} completed successfully via LLM agent")
                successful_scenarios.append(i)
            except BrokenPipeError as e:
                error_msg = f"Broken pipe error for scenario {i}: {str(e)[:200]}"
                logger.warning(error_msg)
                logger.warning("Continuing with remaining scenarios...")
                self.log_trail("scenario_failed", {
                    "scenario_number": i,
                    "error": "Broken pipe - connection interrupted",
                    "error_type": "BrokenPipeError"
                }, error_msg)
                failed_scenarios.append((i, "Broken pipe"))
            except Exception as e:
                error_str = str(e)
                error_msg = f"Agent failed for scenario {i}: {error_str[:200]}"
                
                # Check for 402 error (insufficient credits) from OpenRouter
                if "402" in error_str or ("insufficient credits" in error_str.lower() and self.provider == "openrouter"):
                    logger.warning("Detected 402 error (insufficient credits) from OpenRouter")
                    try:
                        self._switch_to_anthropic()
                        logger.info("Retrying scenario with Anthropic provider...")
                        # Retry the scenario with the new provider
                        result = self.agent.invoke({"messages": [("human", scenario)]})
                        logger.info(f"Scenario {i} completed successfully after provider switch")
                        self.log_trail("scenario_completed", {
                            "scenario_number": i,
                            "success": True,
                            "retried_with_anthropic": True
                        }, f"Scenario {i} completed successfully after switching to Anthropic")
                        successful_scenarios.append(i)
                        continue
                    except Exception as retry_error:
                        logger.error(f"Retry with Anthropic also failed: {str(retry_error)[:200]}")
                        error_msg = f"Agent failed for scenario {i} even after switching to Anthropic: {str(retry_error)[:200]}"
                        self.log_trail("scenario_failed", {
                            "scenario_number": i,
                            "error": str(retry_error)[:200],
                            "error_type": type(retry_error).__name__,
                            "provider_switch_attempted": True
                        }, error_msg)
                        failed_scenarios.append((i, str(retry_error)[:200]))
                else:
                    logger.warning(error_msg)
                    logger.warning("Continuing with remaining scenarios...")
                    self.log_trail("scenario_failed", {
                        "scenario_number": i,
                        "error": error_str[:200],
                        "error_type": type(e).__name__
                    }, error_msg)
                    failed_scenarios.append((i, error_str[:200]))
        
        # Log summary
        logger.info(f"\n{'='*60}")
        logger.info(f"Test Suite Summary:")
        logger.info(f"  Successful scenarios: {len(successful_scenarios)}/{len(test_scenarios)}")
        logger.info(f"  Failed scenarios: {len(failed_scenarios)}/{len(test_scenarios)}")
        if failed_scenarios:
            logger.info(f"  Failed scenario numbers: {[s[0] for s in failed_scenarios]}")
        logger.info(f"{'='*60}\n")
        
        # Generate final report via LLM agent - EXPLICITLY instruct to use generate_report tool
        logger.info("\nGenerating final comprehensive security report...")
        self.log_trail("report_generation_started", {
            "total_tests": len(self.test_results),
            "vulnerabilities_found": sum(1 for r in self.test_results if r.get('is_vulnerable', False))
        }, "Starting final report generation")
        
        try:
            # Explicitly instruct the agent to use the generate_report tool
            result = self.agent.invoke({
                "messages": [("human", """You MUST now generate a comprehensive security report by calling the generate_report tool.

This is the final and mandatory step. Use the generate_report tool to create a detailed report that includes:
- All vulnerabilities found (critical, high, medium, low)
- Detailed findings from all tools (Nuclei, SQLMap, Dalfox, etc.)
- Tool-specific results and outputs
- Risk assessment and recommendations
- Complete test results summary

Call generate_report now to complete the security assessment.""")]
            })
            logger.info("Report generation completed via agent")
        except Exception as e:
            error_str = str(e)
            # Check for 402 error (insufficient credits) from OpenRouter
            if "402" in error_str or ("insufficient credits" in error_str.lower() and self.provider == "openrouter"):
                logger.warning("Detected 402 error (insufficient credits) from OpenRouter during report generation")
                try:
                    self._switch_to_anthropic()
                    logger.info("Retrying report generation with Anthropic provider...")
                    # Retry report generation with Anthropic
                    result = self.agent.invoke({
                        "messages": [("human", """You MUST now generate a comprehensive security report by calling the generate_report tool.

This is the final and mandatory step. Use the generate_report tool to create a detailed report that includes:
- All vulnerabilities found (critical, high, medium, low)
- Detailed findings from all tools (Nuclei, SQLMap, Dalfox, etc.)
- Tool-specific results and outputs
- Risk assessment and recommendations
- Complete test results summary

Call generate_report now to complete the security assessment.""")]
                    })
                    logger.info("Report generation completed via agent after switching to Anthropic")
                except Exception as retry_error:
                    logger.error(f"Report generation failed even after switching to Anthropic: {str(retry_error)[:200]}")
                    raise retry_error
            else:
                raise
        
        # Extract the report from the result - check if generate_report tool was called
            report = None
            if isinstance(result, dict):
                if "messages" in result:
                    # Look for tool message with generate_report result
                    for msg in reversed(result["messages"]):
                        if hasattr(msg, "name") and msg.name == "generate_report":
                            if hasattr(msg, "content"):
                                report = msg.content
                                logger.info("Found report from generate_report tool call")
                                break
                    
                    # Fallback: get last message content
                    if not report:
                        last_message = result["messages"][-1]
                        if hasattr(last_message, "content"):
                            report = last_message.content
                        else:
                            report = str(last_message)
                else:
                    report = str(result.get("output", result))
            else:
                report = str(result)
            
            # If report doesn't contain expected content, generate it directly
            if not report or len(report) < 100:
                logger.warning("Agent report seems incomplete, generating report directly via tool")
                if 'generate_report' in self.tool_functions:
                    report = self.tool_functions['generate_report']()
                    logger.info("Generated report directly via generate_report tool")
                else:
                    logger.warning("generate_report tool not available, using fallback")
                    report_generator = ReportGenerator(self.target_url, self.test_results, self.run_dir)
                    report = report_generator.generate_manual_report()
            
            self.log_trail("report_generated", {
                "method": "llm_agent",
                "success": True,
                "report_length": len(report) if report else 0
            }, f"Report generated successfully via LLM agent ({len(report) if report else 0} characters)")
            
            # Always save the main report to file
            if self.run_dir and report:
                try:
                    report_path = self.run_dir / "reports" / "red_team_report.md"
                    with open(report_path, 'w', encoding='utf-8') as f:
                        f.write(report)
                    logger.info(f"Main security report saved to: {report_path}")
                except Exception as e:
                    logger.error(f"Error saving main report: {str(e)}")
            
            # Generate and save detailed action report
            if self.run_dir:
                try:
                    report_generator = ReportGenerator(self.target_url, self.test_results, self.run_dir)
                    detailed_report = report_generator.generate_detailed_action_report(self.trail_entries)
                    detailed_path = self.run_dir / "reports" / "detailed_action_report.md"
                    with open(detailed_path, 'w', encoding='utf-8') as f:
                        f.write(detailed_report)
                    logger.info(f"Detailed action report saved to: {detailed_path}")
                    self.log_trail("detailed_report_generated", {
                        "format": "markdown",
                        "path": str(detailed_path),
                        "total_actions": len(self.trail_entries),
                        "total_tool_calls": len([e for e in self.trail_entries if e.get('action_type') == 'tool_call'])
                    }, "Generated detailed action report with complete execution trail")
                except Exception as e:
                    logger.error(f"Error generating detailed action report: {str(e)}")
                    logger.exception(e)
            
            # Close trail before returning
            self.close_trail()
            return report
        except Exception as e:
            error_msg = f"Error generating report via agent: {str(e)[:200]}"
            logger.error(error_msg)
            self.log_trail("report_generation_failed", {
                "error": str(e)[:200]
            }, error_msg)
            # Fallback to manual report if LLM report generation fails
            logger.warning("Falling back to manual report generation")
            report = self._generate_manual_report()
            
            # Still generate detailed action report even if main report failed
            if self.run_dir:
                try:
                    detailed_report = self._generate_detailed_action_report()
                    detailed_path = self.run_dir / "reports" / "detailed_action_report.md"
                    with open(detailed_path, 'w', encoding='utf-8') as f:
                        f.write(detailed_report)
                    logger.info(f"Detailed action report saved to: {detailed_path}")
                except Exception as e:
                    logger.error(f"Error generating detailed action report: {str(e)}")
                    logger.exception(e)
            
            self.close_trail()
            return report
    
    # ============================================================================
    # TEST EXECUTION
    # ============================================================================
    
    def test_single_url(self, url: str, test_type: str = "xss") -> Dict[str, Any]:
        """
        Test a single URL for vulnerabilities.
        
        Args:
            url: The URL to test
            test_type: Type of test ('xss', 'sql', 'both')
        
        Returns:
            Test results
        """
        logger.info(f"Testing single URL: {url} (test_type: {test_type})")
        results = {}
        if test_type in ["xss", "both"]:
            logger.info(f"Running XSS test on {url}")
            try:
                result = self.agent.invoke({
                    "messages": [("human", f"Test this URL for XSS vulnerabilities: {url}")]
                })
                results["xss"] = result
                logger.info(f"XSS test completed for {url}")
            except Exception as e:
                logger.error(f"Error during XSS test on {url}: {str(e)}")
                results["xss"] = {"error": str(e)}
        
        if test_type in ["sql", "both"]:
            logger.info(f"Running SQL injection test on {url}")
            try:
                result = self.agent.invoke({
                    "messages": [("human", f"Test this URL for SQL injection vulnerabilities: {url}")]
                })
                results["sql"] = result
                logger.info(f"SQL injection test completed for {url}")
            except Exception as e:
                logger.error(f"Error during SQL injection test on {url}: {str(e)}")
                results["sql"] = {"error": str(e)}
        
        logger.info(f"Single URL test completed for {url}")
        return results
    
    # ============================================================================
    # REPORTING
    # ============================================================================
    # Report generation methods have been moved to core.report_generator.ReportGenerator
    # This section kept for backward compatibility references only
    
    def _generate_manual_report(self) -> str:
        """DEPRECATED: Use ReportGenerator.generate_manual_report() instead."""
        report_generator = ReportGenerator(self.target_url, self.test_results, self.run_dir)
        return report_generator.generate_manual_report()
    
    def _generate_detailed_action_report(self) -> str:
        """DEPRECATED: Use ReportGenerator.generate_detailed_action_report() instead."""
        report_generator = ReportGenerator(self.target_url, self.test_results, self.run_dir)
        return report_generator.generate_detailed_action_report(self.trail_entries)
    
    def _generate_json_report(self) -> Dict[str, Any]:
        """DEPRECATED: Use ReportGenerator.generate_json_report() instead."""
        report_generator = ReportGenerator(self.target_url, self.test_results, self.run_dir)
        return report_generator.generate_json_report()
    
    # ============================================================================
    # UTILITIES
    # ============================================================================
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get all test results."""
        return self.test_results
    
    def log_trail(self, action_type: str, data: Dict[str, Any], reasoning: Optional[str] = None) -> None:
        """
        Log an entry to the trail file.
        
        Args:
            action_type: Type of action (e.g., 'tool_call', 'test_executed', 'decision_made')
            data: Dictionary containing action data
            reasoning: Optional explanation of why this action was taken
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action_type": action_type,
            "data": data,
            "reasoning": reasoning
        }
        self.trail_entries.append(entry)
        
        if self.trail_file:
            self.trail_file.write(json.dumps(entry, ensure_ascii=False) + '\n')
            self.trail_file.flush()
    
    def close_trail(self) -> None:
        """Close the trail file."""
        if self.trail_file:
            self.trail_file.close()
            self.trail_file = None


def main():
    """Example usage of the Web Security Red-Teaming Agent."""
    import argparse
    
    parser = argparse.ArgumentParser(description="LangChain Web Security Red-Teaming Agent")
    parser.add_argument(
        "--url",
        type=str,
        required=True,
        help="URL of the web page to test"
    )
    parser.add_argument(
        "--provider",
        type=str,
        choices=["openrouter", "anthropic", "openai"],
        default="openrouter",
        help="LLM provider to use (default: openrouter)"
    )
    parser.add_argument(
        "--model",
        type=str,
        help="Model to use (defaults based on provider: openrouter='anthropic/claude-3.5-sonnet', anthropic='claude-3-5-sonnet-20241022', openai='gpt-4')"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        help="Single test scenario to run"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output file for the report",
        default="red_team_report.md"
    )
    parser.add_argument(
        "--headers",
        type=str,
        help="JSON string of custom headers to include in requests"
    )
    
    args = parser.parse_args()
    
    # Create run directory with unique timestamp ID
    run_dir = setup_run_directory()
    run_id = run_dir.name
    print(f"\n{'='*60}")
    print(f"Starting Red-Team Run: {run_id}")
    print(f"Run Directory: {run_dir}")
    print(f"{'='*60}\n")
    
    # Set up file logging
    setup_file_logging(run_dir)
    
    # Parse headers if provided
    headers = None
    if args.headers:
        try:
            headers = json.loads(args.headers)
        except json.JSONDecodeError:
            print("Warning: Invalid JSON for headers, ignoring")
    
    # Initialize agent
    print(f"Initializing Web Security Red-Teaming Agent for: {args.url}")
    print(f"Using provider: {args.provider}")
    if args.model:
        print(f"Using model: {args.model}")
    
    agent = RedTeamAgent(
        target_url=args.url,
        provider=args.provider,
        model_name=args.model,
        headers=headers,
        run_dir=run_dir
    )
    
    # Run tests
    if args.scenario:
            print(f"\nRunning single test: {args.scenario}")
            try:
                result = agent.agent.invoke({
                    "messages": [("human", args.scenario)]
                })
                print(f"\nResult: {result}")
            except Exception as e:
                error_str = str(e)
                # Check for 402 error (insufficient credits) from OpenRouter
                if "402" in error_str or ("insufficient credits" in error_str.lower() and agent.provider == "openrouter"):
                    logger.warning("Detected 402 error (insufficient credits) from OpenRouter")
                    try:
                        agent._switch_to_anthropic()
                        logger.info("Retrying with Anthropic provider...")
                        result = agent.agent.invoke({
                            "messages": [("human", args.scenario)]
                        })
                        print(f"\nResult (after switching to Anthropic): {result}")
                    except Exception as retry_error:
                        print(f"\nError (even after switching to Anthropic): {retry_error}")
                else:
                    print(f"\nError: {e}")
    else:
        print("\nRunning comprehensive web security test suite...")
        try:
            report = agent.run_test_suite()
        except Exception as e:
            logger.error(f"Test suite failed: {str(e)}")
            logger.warning("Generating report from partial results...")
            report = None
        
        # Ensure report was generated (fallback if agent didn't call generate_report)
        if not report or len(report) < 100:
            logger.warning("Report seems incomplete, generating comprehensive report directly")
            if 'generate_report' in agent.tool_functions:
                try:
                    report = agent.tool_functions['generate_report']()
                    logger.info("Generated comprehensive report directly")
                except Exception as e:
                    error_str = str(e)
                    # Check for 402 error (insufficient credits) from OpenRouter
                    if "402" in error_str or ("insufficient credits" in error_str.lower() and agent.provider == "openrouter"):
                        logger.warning("Detected 402 error (insufficient credits) from OpenRouter during report generation")
                        try:
                            agent._switch_to_anthropic()
                            logger.info("Retrying report generation with Anthropic provider...")
                            report = agent.tool_functions['generate_report']()
                            logger.info("Generated comprehensive report directly after switching to Anthropic")
                        except Exception as retry_error:
                            logger.error(f"Error generating report via tool (even after switching to Anthropic): {str(retry_error)}")
                            report = agent._generate_manual_report()
                    else:
                        logger.error(f"Error generating report via tool: {str(e)}")
                        report = agent._generate_manual_report()
            else:
                report = agent._generate_manual_report()
        
        # Save report to run directory
        if args.output:
            # If output is specified, save to both run directory and specified location
            report_filename = Path(args.output).name
            run_report_path = run_dir / "reports" / report_filename
            with open(run_report_path, "w") as f:
                f.write(report)
            
            # Also save to specified location if different
            if Path(args.output) != run_report_path:
                with open(args.output, "w") as f:
                    f.write(report)
            
            print(f"\n{'='*60}")
            print(f"Reports saved to:")
            print(f"  - Security Report: {run_report_path}")
            print(f"  - Detailed Action Report: {run_dir / 'reports' / 'detailed_action_report.md'}")
            print(f"  - JSON Report: {run_dir / 'reports' / 'red_team_report.json'}")
            print(f"  - Action Trail: {run_dir / 'reports' / 'trail.jsonl'}")
            if Path(args.output) != run_report_path:
                print(f"  - Specified location: {args.output}")
            print(f"{'='*60}")
        else:
            # Default: save to run directory
            report_filename = f"security_report_{run_id}.md"
            run_report_path = run_dir / "reports" / report_filename
            with open(run_report_path, "w") as f:
                f.write(report)
            
            print(f"\n{'='*60}")
            print(f"Reports saved to:")
            print(f"  - Security Report: {run_report_path}")
            print(f"  - Detailed Action Report: {run_dir / 'reports' / 'detailed_action_report.md'}")
            print(f"  - JSON Report: {run_dir / 'reports' / 'red_team_report.json'}")
            print(f"  - Action Trail: {run_dir / 'reports' / 'trail.jsonl'}")
            print(f"{'='*60}")
        
        # Save run metadata
        metadata = {
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "target_url": args.url,
            "provider": args.provider,
            "model": args.model or "default",
            "total_tests": len(agent.test_results),
            "vulnerabilities_found": sum(1 for r in agent.test_results if r.get('is_vulnerable', False)),
            "run_directory": str(run_dir),
            "reports": {
                "security_report": str(run_dir / "reports" / report_filename if args.output else run_dir / "reports" / f"security_report_{run_id}.md"),
                "detailed_action_report": str(run_dir / "reports" / "detailed_action_report.md"),
                "json_report": str(run_dir / "reports" / "red_team_report.json"),
                "action_trail": str(run_dir / "reports" / "trail.jsonl")
            }
        }
        
        metadata_path = run_dir / "metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        print(f"\nRun Summary:")
        print(f"  - Run ID: {run_id}")
        print(f"  - Total tests: {metadata['total_tests']}")
        print(f"  - Vulnerabilities found: {metadata['vulnerabilities_found']}")
        print(f"  - Logs: {run_dir / 'logs' / 'agent.log'}")
        print(f"  - Reports directory: {run_dir / 'reports'}")
        print(f"    * Security Report (Markdown)")
        print(f"    * Detailed Action Report (Markdown)")
        print(f"    * JSON Report")
        print(f"    * Action Trail (JSONL)")
        print(f"  - Metadata: {metadata_path}")


if __name__ == "__main__":
    main()

