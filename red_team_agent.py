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
from tools.tool_loader import load_all_tools

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
    
    # DEBUG log - DEBUG and above (most verbose)
    debug_handler = logging.FileHandler(logs_dir / "agent.debug", mode='w')
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(detailed_formatter)
    logger.addHandler(debug_handler)
    
    # INFO log - INFO and above (normal operation + errors)
    info_handler = logging.FileHandler(logs_dir / "agent.info", mode='w')
    info_handler.setLevel(logging.INFO)
    info_handler.setFormatter(simple_formatter)
    logger.addHandler(info_handler)
    
    # WARNING log - WARNING and above (security issues, errors)
    warning_handler = logging.FileHandler(logs_dir / "agent.warning", mode='w')
    warning_handler.setLevel(logging.WARNING)
    warning_handler.setFormatter(simple_formatter)
    logger.addHandler(warning_handler)
    
    # ERROR log - ERROR and CRITICAL only (failures, exceptions)
    error_handler = logging.FileHandler(logs_dir / "agent.error", mode='w')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    logger.addHandler(error_handler)
    
    # Ensure the logger captures everything so handlers can filter it
    logger.setLevel(logging.DEBUG)
    
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
        
        logger.info(f"Initializing RedTeamAgent for target URL: {target_url}")
        logger.info(f"Using provider: {self.provider}")
        if self.run_dir:
            logger.info(f"Run directory: {self.run_dir}")
        
        # Initialize LLM based on provider
        self.llm, model_name = self._initialize_llm(
            provider=self.provider,
            model_name=model_name,
            temperature=temperature,
            api_key=api_key
        )
        
        # Initialize HTTP session
        self.headers = headers or {"User-Agent": "RedTeamAgent/1.0"}
        self.cookies = cookies or {}
        self.test_results: List[Dict[str, Any]] = []
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)
        
        logger.debug(f"Created session with {len(self.headers)} headers and {len(self.cookies)} cookies")
        
        # Initialize trail logging
        self._initialize_trail_logging(target_url, model_name)
        
        # Create tools and agent
        self.tools, self.tool_functions = self._create_tools()
        logger.debug(f"Created {len(self.tools)} tools for the agent")
        
        self.agent = self._create_agent()
        logger.info("RedTeamAgent initialized successfully")
    
    def _initialize_llm(
        self,
        provider: str,
        model_name: Optional[str],
        temperature: float,
        api_key: Optional[str]
    ) -> Tuple[Any, str]:
        """
        Initialize the LLM based on the specified provider.
        
        Returns:
            Tuple of (llm instance, model_name used)
        """
        if provider == "openrouter":
            self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
            if not self.api_key:
                raise ValueError(
                    "OpenRouter API key required. Set OPENROUTER_API_KEY env var "
                    "or pass api_key parameter."
                )
            default_model = "anthropic/claude-3.5-sonnet"
            model_name = model_name or default_model
            
            if ChatOpenAI is None:
                raise ImportError(
                    "langchain-openai is required for OpenRouter support. "
                    "Install with: pip install langchain-openai"
                )
            
            llm = ChatOpenAI(
                model=model_name,
                temperature=temperature,
                api_key=self.api_key,
                base_url="https://openrouter.ai/api/v1",
                default_headers={
                    "HTTP-Referer": "https://github.com/shayahal/vibe-code-bench",
                    "X-Title": "Red-Team Agent"
                }
            )
            
        elif provider == "anthropic":
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
            if not self.api_key:
                raise ValueError(
                    "Anthropic API key required. Set ANTHROPIC_API_KEY env var "
                    "or pass api_key parameter."
                )
            default_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
            model_name = model_name or default_model
            
            # Check if custom base URL is provided (for custom endpoints like yovy.app)
            base_url = os.getenv("ANTHROPIC_BASE_URL")
            if base_url:
                if ChatOpenAI is None:
                    raise ImportError(
                        "langchain-openai is required for custom Anthropic endpoints. "
                        "Install with: pip install langchain-openai"
                    )
                
                # Remove quotes if present and ensure /v1 suffix
                base_url = base_url.strip('"\'')
                if not base_url.endswith('/v1') and not base_url.endswith('/v1/'):
                    base_url = f"{base_url}/v1" if not base_url.endswith('/') else f"{base_url}v1"
                
                logger.info(f"Using custom Anthropic base URL: {base_url}")
                llm = ChatOpenAI(
                    model=model_name,
                    temperature=temperature,
                    api_key=self.api_key,
                    base_url=base_url
                )
            else:
                if ChatAnthropic is None:
                    raise ImportError(
                        "langchain-anthropic is required. "
                        "Install with: pip install langchain-anthropic"
                    )
                
                llm = ChatAnthropic(
                    model=model_name,
                    temperature=temperature,
                    api_key=self.api_key
                )
            
        elif provider == "openai":
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
            if not self.api_key:
                raise ValueError(
                    "OpenAI API key required. Set OPENAI_API_KEY env var "
                    "or pass api_key parameter."
                )
            default_model = "gpt-4"
            model_name = model_name or default_model
            
            if ChatOpenAI is None:
                raise ImportError(
                    "langchain-openai is required. "
                    "Install with: pip install langchain-openai"
                )
            
            llm = ChatOpenAI(
                model=model_name,
                temperature=temperature,
                api_key=self.api_key
            )
        else:
            raise ValueError(
                f"Unknown provider: {provider}. "
                f"Supported providers: 'openrouter', 'anthropic', 'openai'"
            )
        
        return llm, model_name
    
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
        
        # Load all tools from category modules
        all_tools = load_all_tools(tool_factory)
        
        # Tool descriptions for LangChain agent
        tool_descriptions = {
            # Utility Tools
            "fetch_page": "Fetch a web page and extract forms, links, and metadata. Input: url (the URL to fetch)",
            "analyze_response_security": "Analyze HTTP response for security issues like exposed sensitive data. Input: response_text (the response HTML/text to analyze)",
            "generate_report": "Generate a comprehensive security report of all tests performed",
            
            # Web Application Security Tools (SOTA - Replaces custom XSS/SQLi tools)
            "scan_with_nuclei": "Scan target with Nuclei - fast vulnerability scanner with 10,000+ templates. Replaces custom vulnerability scanning. Input: url (the URL to scan), template_tags (optional comma-separated tags like 'xss,sqli')",
            "scan_with_sqlmap": "Scan target with SQLMap - automated SQL injection testing. Replaces custom SQL injection payload crafting. Input: url (the URL to test), parameter (optional parameter name to test specifically)",
            "scan_xss_with_dalfox": "Scan for XSS vulnerabilities using Dalfox. Replaces custom XSS payload crafting. Input: url (the URL to test), parameter (optional parameter name to test specifically)",
            "scan_xss_with_xsstrike": "Scan for XSS vulnerabilities using XSStrike. Replaces custom XSS testing. Input: url (the URL to test)",
            "scan_with_owasp_zap": "Scan target with OWASP ZAP - comprehensive web app scanner. Input: url (the URL to scan), zap_proxy (optional ZAP proxy URL, default: http://127.0.0.1:8080)",
            "scan_with_nikto": "Scan web server with Nikto - web server vulnerability scanner. Input: url (the URL to scan)",
            "scan_with_wapiti": "Scan web application with Wapiti - web vulnerability scanner. Input: url (the URL to scan)",
            
            # Network & Infrastructure Tools
            "scan_with_nmap": "Scan network target with Nmap - industry standard network mapper. Input: target (IP address or network range), scan_type (default, stealth, aggressive, vuln)",
            "scan_with_masscan": "Fast port scan with Masscan - ultra-fast port scanner. Input: target (IP address or network), ports (port range, default: '1-1000'), rate (scan rate, default: '1000')",
            "scan_with_rustscan": "Fast port scan with RustScan - modern fast port scanner. Input: target (IP address or network), ports (port range, default: '1-1000')",
            
            # Reconnaissance Tools
            "discover_subdomains": "Discover subdomains using subfinder and amass. Input: domain (the domain to enumerate subdomains for)",
            "discover_with_theharvester": "Discover emails, subdomains, and people using theHarvester. Input: domain (the domain to search), sources (comma-separated sources, default: 'all')",
            "discover_parameters": "Discover URL parameters using ParamSpider and Arjun. Input: url (the URL to discover parameters for)",
            
            # Directory & File Discovery
            "brute_force_directories": "Brute force directories/files using Gobuster or FFuF. Input: url (the base URL to brute force), wordlist (optional path to wordlist file)",
            
            # Fuzzing Tools
            "scan_with_wfuzz": "Fuzz parameters with Wfuzz - powerful web fuzzer. Input: url (the URL to fuzz), parameter (parameter name to fuzz), wordlist (optional path to wordlist file)",
            
            # Active Directory Tools
            "bloodhound_ingest": "Collect data for BloodHound analysis - AD attack path mapping. Input: domain (the domain to collect data for), collection_method (default: 'all')",
            "crackmapexec_scan": "Scan with CrackMapExec - network pentesting framework for AD. Input: target (IP address or network range), scan_type (default: 'smb')",
            
            # Exploitation Frameworks
            "metasploit_exploit": "Execute Metasploit exploit - industry standard exploitation framework. Input: target (target IP address), exploit (exploit module path), payload (optional payload, default: 'generic/shell_reverse_tcp')",
            
            # Password & Credential Tools
            "crack_password_hashcat": "Crack password hashes with Hashcat - fastest password recovery tool. Input: hash_file (path to hash file), wordlist (optional wordlist path), hash_type (hash type code, default: '0')",
            "crack_password_john": "Crack password hashes with John the Ripper - versatile password cracker. Input: hash_file (path to hash file), wordlist (optional wordlist path)",
            "brute_force_login_hydra": "Brute force login with Hydra - network login cracker. Input: target (target IP or hostname), service (service name like 'ssh', 'ftp', 'http'), username (username to test), password_list (optional password list path)",
            
            # Post-Exploitation Tools
            "linpeas_scan": "Run LinPEAS privilege escalation scan - Linux privilege escalation checker. Input: target (target IP address). Note: LinPEAS must be run on the target system.",
            "winpeas_scan": "Run WinPEAS privilege escalation scan - Windows privilege escalation checker. Input: target (target IP address). Note: WinPEAS must be run on the target system.",
            
            # API Security Tools
            "scan_api_rest_attacker": "Scan REST API with REST-Attacker - REST API security testing framework. Input: api_url (the API endpoint URL to test)",
            
            # Cloud Security Tools
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
2. Identify all forms, input fields, and URL parameters
3. Test for XSS vulnerabilities using SOTA tools (scan_xss_with_dalfox, scan_xss_with_xsstrike)
4. Test for SQL injection vulnerabilities using SOTA tools (scan_with_sqlmap)
5. Run comprehensive vulnerability scans using scan_with_nuclei
6. Discover subdomains and parameters using discover_subdomains and discover_parameters
7. Analyze responses for security headers and sensitive data exposure using analyze_response_security
8. Document all findings in a comprehensive report using generate_report

Be thorough but ethical. Your goal is to improve security, not cause harm. Only test systems you have permission to test.

Available SOTA Tools (State-of-the-Art):

Utility Tools:
- fetch_page: Fetch a web page and extract forms, links, and metadata
- analyze_response_security: Analyze HTTP response for security issues like exposed sensitive data
- generate_report: Generate a comprehensive security report of all tests performed

Web Application Security Tools (SOTA):
- scan_with_nuclei: Fast vulnerability scanner with 10,000+ templates. Replaces custom vulnerability scanning
- scan_with_sqlmap: Automated SQL injection testing. Replaces custom SQL injection payload crafting
- scan_xss_with_dalfox: Advanced XSS scanner. Replaces custom XSS payload crafting
- scan_xss_with_xsstrike: XSS vulnerability scanner. Replaces custom XSS testing
- scan_with_owasp_zap: Comprehensive web app scanner
- scan_with_nikto: Web server vulnerability scanner
- scan_with_wapiti: Web vulnerability scanner

Reconnaissance Tools:
- discover_subdomains: Discover subdomains using subfinder and amass
- discover_with_theharvester: Discover emails, subdomains, and people
- discover_parameters: Discover URL parameters using ParamSpider and Arjun

Directory & File Discovery:
- brute_force_directories: Brute force directories/files using Gobuster or FFuF

Fuzzing Tools:
- scan_with_wfuzz: Fuzz parameters with Wfuzz

Network & Infrastructure Tools:
- scan_with_nmap: Industry standard network mapper
- scan_with_masscan: Ultra-fast port scanner
- scan_with_rustscan: Modern fast port scanner

Always think step by step:
1. First, fetch the target page to understand its structure
2. Discover subdomains and parameters if needed
3. Run comprehensive scans with Nuclei for broad coverage
4. Test specific vulnerabilities (XSS with Dalfox/XSStrike, SQLi with SQLMap)
5. Analyze responses for security issues
6. Document vulnerabilities as you find them
7. Generate a comprehensive report at the end"""
        
        # Create agent using LangChain 1.0 API
        agent = create_agent(
            model=self.llm,
            tools=self.tools,
            system_prompt=system_prompt,
            debug=True
        )
        
        return agent
    
    # ============================================================================
    # LLM CONNECTION
    # ============================================================================
    
    def _test_llm_connection(self) -> bool:
        """Test if LLM connection works."""
        try:
            # Quick test with minimal tokens
            test_response = self.llm.invoke("OK")
            if test_response and hasattr(test_response, 'content'):
                logger.debug("✓ LLM connection test successful")
                return True
            return False
        except Exception as e:
            error_msg = str(e)
            # Don't log full error for known endpoint issues
            if "Not Found" in error_msg or "404" in error_msg:
                logger.error(f"LLM endpoint not available: {self.provider}")
            elif "401" in error_msg or "Unauthorized" in error_msg:
                logger.error(f"LLM authentication failed: {self.provider}")
            else:
                logger.error(f"LLM connection test failed: {error_msg[:100]}")
            return False
    
    
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
            except Exception as e:
                error_msg = f"Agent failed for scenario {i}: {str(e)[:200]}"
                logger.error(error_msg)
                self.log_trail("scenario_failed", {
                    "scenario_number": i,
                    "error": str(e)[:200]
                }, error_msg)
                raise RuntimeError(error_msg) from e
        
        # Generate final report via LLM agent
        logger.info("\nGenerating final security report...")
        self.log_trail("report_generation_started", {
            "total_tests": len(self.test_results),
            "vulnerabilities_found": sum(1 for r in self.test_results if r.get('is_vulnerable', False))
        }, "Starting final report generation")
        
        try:
            result = self.agent.invoke({
                "messages": [("human", "Generate a comprehensive security report of all tests performed, including all vulnerabilities found")]
            })
            logger.info("Report generation completed via agent")
            self.log_trail("report_generated", {
                "method": "llm_agent",
                "success": True
            }, "Report generated successfully via LLM agent")
            # Extract the report from the result
            if isinstance(result, dict):
                if "messages" in result:
                    last_message = result["messages"][-1]
                    if hasattr(last_message, "content"):
                        report = last_message.content
                    else:
                        report = str(last_message)
                else:
                    report = str(result.get("output", result))
            else:
                report = str(result)
            
            # Generate and save detailed action report
            if self.run_dir:
                try:
                    detailed_report = self._generate_detailed_action_report()
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
            logger.debug(f"Running XSS test on {url}")
            try:
                result = self.agent.invoke({
                    "messages": [("human", f"Test this URL for XSS vulnerabilities: {url}")]
                })
                results["xss"] = result
                logger.debug(f"XSS test completed for {url}")
            except Exception as e:
                logger.error(f"Error during XSS test on {url}: {str(e)}")
                results["xss"] = {"error": str(e)}
        
        if test_type in ["sql", "both"]:
            logger.debug(f"Running SQL injection test on {url}")
            try:
                result = self.agent.invoke({
                    "messages": [("human", f"Test this URL for SQL injection vulnerabilities: {url}")]
                })
                results["sql"] = result
                logger.debug(f"SQL injection test completed for {url}")
            except Exception as e:
                logger.error(f"Error during SQL injection test on {url}: {str(e)}")
                results["sql"] = {"error": str(e)}
        
        logger.info(f"Single URL test completed for {url}")
        return results
    
    # ============================================================================
    # REPORTING
    # ============================================================================
    
    def _generate_manual_report(self) -> str:
        """Generate a manual report from test results and save JSON version."""
        vulnerable_tests = [r for r in self.test_results if r.get('is_vulnerable', False)]
        critical_tests = [r for r in vulnerable_tests if r.get('severity') == 'CRITICAL']
        high_tests = [r for r in vulnerable_tests if r.get('severity') == 'HIGH']
        
        report = f"""# Web Security Red-Teaming Report
Generated: {datetime.now().isoformat()}

## Target URL
{self.target_url}

## Executive Summary
- Total tests performed: {len(self.test_results)}
- Vulnerabilities found: {len(vulnerable_tests)}
- Critical vulnerabilities: {len(critical_tests)}
- High severity vulnerabilities: {len(high_tests)}

## Vulnerability Breakdown

### Critical Vulnerabilities ({len(critical_tests)})
"""
        for i, result in enumerate(critical_tests, 1):
            report += f"\n#### {i}. {result.get('issue', 'Unknown issue')}\n"
            report += f"- URL: {result.get('url', 'N/A')}\n"
            report += f"- Parameter: {result.get('parameter', 'N/A')}\n"
            report += f"- Payload: {result.get('payload', 'N/A')}\n"
            report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
        
        report += f"\n### High Severity Vulnerabilities ({len(high_tests)})\n"
        for i, result in enumerate(high_tests, 1):
            report += f"\n#### {i}. {result.get('issue', 'Unknown issue')}\n"
            report += f"- URL: {result.get('url', 'N/A')}\n"
            report += f"- Parameter: {result.get('parameter', 'N/A')}\n"
            report += f"- Payload: {result.get('payload', 'N/A')}\n"
            report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
        
        report += "\n## Detailed Test Results\n"
        for i, result in enumerate(self.test_results, 1):
            report += f"\n### Test {i}\n"
            report += f"- Type: {result.get('test_type', 'Unknown')}\n"
            report += f"- URL: {result.get('url', 'N/A')}\n"
            report += f"- Status: {'VULNERABLE' if result.get('is_vulnerable') else 'SAFE'}\n"
            if result.get('issue'):
                report += f"- Issue: {result['issue']}\n"
            report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
        
            # Generate and save JSON report
        if self.run_dir:
            json_report = self._generate_json_report()
            json_path = self.run_dir / "reports" / "red_team_report.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON report saved to: {json_path}")
            self.log_trail("report_generated", {
                "format": "json",
                "path": str(json_path),
                "total_tests": len(self.test_results),
                "vulnerabilities": len(vulnerable_tests)
            }, "Generated JSON report with structured vulnerability data")
            
            # Generate and save detailed action report
            try:
                detailed_report = self._generate_detailed_action_report()
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
        
        return report
    
    def _generate_detailed_action_report(self) -> str:
        """
        Generate a detailed report of all agent actions during the test run.
        This includes all tool calls, decisions, timing, and execution flow.
        """
        from urllib.parse import urlparse
        
        parsed_url = urlparse(self.target_url)
        domain = parsed_url.netloc or parsed_url.path
        
        # Group trail entries by action type
        action_groups = {}
        for entry in self.trail_entries:
            action_type = entry.get('action_type', 'unknown')
            if action_type not in action_groups:
                action_groups[action_type] = []
            action_groups[action_type].append(entry)
        
        # Calculate timing information
        if self.trail_entries:
            try:
                start_time = datetime.fromisoformat(self.trail_entries[0]['timestamp'])
                end_time = datetime.fromisoformat(self.trail_entries[-1]['timestamp'])
                duration = (end_time - start_time).total_seconds()
            except (KeyError, ValueError, IndexError):
                duration = 0
        else:
            duration = 0
        
        # Count tool calls
        tool_calls = [e for e in self.trail_entries if e.get('action_type') == 'tool_call']
        tool_results = [e for e in self.trail_entries if e.get('action_type') == 'tool_result']
        
        # Count scenarios
        scenarios_started = len([e for e in self.trail_entries if e.get('action_type') == 'scenario_started'])
        scenarios_completed = len([e for e in self.trail_entries if e.get('action_type') == 'scenario_completed'])
        scenarios_failed = len([e for e in self.trail_entries if e.get('action_type') == 'scenario_failed'])
        
        # Build detailed report
        report = f"""# Red Team Agent - Detailed Action Report

Generated: {datetime.now().isoformat()}

## Executive Summary

- **Target URL**: {self.target_url}
- **Domain**: {domain}
- **Provider**: {self.provider}
- **Model**: {self.trail_entries[0].get('data', {}).get('model', 'N/A') if self.trail_entries else 'N/A'}
- **Total Execution Time**: {duration:.2f} seconds ({duration/60:.2f} minutes)
- **Total Actions Logged**: {len(self.trail_entries)}
- **Tool Calls**: {len(tool_calls)}
- **Test Scenarios**: {scenarios_started} started, {scenarios_completed} completed, {scenarios_failed} failed
- **Total Tests Performed**: {len(self.test_results)}
- **Vulnerabilities Found**: {sum(1 for r in self.test_results if r.get('is_vulnerable', False))}

---

## Execution Timeline

### Run Initialization
"""
        
        # Add initialization entries
        init_entries = [e for e in self.trail_entries if e.get('action_type') in ['agent_initialized', 'test_suite_started', 'test_scenarios_defined', 'execution_mode_selected']]
        for entry in init_entries:
            timestamp = entry.get('timestamp', 'N/A')
            action_type = entry.get('action_type', 'unknown')
            data = entry.get('data', {})
            reasoning = entry.get('reasoning', '')
            
            report += f"\n**{timestamp}** - `{action_type}`\n"
            report += f"- **Data**: {json.dumps(data, indent=2)}\n"
            if reasoning:
                report += f"- **Reasoning**: {reasoning}\n"
        
        # Add scenario execution details
        report += "\n### Test Scenario Execution\n\n"
        
        scenario_starts = [e for e in self.trail_entries if e.get('action_type') == 'scenario_started']
        for scenario_entry in scenario_starts:
            scenario_num = scenario_entry.get('data', {}).get('scenario_number', '?')
            scenario_text = scenario_entry.get('data', {}).get('scenario', 'N/A')
            timestamp = scenario_entry.get('timestamp', 'N/A')
            
            report += f"\n#### Scenario {scenario_num}: {scenario_text}\n"
            report += f"**Started**: {timestamp}\n\n"
            
            # Find related actions for this scenario
            try:
                scenario_start_time = datetime.fromisoformat(timestamp)
            except ValueError:
                # Skip this scenario if timestamp is invalid
                report += f"  - **Warning**: Invalid timestamp format\n\n"
                continue
            
            # Find agent invocation
            agent_invocations = [e for e in self.trail_entries 
                               if e.get('action_type') == 'agent_invoked' 
                               and abs((datetime.fromisoformat(e['timestamp']) - scenario_start_time).total_seconds()) < 5]
            
            for inv in agent_invocations:
                report += f"- **Agent Invoked**: {inv.get('timestamp', 'N/A')}\n"
                report += f"  - Reasoning: {inv.get('reasoning', 'N/A')}\n"
            
            # Find tool calls during this scenario
            scenario_tool_calls = []
            scenario_tool_results = []
            
            for entry in self.trail_entries:
                try:
                    entry_time = datetime.fromisoformat(entry.get('timestamp', ''))
                    time_diff = (entry_time - scenario_start_time).total_seconds()
                    
                    if 0 <= time_diff <= 300:  # Within 5 minutes of scenario start
                        if entry.get('action_type') == 'tool_call':
                            scenario_tool_calls.append(entry)
                        elif entry.get('action_type') == 'tool_result':
                            scenario_tool_results.append(entry)
                except (ValueError, KeyError):
                    # Skip entries with invalid timestamps
                    continue
            
            if scenario_tool_calls:
                report += "\n**Tool Calls During This Scenario:**\n"
                for tool_call in scenario_tool_calls:
                    tool_name = tool_call.get('data', {}).get('tool', 'unknown')
                    tool_data = tool_call.get('data', {})
                    tool_timestamp = tool_call.get('timestamp', 'N/A')
                    tool_reasoning = tool_call.get('reasoning', '')
                    
                    report += f"\n- **{tool_timestamp}** - Tool: `{tool_name}`\n"
                    report += f"  - Input: {json.dumps({k: v for k, v in tool_data.items() if k != 'tool'}, indent=2)}\n"
                    if tool_reasoning:
                        report += f"  - Reasoning: {tool_reasoning}\n"
                    
                    # Find corresponding result
                    for result in scenario_tool_results:
                        result_tool = result.get('data', {}).get('tool', '')
                        if result_tool == tool_name:
                            result_data = result.get('data', {})
                            result_timestamp = result.get('timestamp', 'N/A')
                            result_reasoning = result.get('reasoning', '')
                            
                            report += f"  - **Result** ({result_timestamp}):\n"
                            # Format result data nicely
                            for key, value in result_data.items():
                                if key != 'tool':
                                    if isinstance(value, (dict, list)):
                                        report += f"    - {key}: {json.dumps(value, indent=4)}\n"
                                    else:
                                        report += f"    - {key}: {value}\n"
                            if result_reasoning:
                                report += f"    - Reasoning: {result_reasoning}\n"
                            break
            
            # Find scenario completion/failure
            scenario_completions = []
            for e in self.trail_entries:
                if e.get('action_type') in ['scenario_completed', 'scenario_failed']:
                    try:
                        e_time = datetime.fromisoformat(e.get('timestamp', ''))
                        time_diff = abs((e_time - scenario_start_time).total_seconds())
                        if time_diff < 300:
                            scenario_completions.append(e)
                    except (ValueError, KeyError):
                        continue
            
            for completion in scenario_completions:
                completion_type = completion.get('action_type', '')
                completion_data = completion.get('data', {})
                completion_timestamp = completion.get('timestamp', 'N/A')
                
                if completion_type == 'scenario_completed':
                    report += f"\n- **Completed**: {completion_timestamp}\n"
                    report += f"  - Success: {completion_data.get('success', 'N/A')}\n"
                elif completion_type == 'scenario_failed':
                    report += f"\n- **Failed**: {completion_timestamp}\n"
                    report += f"  - Error: {completion_data.get('error', 'N/A')}\n"
            
            report += "\n---\n"
        
        # Add tool usage statistics
        report += "\n## Tool Usage Statistics\n\n"
        
        tool_usage = {}
        for call in tool_calls:
            tool_name = call.get('data', {}).get('tool', 'unknown')
            tool_usage[tool_name] = tool_usage.get(tool_name, 0) + 1
        
        if tool_usage:
            report += "| Tool Name | Usage Count |\n"
            report += "|-----------|-------------|\n"
            for tool_name, count in sorted(tool_usage.items(), key=lambda x: x[1], reverse=True):
                report += f"| `{tool_name}` | {count} |\n"
        else:
            report += "No tools were called during this run.\n"
        
        # Add action type breakdown
        report += "\n## Action Type Breakdown\n\n"
        report += "| Action Type | Count |\n"
        report += "|--------------|-------|\n"
        for action_type, entries in sorted(action_groups.items(), key=lambda x: len(x[1]), reverse=True):
            report += f"| `{action_type}` | {len(entries)} |\n"
        
        # Add test results summary
        if self.test_results:
            report += "\n## Test Results Summary\n\n"
            vulnerable_tests = [r for r in self.test_results if r.get('is_vulnerable', False)]
            safe_tests = [r for r in self.test_results if not r.get('is_vulnerable', False)]
            
            report += f"- **Total Tests**: {len(self.test_results)}\n"
            report += f"- **Vulnerable**: {len(vulnerable_tests)}\n"
            report += f"- **Safe**: {len(safe_tests)}\n"
            
            if vulnerable_tests:
                report += "\n### Vulnerabilities Found\n\n"
                for i, test in enumerate(vulnerable_tests, 1):
                    report += f"#### Vulnerability {i}\n"
                    report += f"- **Test Type**: {test.get('test_type', 'N/A')}\n"
                    report += f"- **URL**: {test.get('url', 'N/A')}\n"
                    report += f"- **Severity**: {test.get('severity', 'N/A')}\n"
                    report += f"- **Issue**: {test.get('issue', 'N/A')}\n"
                    if test.get('parameter'):
                        report += f"- **Parameter**: {test.get('parameter')}\n"
                    if test.get('payload'):
                        report += f"- **Payload**: {test.get('payload')}\n"
                    report += f"- **Timestamp**: {test.get('timestamp', 'N/A')}\n\n"
        
        # Add complete trail entries (for debugging)
        report += "\n## Complete Action Trail\n\n"
        report += "<details>\n<summary>Click to expand complete action trail (JSON format)</summary>\n\n"
        report += "```json\n"
        report += json.dumps(self.trail_entries, indent=2, ensure_ascii=False)
        report += "\n```\n\n</details>\n"
        
        return report
    
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
    
    def _generate_json_report(self) -> Dict[str, Any]:
        """Generate a JSON report from test results."""
        from urllib.parse import urlparse
        
        vulnerable_tests = [r for r in self.test_results if r.get('is_vulnerable', False)]
        critical_tests = [r for r in vulnerable_tests if r.get('severity') == 'CRITICAL']
        high_tests = [r for r in vulnerable_tests if r.get('severity') == 'HIGH']
        medium_tests = [r for r in vulnerable_tests if r.get('severity') == 'MEDIUM']
        low_tests = [r for r in vulnerable_tests if r.get('severity') == 'LOW']
        info_tests = [r for r in vulnerable_tests if r.get('severity') == 'INFO']
        safe_tests = [r for r in self.test_results if not r.get('is_vulnerable', False)]
        
        # Parse domain from URL
        parsed_url = urlparse(self.target_url)
        domain = parsed_url.netloc or parsed_url.path
        
        # Count tests by type
        tests_by_type = {}
        for result in self.test_results:
            test_type = result.get('test_type', 'unknown')
            tests_by_type[test_type] = tests_by_type.get(test_type, 0) + 1
        
        # Calculate vulnerability rate
        vulnerability_rate = (len(vulnerable_tests) / len(self.test_results) * 100) if self.test_results else 0.0
        
        # Calculate average severity score (CRITICAL=5, HIGH=4, MEDIUM=3, LOW=2, INFO=1)
        severity_scores = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3,
            'LOW': 2,
            'INFO': 1
        }
        severity_values = [severity_scores.get(r.get('severity', ''), 0) for r in vulnerable_tests]
        avg_severity_score = sum(severity_values) / len(severity_values) if severity_values else 0.0
        
        # Format vulnerabilities by severity
        def format_vulnerability(result: Dict[str, Any], vuln_id: str) -> Dict[str, Any]:
            formatted = {
                "id": vuln_id,
                "test_id": self.test_results.index(result) + 1,
                "test_type": result.get('test_type', 'unknown'),
                "url": result.get('url', 'N/A'),
                "issue": result.get('issue', 'Unknown issue'),
                "severity": result.get('severity', 'UNKNOWN'),
                "status": "VULNERABLE" if result.get('is_vulnerable') else "SAFE",
                "timestamp": result.get('timestamp', 'N/A')
            }
            
            # Add optional fields if present
            if result.get('parameter'):
                formatted["parameter"] = result['parameter']
            if result.get('payload'):
                formatted["payload"] = result['payload']
            if result.get('status_code'):
                formatted["status_code"] = result['status_code']
            
            # Add recommendation based on issue type
            issue = result.get('issue', '').lower()
            if 'x-frame-options' in issue:
                formatted["recommendation"] = "Add X-Frame-Options header to prevent clickjacking attacks"
            elif 'x-content-type-options' in issue:
                formatted["recommendation"] = "Add X-Content-Type-Options: nosniff header to prevent MIME type sniffing"
            elif 'x-xss-protection' in issue:
                formatted["recommendation"] = "Add X-XSS-Protection header (though modern browsers handle this)"
            elif 'csp' in issue or 'content-security-policy' in issue:
                formatted["recommendation"] = "Add Content-Security-Policy header to prevent XSS attacks"
            elif 'xss' in issue:
                formatted["recommendation"] = "Implement proper input validation and output encoding to prevent XSS"
            elif 'sql injection' in issue or 'sqli' in issue:
                formatted["recommendation"] = "Use parameterized queries and input validation to prevent SQL injection"
            elif 'csrf' in issue:
                formatted["recommendation"] = "Implement CSRF tokens and validate origin/referer headers"
            else:
                formatted["recommendation"] = "Review and address the security issue identified"
            
            return formatted
        
        # Format all vulnerabilities
        vuln_counter = 1
        critical_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                             for i, r in enumerate(critical_tests)]
        vuln_counter += len(critical_tests)
        high_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                         for i, r in enumerate(high_tests)]
        vuln_counter += len(high_tests)
        medium_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                           for i, r in enumerate(medium_tests)]
        vuln_counter += len(medium_tests)
        low_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                        for i, r in enumerate(low_tests)]
        vuln_counter += len(low_tests)
        info_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                         for i, r in enumerate(info_tests)]
        
        report = {
            "metadata": {
                "report_type": "web_security_red_team",
                "generated_at": datetime.now().isoformat(),
                "version": "1.0"
            },
            "target": {
                "url": self.target_url,
                "domain": domain
            },
            "executive_summary": {
                "total_tests_performed": len(self.test_results),
                "vulnerabilities_found": len(vulnerable_tests),
                "tests_passed": len(safe_tests),
                "tests_failed": len(vulnerable_tests),
                "severity_breakdown": {
                    "critical": len(critical_tests),
                    "high": len(high_tests),
                    "medium": len(medium_tests),
                    "low": len(low_tests),
                    "info": len(info_tests)
                }
            },
            "vulnerabilities": {
                "critical": critical_formatted,
                "high": high_formatted,
                "medium": medium_formatted,
                "low": low_formatted,
                "info": info_formatted
            },
            "test_results": self.test_results,
            "statistics": {
                "tests_by_type": tests_by_type,
                "vulnerability_rate": round(vulnerability_rate, 2),
                "average_severity_score": round(avg_severity_score, 2)
            }
        }
        
        return report


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
        default=None
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
    logger.info("=" * 60)
    logger.info(f"Starting Red-Team Run: {run_id}")
    logger.info(f"Run Directory: {run_dir}")
    logger.info("=" * 60)
    
    # Set up file logging
    setup_file_logging(run_dir)
    
    # Parse headers if provided
    headers = None
    if args.headers:
        try:
            headers = json.loads(args.headers)
        except json.JSONDecodeError:
            logger.warning("Warning: Invalid JSON for headers, ignoring")
    
    # Initialize agent
    logger.info(f"Initializing Web Security Red-Teaming Agent for: {args.url}")
    logger.info(f"Using provider: {args.provider}")
    if args.model:
        logger.info(f"Using model: {args.model}")
    
    agent = RedTeamAgent(
        target_url=args.url,
        provider=args.provider,
        model_name=args.model,
        headers=headers,
        run_dir=run_dir
    )
    
    # Run tests
    if args.scenario:
        logger.info(f"Running single test: {args.scenario}")
        try:
            result = agent.agent.invoke({
                "messages": [("human", args.scenario)]
            })
            logger.debug(f"Result: {result}")
        except Exception as e:
            logger.error(f"Error: {e}")
    else:
        logger.info("Running comprehensive web security test suite...")
        report = agent.run_test_suite()
        
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
            
            logger.info("=" * 60)
            logger.info("Reports saved to:")
            logger.info(f"  - Security Report: {run_report_path}")
            logger.info(f"  - Detailed Action Report: {run_dir / 'reports' / 'detailed_action_report.md'}")
            logger.info(f"  - JSON Report: {run_dir / 'reports' / 'red_team_report.json'}")
            logger.info(f"  - Action Trail: {run_dir / 'reports' / 'trail.jsonl'}")
            if Path(args.output) != run_report_path:
                logger.info(f"  - Specified location: {args.output}")
            logger.info("=" * 60)
        else:
            # Default: save to run directory
            report_filename = f"security_report_{run_id}.md"
            run_report_path = run_dir / "reports" / report_filename
            with open(run_report_path, "w") as f:
                f.write(report)
            
            logger.info("=" * 60)
            logger.info("Reports saved to:")
            logger.info(f"  - Security Report: {run_report_path}")
            logger.info(f"  - Detailed Action Report: {run_dir / 'reports' / 'detailed_action_report.md'}")
            logger.info(f"  - JSON Report: {run_dir / 'reports' / 'red_team_report.json'}")
            logger.info(f"  - Action Trail: {run_dir / 'reports' / 'trail.jsonl'}")
            logger.info("=" * 60)
        
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
        
        logger.info("Run Summary:")
        logger.info(f"  - Run ID: {run_id}")
        logger.info(f"  - Total tests: {metadata['total_tests']}")
        logger.info(f"  - Vulnerabilities found: {metadata['vulnerabilities_found']}")
        logger.info(f"  - Logs: {run_dir / 'logs' / 'agent.debug'}")
        logger.info(f"  - Reports directory: {run_dir / 'reports'}")
        logger.info(f"    * Security Report (Markdown)")
        logger.info(f"    * Detailed Action Report (Markdown)")
        logger.info(f"    * JSON Report")
        logger.info(f"    * Action Trail (JSONL)")
        logger.info(f"  - Metadata: {metadata_path}")


if __name__ == "__main__":
    main()

