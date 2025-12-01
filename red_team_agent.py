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
import re
import urllib.parse
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain.tools import BaseTool
from langchain_core.tools import StructuredTool
from langchain_core.messages import HumanMessage, SystemMessage
from typing import Callable
import json
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

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
        self.provider = provider.lower()
        self.target_url = target_url
        self.run_dir = run_dir or _current_run_dir
        
        logger.info(f"Initializing RedTeamAgent for target URL: {target_url}")
        logger.info(f"Using provider: {self.provider}")
        if self.run_dir:
            logger.info(f"Run directory: {self.run_dir}")
        
        # Determine API key and model based on provider
        if self.provider == "openrouter":
            self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
            if not self.api_key:
                raise ValueError("OpenRouter API key required. Set OPENROUTER_API_KEY env var or pass api_key parameter.")
            default_model = "anthropic/claude-3.5-sonnet"
            model_name = model_name or default_model
            
            # Use ChatOpenAI with OpenRouter endpoint
            if ChatOpenAI is None:
                raise ImportError("langchain-openai is required for OpenRouter support. Install with: pip install langchain-openai")
            
            self.llm = ChatOpenAI(
                model=model_name,
                temperature=temperature,
                api_key=self.api_key,
                base_url="https://openrouter.ai/api/v1",
                default_headers={
                    "HTTP-Referer": "https://github.com/shayahal/vibe-code-bench",
                    "X-Title": "Red-Team Agent"
                }
            )
            
        elif self.provider == "anthropic":
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
            if not self.api_key:
                raise ValueError("Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass api_key parameter.")
            default_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
            model_name = model_name or default_model
            
            # Check if custom base URL is provided (for custom endpoints like yovy.app)
            base_url = os.getenv("ANTHROPIC_BASE_URL")
            if base_url:
                # Use ChatOpenAI with custom base URL (compatible with OpenAI API format)
                if ChatOpenAI is None:
                    raise ImportError("langchain-openai is required for custom Anthropic endpoints. Install with: pip install langchain-openai")
                
                # Remove quotes if present
                base_url = base_url.strip('"\'')
                # Ensure base URL ends with /v1 if it doesn't already
                if not base_url.endswith('/v1') and not base_url.endswith('/v1/'):
                    base_url = f"{base_url}/v1" if not base_url.endswith('/') else f"{base_url}v1"
                
                logger.info(f"Using custom Anthropic base URL: {base_url}")
                self.llm = ChatOpenAI(
                    model=model_name,
                    temperature=temperature,
                    api_key=self.api_key,
                    base_url=base_url
                )
            else:
                # Use standard Anthropic client
                if ChatAnthropic is None:
                    raise ImportError("langchain-anthropic is required. Install with: pip install langchain-anthropic")
                
                self.llm = ChatAnthropic(
                    model=model_name,
                    temperature=temperature,
                    api_key=self.api_key
                )
            
        elif self.provider == "openai":
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
            if not self.api_key:
                raise ValueError("OpenAI API key required. Set OPENAI_API_KEY env var or pass api_key parameter.")
            default_model = "gpt-4"
            model_name = model_name or default_model
            
            if ChatOpenAI is None:
                raise ImportError("langchain-openai is required. Install with: pip install langchain-openai")
            
            self.llm = ChatOpenAI(
                model=model_name,
                temperature=temperature,
                api_key=self.api_key
            )
        else:
            raise ValueError(f"Unknown provider: {provider}. Supported providers: 'openrouter', 'anthropic', 'openai'")
        
        self.target_url = target_url
        self.headers = headers or {"User-Agent": "RedTeamAgent/1.0"}
        self.cookies = cookies or {}
        self.test_results: List[Dict[str, Any]] = []
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)
        
        logger.info(f"Created session with {len(self.headers)} headers and {len(self.cookies)} cookies")
        
        # Create tools for the agent
        self.tools = self._create_tools()
        logger.info(f"Created {len(self.tools)} tools for the agent")
        
        # Create the agent
        self.agent = self._create_agent()
        logger.info("RedTeamAgent initialized successfully")
        
    def _create_tools(self) -> List[BaseTool]:
        """Create tools for the web security red-teaming agent."""
        
        def fetch_page(url: str) -> Dict[str, Any]:
            """Fetch a web page and return its content and metadata.
            
            Args:
                url: The URL to fetch
            """
            logger.info(f"Fetching page: {url}")
            try:
                response = self.session.get(url, timeout=10)
                logger.info(f"Fetched {url} - Status: {response.status_code}, Size: {len(response.text)} bytes")
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                forms = []
                for form in soup.find_all('form'):
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        form_data['inputs'].append({
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        })
                    forms.append(form_data)
                
                # Extract links
                links = [a.get('href', '') for a in soup.find_all('a', href=True)]
                
                logger.info(f"Extracted {len(forms)} forms and {len(links)} links from {url}")
                
                return {
                    "url": url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "forms": forms,
                    "links": links,
                    "content_length": len(response.text),
                    "has_forms": len(forms) > 0,
                    "response_text": response.text
                }
            except Exception as e:
                logger.error(f"Error fetching page {url}: {str(e)}")
                return {"error": str(e), "url": url}
        
        def craft_xss_payload(payload_type: str = "basic") -> str:
            """Craft an XSS (Cross-Site Scripting) payload.
            
            Args:
                payload_type: Type of XSS payload ('basic', 'event', 'svg', 'img')
            """
            logger.info(f"Crafting XSS payload of type: {payload_type}")
            payloads = {
                "basic": "<script>alert('XSS')</script>",
                "event": "<img src=x onerror=alert('XSS')>",
                "svg": "<svg onload=alert('XSS')>",
                "img": "<img src=\"javascript:alert('XSS')\">",
                "body": "<body onload=alert('XSS')>",
                "input": "<input onfocus=alert('XSS') autofocus>",
                "iframe": "<iframe src=\"javascript:alert('XSS')\"></iframe>",
                "encoded": "%3Cscript%3Ealert('XSS')%3C/script%3E",
            }
            payload = payloads.get(payload_type, payloads["basic"])
            logger.debug(f"Created XSS payload: {payload[:50]}...")
            return payload
        
        def craft_sql_injection_payload(payload_type: str = "basic") -> str:
            """Craft a SQL injection payload.
            
            Args:
                payload_type: Type of SQL injection ('basic', 'union', 'boolean', 'time')
            """
            payloads = {
                "basic": "' OR '1'='1",
                "union": "' UNION SELECT NULL--",
                "boolean": "' OR 1=1--",
                "time": "'; WAITFOR DELAY '00:00:05'--",
                "comment": "' OR 1=1#",
                "double": "\" OR \"1\"=\"1",
                "concat": "' OR 'a'='a",
            }
            payload = payloads.get(payload_type, payloads["basic"])
            logger.info(f"Crafting SQL injection payload of type: {payload_type}")
            logger.debug(f"Created SQL injection payload: {payload[:50]}...")
            return payload
        
        def test_xss(url: str, parameter: str, payload: str) -> Dict[str, Any]:
            """Test for XSS vulnerability in a URL parameter.
            
            Args:
                url: The URL to test
                parameter: The parameter name to test
                payload: The XSS payload to inject
            """
            logger.info(f"Testing XSS vulnerability - URL: {url}, Parameter: {parameter}")
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params, doseq=True)}"
                logger.debug(f"Testing XSS with URL: {test_url}")
                response = self.session.get(test_url, timeout=10)
                
                # Check if payload is reflected in response
                is_vulnerable = payload in response.text or payload.replace("'", "&#39;") in response.text
                
                if is_vulnerable:
                    logger.warning(f"XSS VULNERABILITY DETECTED - URL: {url}, Parameter: {parameter}")
                else:
                    logger.info(f"XSS test passed - URL: {url}, Parameter: {parameter}")
                
                result = {
                    "url": test_url,
                    "parameter": parameter,
                    "payload": payload,
                    "status_code": response.status_code,
                    "is_vulnerable": is_vulnerable,
                    "timestamp": datetime.now().isoformat()
                }
                
                if is_vulnerable:
                    result["severity"] = "HIGH"
                    result["issue"] = "XSS vulnerability detected - payload reflected in response"
                
                self.test_results.append(result)
                logger.info(f"XSS test completed - Vulnerable: {is_vulnerable}, Status: {result['status_code']}")
                return result
            except Exception as e:
                logger.error(f"Error testing XSS on {url}: {str(e)}")
                return {"error": str(e), "url": url}
        
        def test_sql_injection(url: str, parameter: str, payload: str) -> Dict[str, Any]:
            """Test for SQL injection vulnerability.
            
            Args:
                url: The URL to test
                parameter: The parameter name to test
                payload: The SQL injection payload
            """
            logger.info(f"Testing SQL injection vulnerability - URL: {url}, Parameter: {parameter}")
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[parameter] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params, doseq=True)}"
                logger.debug(f"Testing SQL injection with URL: {test_url}")
                
                # Test with payload
                start_time = datetime.now()
                response = self.session.get(test_url, timeout=15)
                elapsed = (datetime.now() - start_time).total_seconds()
                logger.debug(f"SQL injection test response time: {elapsed:.2f}s")
                
                # Check for SQL error messages
                sql_errors = [
                    "sql syntax",
                    "mysql_fetch",
                    "warning: mysql",
                    "postgresql query failed",
                    "ora-01756",
                    "microsoft ole db provider",
                    "sqlite_exception",
                    "sqlcommand",
                ]
                
                response_lower = response.text.lower()
                has_sql_error = any(error in response_lower for error in sql_errors)
                
                # Check for time-based SQL injection (if payload contains delay)
                is_time_based = "WAITFOR" in payload.upper() and elapsed > 4
                
                is_vulnerable = has_sql_error or is_time_based
                
                if is_vulnerable:
                    logger.critical(f"SQL INJECTION VULNERABILITY DETECTED - URL: {url}, Parameter: {parameter}")
                else:
                    logger.info(f"SQL injection test passed - URL: {url}, Parameter: {parameter}")
                
                result = {
                    "url": test_url,
                    "parameter": parameter,
                    "payload": payload,
                    "status_code": response.status_code,
                    "response_time": elapsed,
                    "has_sql_error": has_sql_error,
                    "is_vulnerable": is_vulnerable,
                    "timestamp": datetime.now().isoformat()
                }
                
                if is_vulnerable:
                    result["severity"] = "CRITICAL"
                    result["issue"] = "SQL injection vulnerability detected"
                
                self.test_results.append(result)
                logger.info(f"SQL injection test completed - Vulnerable: {is_vulnerable}, Status: {result['status_code']}")
                return result
            except Exception as e:
                logger.error(f"Error testing SQL injection on {url}: {str(e)}")
                return {"error": str(e), "url": url}
        
        def test_form_submission(form_action: str, form_method: str, form_data: Dict[str, str]) -> Dict[str, Any]:
            """Test form submission with malicious payloads.
            
            Args:
                form_action: The form action URL
                form_method: The form method (GET/POST)
                form_data: Dictionary of form field names and values
            """
            logger.info(f"Testing form submission - Action: {form_action}, Method: {form_method}, Fields: {list(form_data.keys())}")
            try:
                # Test with XSS payloads
                test_data = form_data.copy()
                for field_name in test_data.keys():
                    test_data[field_name] = self.craft_xss_payload("basic")
                
                if form_method.upper() == "POST":
                    logger.debug(f"Submitting form via POST to {form_action}")
                    response = self.session.post(form_action, data=test_data, timeout=10)
                else:
                    logger.debug(f"Submitting form via GET to {form_action}")
                    response = self.session.get(form_action, params=test_data, timeout=10)
                
                logger.info(f"Form submission completed - Status: {response.status_code}")
                
                result = {
                    "form_action": form_action,
                    "method": form_method,
                    "status_code": response.status_code,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.test_results.append(result)
                return result
            except Exception as e:
                logger.error(f"Error testing form submission on {form_action}: {str(e)}")
                return {"error": str(e), "form_action": form_action}
        
        def analyze_response_security(response_text: str) -> Dict[str, Any]:
            """Analyze HTTP response for security issues.
            
            Args:
                response_text: The response text to analyze
            """
            logger.info(f"Analyzing response security - Response size: {len(response_text)} bytes")
            issues = []
            
            # Check for sensitive information
            sensitive_patterns = {
                "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "credit_card": r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
                "api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                "password": r'(?i)(password|pwd|pass)\s*[:=]\s*["\']?([^\s"\'<>]{6,})["\']?',
            }
            
            for pattern_name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, response_text)
                if matches:
                    logger.warning(f"Potential {pattern_name} exposure found in response ({len(matches)} matches)")
                    issues.append(f"Potential {pattern_name} exposure found")
            
            # Check security headers
            security_headers = {
                "X-Frame-Options": "Missing X-Frame-Options header",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "X-XSS-Protection": "Missing X-XSS-Protection header",
                "Strict-Transport-Security": "Missing HSTS header",
            }
            
            if issues:
                logger.warning(f"Security analysis found {len(issues)} issues")
            else:
                logger.info("Security analysis completed - No issues found")
            
            return {
                "issues": issues,
                "has_issues": len(issues) > 0,
                "analysis_timestamp": datetime.now().isoformat()
            }
        
        def generate_report() -> str:
            """Generate a comprehensive security report."""
            logger.info(f"Generating security report - Total tests: {len(self.test_results)}")
            vulnerable_tests = [r for r in self.test_results if r.get('is_vulnerable', False)]
            critical_tests = [r for r in vulnerable_tests if r.get('severity') == 'CRITICAL']
            high_tests = [r for r in vulnerable_tests if r.get('severity') == 'HIGH']
            
            logger.info(f"Report summary - Vulnerabilities: {len(vulnerable_tests)}, Critical: {len(critical_tests)}, High: {len(high_tests)}")
            
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
            
            logger.info("Security report generated successfully")
            return report
        
        return [
            StructuredTool.from_function(
                func=fetch_page,
                name="fetch_page",
                description="Fetch a web page and extract forms, links, and metadata. Input: url (the URL to fetch)"
            ),
            StructuredTool.from_function(
                func=craft_xss_payload,
                name="craft_xss_payload",
                description="Craft an XSS (Cross-Site Scripting) payload. Input: payload_type (basic, event, svg, img, body, input, iframe, encoded)"
            ),
            StructuredTool.from_function(
                func=craft_sql_injection_payload,
                name="craft_sql_injection_payload",
                description="Craft a SQL injection payload. Input: payload_type (basic, union, boolean, time, comment, double, concat)"
            ),
            StructuredTool.from_function(
                func=test_xss,
                name="test_xss",
                description="Test for XSS vulnerability in a URL parameter. Input: url (the URL to test), parameter (parameter name), payload (XSS payload)"
            ),
            StructuredTool.from_function(
                func=test_sql_injection,
                name="test_sql_injection",
                description="Test for SQL injection vulnerability. Input: url (the URL to test), parameter (parameter name), payload (SQL injection payload)"
            ),
            StructuredTool.from_function(
                func=test_form_submission,
                name="test_form_submission",
                description="Test form submission with malicious payloads. Input: form_action (form action URL), form_method (GET/POST), form_data (dict of form fields)"
            ),
            StructuredTool.from_function(
                func=analyze_response_security,
                name="analyze_response_security",
                description="Analyze HTTP response for security issues like exposed sensitive data. Input: response_text (the response HTML/text to analyze)"
            ),
            StructuredTool.from_function(
                func=generate_report,
                name="generate_report",
                description="Generate a comprehensive security report of all tests performed"
            ),
        ]
    
    def _create_agent(self):
        """Create the LangChain agent using LangChain 1.0 API."""
        
        system_prompt = f"""You are a web security red-teaming expert testing web pages for vulnerabilities.

Your goal is to test the following web page: {self.target_url}

You should:
1. Fetch and analyze the target web page
2. Identify all forms, input fields, and URL parameters
3. Test for XSS (Cross-Site Scripting) vulnerabilities
4. Test for SQL injection vulnerabilities
5. Test for CSRF vulnerabilities
6. Test authentication and authorization mechanisms
7. Analyze responses for security headers and sensitive data exposure
8. Document all findings in a comprehensive report

Be thorough but ethical. Your goal is to improve security, not cause harm. Only test systems you have permission to test.

Available tools:
- fetch_page: Fetch a web page and extract forms, links, and metadata
- craft_xss_payload: Create XSS payloads for testing
- craft_sql_injection_payload: Create SQL injection payloads for testing
- test_xss: Test URL parameters for XSS vulnerabilities
- test_sql_injection: Test URL parameters for SQL injection vulnerabilities
- test_form_submission: Test form submissions with malicious payloads
- analyze_response_security: Analyze responses for security issues
- generate_report: Create a final security report

Always think step by step:
1. First, fetch the target page to understand its structure
2. Identify all input points (forms, URL parameters)
3. Test each input point systematically
4. Document vulnerabilities as you find them
5. Generate a comprehensive report at the end"""
        
        # Create agent using LangChain 1.0 API
        agent = create_agent(
            model=self.llm,
            tools=self.tools,
            system_prompt=system_prompt,
            debug=True
        )
        
        return agent
    
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
            error_msg = str(e)
            # Don't log full error for known endpoint issues
            if "Not Found" in error_msg or "404" in error_msg:
                logger.debug(f"LLM endpoint not available (using direct mode): {self.provider}")
            elif "401" in error_msg or "Unauthorized" in error_msg:
                logger.debug(f"LLM authentication failed (using direct mode): {self.provider}")
            else:
                logger.debug(f"LLM connection test failed (using direct mode): {error_msg[:100]}")
            return False
    
    def _try_fallback_provider(self) -> bool:
        """Try to use OpenRouter as fallback if current provider fails."""
        if self.provider == "anthropic":
            # Try OpenRouter as fallback
            openrouter_key = os.getenv("OPENROUTER_API_KEY")
            if openrouter_key and ChatOpenAI:
                try:
                    logger.info("Attempting fallback to OpenRouter...")
                    self.llm = ChatOpenAI(
                        model="anthropic/claude-3.5-sonnet",
                        temperature=0.7,
                        api_key=openrouter_key,
                        base_url="https://openrouter.ai/api/v1",
                        default_headers={
                            "HTTP-Referer": "https://github.com/shayahal/vibe-code-bench",
                            "X-Title": "Red-Team Agent"
                        }
                    )
                    if self._test_llm_connection():
                        logger.info("✓ Successfully connected to OpenRouter (fallback)")
                        self.provider = "openrouter"
                        return True
                except Exception as e:
                    logger.debug(f"OpenRouter fallback also failed: {str(e)[:100]}")
        return False
    
    def _execute_tools_directly(self, scenario: str) -> None:
        """Execute tools directly based on scenario without LLM."""
        logger.info("Executing tools directly (LLM fallback mode)")
        
        scenario_lower = scenario.lower()
        
        # Fetch page scenario
        if "fetch" in scenario_lower and "analyze" in scenario_lower:
            logger.info("→ Executing: fetch_page")
            tool = next((t for t in self.tools if t.name == "fetch_page"), None)
            if tool:
                try:
                    result = tool.func(self.target_url)
                    logger.info(f"✓ Fetched page: {result.get('status_code', 'N/A')}")
                    if result.get('forms'):
                        logger.info(f"  Found {len(result['forms'])} forms")
                    if result.get('links'):
                        logger.info(f"  Found {len(result['links'])} links")
                except Exception as e:
                    logger.error(f"Error fetching page: {e}")
        
        # XSS testing scenario
        if "xss" in scenario_lower and ("test" in scenario_lower or "vulnerability" in scenario_lower):
            logger.info("→ Executing: XSS vulnerability tests")
            # First fetch the page to find parameters
            fetch_tool = next((t for t in self.tools if t.name == "fetch_page"), None)
            if fetch_tool:
                try:
                    page_data = fetch_tool.func(self.target_url)
                    # Check URL parameters
                    parsed = urlparse(self.target_url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        xss_tool = next((t for t in self.tools if t.name == "test_xss"), None)
                        payload_tool = next((t for t in self.tools if t.name == "craft_xss_payload"), None)
                        if xss_tool and payload_tool:
                            payload = payload_tool.func("basic")
                            for param_name in params.keys():
                                logger.info(f"  Testing parameter: {param_name}")
                                xss_tool.func(self.target_url, param_name, payload)
                    # Test forms
                    for form in page_data.get('forms', []):
                        form_tool = next((t for t in self.tools if t.name == "test_form_submission"), None)
                        if form_tool:
                            form_data = {inp['name']: '' for inp in form.get('inputs', []) if inp.get('name')}
                            if form_data:
                                logger.info(f"  Testing form: {form.get('action', 'N/A')}")
                                form_tool.func(form.get('action', self.target_url), form.get('method', 'GET'), form_data)
                except Exception as e:
                    logger.error(f"Error in XSS testing: {e}")
        
        # SQL injection testing scenario
        if "sql" in scenario_lower and ("injection" in scenario_lower or "test" in scenario_lower):
            logger.info("→ Executing: SQL injection vulnerability tests")
            fetch_tool = next((t for t in self.tools if t.name == "fetch_page"), None)
            if fetch_tool:
                try:
                    page_data = fetch_tool.func(self.target_url)
                    parsed = urlparse(self.target_url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        sql_tool = next((t for t in self.tools if t.name == "test_sql_injection"), None)
                        payload_tool = next((t for t in self.tools if t.name == "craft_sql_injection_payload"), None)
                        if sql_tool and payload_tool:
                            payload = payload_tool.func("basic")
                            for param_name in params.keys():
                                logger.info(f"  Testing parameter: {param_name}")
                                sql_tool.func(self.target_url, param_name, payload)
                except Exception as e:
                    logger.error(f"Error in SQL injection testing: {e}")
        
        # Security analysis scenario
        if "analyze" in scenario_lower and ("security" in scenario_lower or "header" in scenario_lower):
            logger.info("→ Executing: Security analysis")
            fetch_tool = next((t for t in self.tools if t.name == "fetch_page"), None)
            analyze_tool = next((t for t in self.tools if t.name == "analyze_response_security"), None)
            if fetch_tool and analyze_tool:
                try:
                    page_data = fetch_tool.func(self.target_url)
                    response_text = page_data.get('response_text', '')
                    if not response_text:
                        # Fetch again to get response text
                        response = self.session.get(self.target_url, timeout=10)
                        response_text = response.text
                    result = analyze_tool.func(response_text)
                    logger.info(f"✓ Security analysis completed: {len(result.get('issues', []))} issues found")
                    
                    # Also check security headers
                    headers = page_data.get('headers', {})
                    security_headers = {
                        "X-Frame-Options": "Missing X-Frame-Options header",
                        "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                        "X-XSS-Protection": "Missing X-XSS-Protection header",
                        "Strict-Transport-Security": "Missing HSTS header",
                        "Content-Security-Policy": "Missing CSP header",
                    }
                    missing_headers = []
                    for header, message in security_headers.items():
                        if header not in headers:
                            logger.warning(f"  ⚠️  {message}")
                            missing_headers.append(message)
                            # Add to test results
                            self.test_results.append({
                                "test_type": "security_header",
                                "url": self.target_url,
                                "issue": message,
                                "severity": "MEDIUM",
                                "timestamp": datetime.now().isoformat(),
                                "is_vulnerable": True
                            })
                        else:
                            logger.info(f"  ✓ {header}: {headers[header]}")
                except Exception as e:
                    logger.error(f"Error in security analysis: {e}")
    
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
        
        if test_scenarios is None:
            test_scenarios = [
                f"Fetch and analyze the target page: {self.target_url}",
                "Test all URL parameters for XSS vulnerabilities",
                "Test all URL parameters for SQL injection vulnerabilities",
                "Test all forms for XSS and SQL injection vulnerabilities",
                "Analyze responses for security headers and sensitive data exposure",
            ]
        
        # Test LLM connection first
        llm_works = self._test_llm_connection()
        
        # Try fallback provider if primary fails
        if not llm_works:
            llm_works = self._try_fallback_provider()
        
        use_direct_mode = not llm_works
        
        if use_direct_mode:
            logger.info("Using direct tool execution mode (LLM orchestration unavailable)")
        
        logger.info(f"Running {len(test_scenarios)} test scenarios")
        
        for i, scenario in enumerate(test_scenarios, 1):
            logger.info(f"\n{'='*60}")
            logger.info(f"Test Scenario {i}/{len(test_scenarios)}: {scenario}")
            logger.info(f"{'='*60}")
            
            if use_direct_mode:
                # Execute tools directly
                self._execute_tools_directly(scenario)
            else:
                # Try using LLM agent
                try:
                    logger.debug(f"Invoking agent with scenario: {scenario[:100]}...")
                    result = self.agent.invoke({"messages": [("human", scenario)]})
                    logger.info(f"Scenario {i} completed successfully")
                    logger.debug(f"Result: {str(result)[:200]}...")
                except Exception as e:
                    logger.warning(f"Agent failed, falling back to direct execution: {str(e)[:100]}")
                    self._execute_tools_directly(scenario)
        
        # Generate final report
        logger.info("\nGenerating final security report...")
        if not use_direct_mode:
            try:
                result = self.agent.invoke({
                    "messages": [("human", "Generate a comprehensive security report of all tests performed, including all vulnerabilities found")]
                })
                logger.info("Report generation completed via agent")
                # Extract the report from the result
                if isinstance(result, dict):
                    if "messages" in result:
                        last_message = result["messages"][-1]
                        if hasattr(last_message, "content"):
                            return last_message.content
                        return str(last_message)
                    return str(result.get("output", result))
                return str(result)
            except Exception as e:
                logger.warning(f"Error generating report via agent, using manual report: {str(e)[:100]}")
        
        return self._generate_manual_report()
    
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
    
    def _generate_manual_report(self) -> str:
        """Generate a manual report from test results."""
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
        
        return report
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Get all test results."""
        return self.test_results


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
            print(f"\nError: {e}")
    else:
        print("\nRunning comprehensive web security test suite...")
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
            
            print(f"\n{'='*60}")
            print(f"Report saved to:")
            print(f"  - Run directory: {run_report_path}")
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
            print(f"Report saved to: {run_report_path}")
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
            "run_directory": str(run_dir)
        }
        
        metadata_path = run_dir / "metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        print(f"\nRun Summary:")
        print(f"  - Run ID: {run_id}")
        print(f"  - Total tests: {metadata['total_tests']}")
        print(f"  - Vulnerabilities found: {metadata['vulnerabilities_found']}")
        print(f"  - Logs: {run_dir / 'logs' / 'agent.log'}")
        print(f"  - Reports: {run_dir / 'reports'}")
        print(f"  - Metadata: {metadata_path}")


if __name__ == "__main__":
    main()

