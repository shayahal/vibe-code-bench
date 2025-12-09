"""Authentication testing module for login forms, session management, and authorization."""

# Load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip loading .env

import time
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

import httpx

from vibe_code_bench.red_team_agent.models import VulnerabilityFinding, SecurityTestResult
from vibe_code_bench.red_team_agent.utils import classify_severity, get_owasp_category
from vibe_code_bench.red_team_agent.logging_config import get_logger

logger = get_logger(__name__)

# Try to import Anchor Browser tools
try:
    from langchain_anchorbrowser import AnchorContentTool, SimpleAnchorWebTaskTool
    ANCHOR_BROWSER_AVAILABLE = True
except ImportError:
    ANCHOR_BROWSER_AVAILABLE = False
    logger.warning(
        "langchain-anchorbrowser not available. "
        "Install with: pip install langchain-anchorbrowser. "
        "Some JavaScript-heavy tests will be limited."
    )


class AuthTester:
    """Tests authentication mechanisms and session management."""

    def __init__(self, use_anchor_browser: bool = True, timeout: int = 30):
        """
        Initialize authentication tester.

        Args:
            use_anchor_browser: Whether to use Anchor Browser tools
            timeout: HTTP request timeout in seconds
        """
        self.logger = get_logger(f"{__name__}.AuthTester")
        self.use_anchor_browser = use_anchor_browser and ANCHOR_BROWSER_AVAILABLE
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout, follow_redirects=True)

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
                    self.web_task_tool = SimpleAnchorWebTaskTool()
                    self.logger.info("[SETUP] Anchor Browser tools initialized")
            except Exception as e:
                self.logger.warning(f"[SETUP] Failed to initialize Anchor Browser: {e}")
                self.use_anchor_browser = False

    def test_login_form(
        self, auth_endpoint: Dict[str, Any], credentials: Optional[Dict[str, str]] = None
    ) -> SecurityTestResult:
        """
        Test login form for vulnerabilities.

        Args:
            auth_endpoint: Authentication endpoint information
            credentials: Optional credentials for testing

        Returns:
            SecurityTestResult with findings
        """
        start_time = time.time()
        url = auth_endpoint.get("url", "")

        self.logger.info(f"[TEST] Login Form - {url} - Started")

        result = SecurityTestResult(
            test_type="Login Form",
            target_url=url,
            status="safe",
        )

        try:
            # Fetch login page
            response = self.client.get(url)
            html = response.text

            # Check for common weak authentication indicators
            weak_indicators = [
                "password must be at least 4 characters",
                "password must be at least 3 characters",
                "username and password",
                "login with email",
            ]

            html_lower = html.lower()
            for indicator in weak_indicators:
                if indicator in html_lower:
                    finding = VulnerabilityFinding(
                        vulnerability_type="Weak Authentication",
                        severity=classify_severity("Weak Authentication"),
                        affected_url=url,
                        description=f"Potential weak authentication policy detected: {indicator}",
                        proof_of_concept=f"Indicator found in page: {indicator}",
                        remediation="Implement strong password policies and multi-factor authentication",
                        cwe_id=521,
                        owasp_category=get_owasp_category("Weak Authentication"),
                        test_type="Login Form",
                    )
                    result.findings.append(finding)
                    result.status = "vulnerable"
                    self.logger.warning(
                        f"[FINDING] Weak Authentication - {classify_severity('Weak Authentication')} - {url}"
                    )

            # Test with common weak credentials if provided
            if credentials:
                username = credentials.get("username", "admin")
                password = credentials.get("password", "admin")

                # Try common weak credentials
                weak_combos = [
                    ("admin", "admin"),
                    ("admin", "password"),
                    ("admin", "123456"),
                    ("admin", ""),
                    ("test", "test"),
                ]

                for user, pwd in weak_combos:
                    try:
                        # Try to login (this is a basic test - actual implementation would need form parsing)
                        login_response = self.client.post(
                            url, data={"username": user, "password": pwd}
                        )

                        # Check if login succeeded (basic check)
                        if login_response.status_code == 200 and "dashboard" in login_response.text.lower():
                            finding = VulnerabilityFinding(
                                vulnerability_type="Weak Authentication",
                                severity="Critical",
                                affected_url=url,
                                description=f"Login successful with weak credentials: {user}/{pwd}",
                                proof_of_concept=f"Credentials: {user}/{pwd}",
                                remediation="Implement account lockout and strong password requirements",
                                cwe_id=307,
                                owasp_category=get_owasp_category("Weak Authentication"),
                                test_type="Login Form",
                            )
                            result.findings.append(finding)
                            result.status = "vulnerable"
                            self.logger.warning(
                                f"[FINDING] Weak Authentication - Critical - {url} - Credentials: {user}/{pwd}"
                            )
                    except Exception:
                        pass

        except Exception as e:
            self.logger.error(f"[ERROR] Login form test failed: {e}")
            result.status = "error"
            result.error_message = str(e)

        result.execution_time = time.time() - start_time
        self.logger.info(
            f"[TEST] Login Form - {url} - {result.status} - Findings: {len(result.findings)}"
        )

        return result

    def test_session_management(self, base_url: str, session_cookie: Optional[str] = None) -> SecurityTestResult:
        """
        Test session management vulnerabilities.

        Args:
            base_url: Base URL of the website
            session_cookie: Optional session cookie to test

        Returns:
            SecurityTestResult with findings
        """
        start_time = time.time()

        self.logger.info(f"[TEST] Session Management - {base_url} - Started")

        result = SecurityTestResult(
            test_type="Session Management",
            target_url=base_url,
            status="safe",
        )

        try:
            # Test for session fixation
            # Create a session
            response1 = self.client.get(base_url)
            cookies1 = response1.cookies

            # Check if session ID is predictable
            session_ids = []
            for cookie in cookies1:
                if "session" in cookie.name.lower() or "sid" in cookie.name.lower():
                    session_ids.append(cookie.value)

            if session_ids:
                # Check if session IDs are sequential or predictable
                for sid in session_ids:
                    if len(sid) < 16:
                        finding = VulnerabilityFinding(
                            vulnerability_type="Weak Session Management",
                            severity=classify_severity("Weak Authentication"),
                            affected_url=base_url,
                            description=f"Session ID appears to be weak: {sid[:10]}...",
                            proof_of_concept=f"Session ID length: {len(sid)}",
                            remediation="Use cryptographically secure random session IDs",
                            cwe_id=613,
                            owasp_category=get_owasp_category("Weak Authentication"),
                            test_type="Session Management",
                        )
                        result.findings.append(finding)
                        result.status = "vulnerable"
                        self.logger.warning(
                            f"[FINDING] Weak Session Management - {base_url}"
                        )

            # Check for missing secure flag on cookies
            for cookie in cookies1:
                if "session" in cookie.name.lower() and not cookie.secure:
                    finding = VulnerabilityFinding(
                        vulnerability_type="Insecure Cookie",
                        severity="Medium",
                        affected_url=base_url,
                        description=f"Session cookie '{cookie.name}' missing Secure flag",
                        proof_of_concept=f"Cookie: {cookie.name}",
                        remediation="Set Secure flag on all session cookies",
                        cwe_id=614,
                        owasp_category=get_owasp_category("Security Misconfiguration"),
                        test_type="Session Management",
                    )
                    result.findings.append(finding)
                    result.status = "vulnerable"
                    self.logger.warning(
                        f"[FINDING] Insecure Cookie - Medium - {base_url}"
                    )

        except Exception as e:
            self.logger.error(f"[ERROR] Session management test failed: {e}")
            result.status = "error"
            result.error_message = str(e)

        result.execution_time = time.time() - start_time
        self.logger.info(
            f"[TEST] Session Management - {base_url} - {result.status} - Findings: {len(result.findings)}"
        )

        return result

    def test_authorization_bypass(
        self, sensitive_page: Dict[str, Any], base_url: str
    ) -> SecurityTestResult:
        """
        Test for authorization bypass vulnerabilities.

        Args:
            sensitive_page: Sensitive page information
            base_url: Base URL of the website

        Returns:
            SecurityTestResult with findings
        """
        start_time = time.time()
        url = sensitive_page.get("url", "")

        self.logger.info(f"[TEST] Authorization Bypass - {url} - Started")

        result = SecurityTestResult(
            test_type="Authorization Bypass",
            target_url=url,
            status="safe",
        )

        try:
            # Try to access without authentication
            response = self.client.get(url)

            # If page is accessible without auth, it might be vulnerable
            if response.status_code == 200 and sensitive_page.get("requires_auth", False):
                # Check if page content suggests it should be protected
                content_lower = response.text.lower()
                protected_indicators = [
                    "access denied",
                    "unauthorized",
                    "forbidden",
                    "login required",
                ]

                if not any(indicator in content_lower for indicator in protected_indicators):
                    finding = VulnerabilityFinding(
                        vulnerability_type="Authorization Bypass",
                        severity="High",
                        affected_url=url,
                        description="Sensitive page accessible without authentication",
                        proof_of_concept=f"Status code: {response.status_code}",
                        remediation="Implement proper access control and authentication checks",
                        cwe_id=284,
                        owasp_category=get_owasp_category("Broken Access Control"),
                        test_type="Authorization Bypass",
                    )
                    result.findings.append(finding)
                    result.status = "vulnerable"
                    self.logger.warning(
                        f"[FINDING] Authorization Bypass - High - {url}"
                    )

        except Exception as e:
            self.logger.error(f"[ERROR] Authorization bypass test failed: {e}")
            result.status = "error"
            result.error_message = str(e)

        result.execution_time = time.time() - start_time
        self.logger.info(
            f"[TEST] Authorization Bypass - {url} - {result.status} - Findings: {len(result.findings)}"
        )

        return result

    def close(self):
        """Close HTTP client."""
        self.client.close()
