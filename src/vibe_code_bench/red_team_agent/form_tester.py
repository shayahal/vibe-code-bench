"""Form testing module for SQL injection, XSS, and CSRF vulnerabilities."""

# Load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip loading .env

import time
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from vibe_code_bench.red_team_agent.models import VulnerabilityFinding, SecurityTestResult
from vibe_code_bench.red_team_agent.utils import (
    generate_sql_injection_payloads,
    generate_xss_payloads,
    detect_csrf_token,
    classify_severity,
    get_owasp_category,
)
from vibe_code_bench.red_team_agent.logging_config import get_logger

logger = get_logger(__name__)

# Try to import Anchor Browser tools
try:
    from langchain_anchorbrowser import AnchorContentTool, AnchorScreenshotTool
    ANCHOR_BROWSER_AVAILABLE = True
except ImportError:
    ANCHOR_BROWSER_AVAILABLE = False
    logger.warning(
        "langchain-anchorbrowser not available. "
        "Install with: pip install langchain-anchorbrowser. "
        "Some JavaScript-heavy tests will be limited."
    )


class FormTester:
    """Tests forms for SQL injection, XSS, and CSRF vulnerabilities."""

    def __init__(self, use_anchor_browser: bool = True, timeout: int = 30):
        """
        Initialize form tester.

        Args:
            use_anchor_browser: Whether to use Anchor Browser tools
            timeout: HTTP request timeout in seconds
        """
        self.logger = get_logger(f"{__name__}.FormTester")
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
                    self.screenshot_tool = AnchorScreenshotTool()
                    self.logger.info("[SETUP] Anchor Browser tools initialized")
            except Exception as e:
                self.logger.warning(f"[SETUP] Failed to initialize Anchor Browser: {e}")
                self.use_anchor_browser = False

    def test_sql_injection(
        self, form_info: Dict[str, Any], base_url: str
    ) -> SecurityTestResult:
        """
        Test form for SQL injection vulnerabilities.

        Args:
            form_info: Form information dictionary
            base_url: Base URL of the website

        Returns:
            SecurityTestResult with findings
        """
        start_time = time.time()
        url = form_info.get("url", "")
        action = form_info.get("action", "")
        method = form_info.get("method", "get").lower()
        fields = form_info.get("fields", [])

        self.logger.info(f"[TEST] SQL Injection - {url} - Started")

        result = SecurityTestResult(
            test_type="SQL Injection",
            target_url=url,
            status="safe",
        )

        if not fields:
            self.logger.info(f"[TEST] SQL Injection - {url} - No fields to test")
            result.status = "safe"
            result.execution_time = time.time() - start_time
            return result

        # Resolve form action URL
        form_url = urljoin(url, action) if action else url

        # Get SQL injection payloads
        payloads = generate_sql_injection_payloads()

        # Test each field with each payload
        for field in fields:
            field_name = field.get("name", "")
            if not field_name:
                continue

            for payload in payloads:
                try:
                    # Prepare form data
                    form_data = {}
                    for f in fields:
                        f_name = f.get("name", "")
                        if f_name == field_name:
                            form_data[f_name] = payload
                        else:
                            # Use default values for other fields
                            f_type = f.get("type", "text")
                            if f_type == "email":
                                form_data[f_name] = "test@example.com"
                            elif f_type == "password":
                                form_data[f_name] = "testpassword"
                            else:
                                form_data[f_name] = "test"

                    # Submit form
                    if method == "post":
                        response = self.client.post(form_url, data=form_data)
                    else:
                        response = self.client.get(form_url, params=form_data)

                    # Check for SQL error indicators
                    response_text = response.text.lower()
                    sql_errors = [
                        "sql syntax",
                        "mysql error",
                        "postgresql error",
                        "sqlite error",
                        "ora-",
                        "sql server",
                        "sql exception",
                        "sql warning",
                        "sqlstate",
                        "syntax error",
                    ]

                    if any(error in response_text for error in sql_errors):
                        # Potential SQL injection found
                        finding = VulnerabilityFinding(
                            vulnerability_type="SQL Injection",
                            severity=classify_severity("SQL Injection"),
                            affected_url=form_url,
                            description=f"Potential SQL injection vulnerability in field '{field_name}'",
                            proof_of_concept=f"Payload: {payload}",
                            remediation="Use parameterized queries or prepared statements",
                            cwe_id=89,
                            owasp_category=get_owasp_category("SQL Injection"),
                            test_type="SQL Injection",
                            additional_info={
                                "field_name": field_name,
                                "payload": payload,
                                "response_status": response.status_code,
                            },
                        )
                        result.findings.append(finding)
                        result.status = "vulnerable"
                        self.logger.warning(
                            f"[FINDING] SQL Injection - Critical - {form_url} - Field: {field_name}"
                        )

                except Exception as e:
                    self.logger.error(f"[ERROR] SQL Injection test failed: {e}")

        result.execution_time = time.time() - start_time
        self.logger.info(
            f"[TEST] SQL Injection - {url} - {result.status} - Findings: {len(result.findings)}"
        )

        return result

    def test_xss(
        self, form_info: Dict[str, Any], base_url: str
    ) -> SecurityTestResult:
        """
        Test form for XSS vulnerabilities.

        Args:
            form_info: Form information dictionary
            base_url: Base URL of the website

        Returns:
            SecurityTestResult with findings
        """
        start_time = time.time()
        url = form_info.get("url", "")
        action = form_info.get("action", "")
        method = form_info.get("method", "get").lower()
        fields = form_info.get("fields", [])

        self.logger.info(f"[TEST] XSS - {url} - Started")

        result = SecurityTestResult(
            test_type="XSS",
            target_url=url,
            status="safe",
        )

        if not fields:
            self.logger.info(f"[TEST] XSS - {url} - No fields to test")
            result.status = "safe"
            result.execution_time = time.time() - start_time
            return result

        # Resolve form action URL
        form_url = urljoin(url, action) if action else url

        # Get XSS payloads
        payloads = generate_xss_payloads()

        # Test each field with each payload
        for field in fields:
            field_name = field.get("name", "")
            if not field_name:
                continue

            for payload in payloads:
                try:
                    # Prepare form data
                    form_data = {}
                    for f in fields:
                        f_name = f.get("name", "")
                        if f_name == field_name:
                            form_data[f_name] = payload
                        else:
                            # Use default values
                            f_type = f.get("type", "text")
                            if f_type == "email":
                                form_data[f_name] = "test@example.com"
                            elif f_type == "password":
                                form_data[f_name] = "testpassword"
                            else:
                                form_data[f_name] = "test"

                    # Submit form
                    if method == "post":
                        response = self.client.post(form_url, data=form_data)
                    else:
                        response = self.client.get(form_url, params=form_data)

                    # Check if payload is reflected in response
                    response_text = response.text
                    if payload in response_text:
                        # Check if payload is executed (basic check)
                        if "<script>" in payload.lower() and "<script>" in response_text.lower():
                            finding = VulnerabilityFinding(
                                vulnerability_type="XSS",
                                severity=classify_severity("XSS"),
                                affected_url=form_url,
                                description=f"Potential XSS vulnerability in field '{field_name}'",
                                proof_of_concept=f"Payload: {payload}",
                                remediation="Sanitize and validate all user input, use Content Security Policy",
                                cwe_id=79,
                                owasp_category=get_owasp_category("XSS"),
                                test_type="XSS",
                                additional_info={
                                    "field_name": field_name,
                                    "payload": payload,
                                    "xss_type": "reflected",
                                    "response_status": response.status_code,
                                },
                            )
                            result.findings.append(finding)
                            result.status = "vulnerable"
                            self.logger.warning(
                                f"[FINDING] XSS - {classify_severity('XSS')} - {form_url} - Field: {field_name}"
                            )

                    # For DOM-based XSS, use Anchor Browser if available
                    if self.use_anchor_browser:
                        try:
                            # Navigate and check for DOM XSS
                            content_result = self.content_tool.invoke({"url": form_url})
                            if payload in str(content_result):
                                finding = VulnerabilityFinding(
                                    vulnerability_type="XSS",
                                    severity=classify_severity("XSS"),
                                    affected_url=form_url,
                                    description=f"Potential DOM-based XSS vulnerability in field '{field_name}'",
                                    proof_of_concept=f"Payload: {payload}",
                                    remediation="Sanitize and validate all user input, use Content Security Policy",
                                    cwe_id=79,
                                    owasp_category=get_owasp_category("XSS"),
                                    test_type="XSS",
                                    additional_info={
                                        "field_name": field_name,
                                        "payload": payload,
                                        "xss_type": "dom-based",
                                    },
                                )
                                result.findings.append(finding)
                                result.status = "vulnerable"
                                self.logger.warning(
                                    f"[FINDING] XSS (DOM-based) - {classify_severity('XSS')} - {form_url}"
                                )
                        except Exception as e:
                            self.logger.debug(f"[DEBUG] Anchor Browser XSS test failed: {e}")

                except Exception as e:
                    self.logger.error(f"[ERROR] XSS test failed: {e}")

        result.execution_time = time.time() - start_time
        self.logger.info(
            f"[TEST] XSS - {url} - {result.status} - Findings: {len(result.findings)}"
        )

        return result

    def test_csrf(
        self, form_info: Dict[str, Any], base_url: str
    ) -> SecurityTestResult:
        """
        Test form for CSRF protection.

        Args:
            form_info: Form information dictionary
            base_url: Base URL of the website

        Returns:
            SecurityTestResult with findings
        """
        start_time = time.time()
        url = form_info.get("url", "")
        action = form_info.get("action", "")
        method = form_info.get("method", "get").lower()

        self.logger.info(f"[TEST] CSRF - {url} - Started")

        result = SecurityTestResult(
            test_type="CSRF",
            target_url=url,
            status="safe",
        )

        # Only test POST forms (GET forms are less critical for CSRF)
        if method != "post":
            self.logger.info(f"[TEST] CSRF - {url} - GET method, skipping")
            result.status = "safe"
            result.execution_time = time.time() - start_time
            return result

        try:
            # Fetch the form page
            response = self.client.get(url)
            html = response.text

            # Check for CSRF token
            has_csrf_token = detect_csrf_token(html)

            if not has_csrf_token:
                # Try to submit form without token
                form_url = urljoin(url, action) if action else url

                # Prepare minimal form data
                form_data = {"test": "test"}

                # Submit form without CSRF token
                submit_response = self.client.post(form_url, data=form_data)

                # If form submission succeeds without token, it's vulnerable
                if submit_response.status_code in [200, 302, 301]:
                    finding = VulnerabilityFinding(
                        vulnerability_type="CSRF",
                        severity=classify_severity("CSRF"),
                        affected_url=form_url,
                        description="Form lacks CSRF protection",
                        proof_of_concept="Form can be submitted without CSRF token",
                        remediation="Implement CSRF tokens and validate them on form submission",
                        cwe_id=352,
                        owasp_category=get_owasp_category("CSRF"),
                        test_type="CSRF",
                        additional_info={
                            "has_csrf_token": False,
                            "response_status": submit_response.status_code,
                        },
                    )
                    result.findings.append(finding)
                    result.status = "vulnerable"
                    self.logger.warning(
                        f"[FINDING] CSRF - {classify_severity('CSRF')} - {form_url}"
                    )
                else:
                    self.logger.info(f"[TEST] CSRF - {url} - Form submission blocked (may have protection)")
            else:
                self.logger.info(f"[TEST] CSRF - {url} - CSRF token detected")

        except Exception as e:
            self.logger.error(f"[ERROR] CSRF test failed: {e}")
            result.status = "error"
            result.error_message = str(e)

        result.execution_time = time.time() - start_time
        self.logger.info(
            f"[TEST] CSRF - {url} - {result.status} - Findings: {len(result.findings)}"
        )

        return result

    def test_form_group(
        self, form_group: Dict[str, Any], base_url: str
    ) -> List[SecurityTestResult]:
        """
        Test a group of forms of the same type.

        Args:
            form_group: Form group dictionary with type and forms list
            base_url: Base URL of the website

        Returns:
            List of SecurityTestResult objects
        """
        form_type = form_group.get("type", "generic")
        forms = form_group.get("forms", [])

        self.logger.info(f"[TEST] Form Group - {form_type} - {len(forms)} forms - Started")

        results = []

        for form_info in forms:
            # Test SQL injection
            sql_result = self.test_sql_injection(form_info, base_url)
            results.append(sql_result)

            # Test XSS
            xss_result = self.test_xss(form_info, base_url)
            results.append(xss_result)

            # Test CSRF (only for POST forms)
            if form_info.get("method", "get").lower() == "post":
                csrf_result = self.test_csrf(form_info, base_url)
                results.append(csrf_result)

        self.logger.info(f"[TEST] Form Group - {form_type} - Completed - {len(results)} tests")

        return results

    def close(self):
        """Close HTTP client."""
        self.client.close()
