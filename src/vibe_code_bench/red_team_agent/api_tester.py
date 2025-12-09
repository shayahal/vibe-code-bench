"""API endpoint testing module for authentication, rate limiting, and input validation."""

import time
import logging
from typing import List, Dict, Any, Optional

import httpx

from vibe_code_bench.red_team_agent.models import VulnerabilityFinding, SecurityTestResult
from vibe_code_bench.red_team_agent.utils import classify_severity, get_owasp_category, is_api_endpoint
from vibe_code_bench.red_team_agent.logging_config import get_logger

logger = get_logger(__name__)


class APITester:
    """Tests API endpoints for security vulnerabilities."""

    def __init__(self, timeout: int = 30):
        """
        Initialize API tester.

        Args:
            timeout: HTTP request timeout in seconds
        """
        self.logger = get_logger(f"{__name__}.APITester")
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout, follow_redirects=True)

    def test_authentication_bypass(self, api_endpoint: Dict[str, Any]) -> SecurityTestResult:
        """
        Test API endpoint for authentication bypass.

        Args:
            api_endpoint: API endpoint information

        Returns:
            SecurityTestResult with findings
        """
        start_time = time.time()
        url = api_endpoint.get("url", "")

        self.logger.info(f"[TEST] API Auth Bypass - {url} - Started")

        result = SecurityTestResult(
            test_type="API Authentication Bypass",
            target_url=url,
            status="safe",
        )

        try:
            # Try to access without authentication
            response = self.client.get(url)

            # If endpoint is accessible without auth, it might be vulnerable
            if response.status_code == 200:
                # Check response content
                try:
                    json_data = response.json()
                    # If we get valid JSON data, endpoint might be unprotected
                    finding = VulnerabilityFinding(
                        vulnerability_type="API Authentication Bypass",
                        severity="High",
                        affected_url=url,
                        description="API endpoint accessible without authentication",
                        proof_of_concept=f"Status code: {response.status_code}, Response: {str(json_data)[:100]}",
                        remediation="Implement proper API authentication (API keys, OAuth, JWT)",
                        cwe_id=306,
                        owasp_category=get_owasp_category("Broken Access Control"),
                        test_type="API Authentication Bypass",
                    )
                    result.findings.append(finding)
                    result.status = "vulnerable"
                    self.logger.warning(
                        f"[FINDING] API Auth Bypass - High - {url}"
                    )
                except Exception:
                    # Not JSON, might be HTML error page
                    pass

            # Try common API authentication bypass techniques
            bypass_headers = [
                {"X-API-Key": ""},
                {"Authorization": ""},
                {"X-Auth-Token": ""},
                {"X-Forwarded-For": "127.0.0.1"},
            ]

            for headers in bypass_headers:
                try:
                    bypass_response = self.client.get(url, headers=headers)
                    if bypass_response.status_code == 200:
                        finding = VulnerabilityFinding(
                            vulnerability_type="API Authentication Bypass",
                            severity="High",
                            affected_url=url,
                            description=f"API endpoint accessible with bypass headers: {headers}",
                            proof_of_concept=f"Headers: {headers}",
                            remediation="Implement proper API authentication and validate all headers",
                            cwe_id=306,
                            owasp_category=get_owasp_category("Broken Access Control"),
                            test_type="API Authentication Bypass",
                        )
                        result.findings.append(finding)
                        result.status = "vulnerable"
                        self.logger.warning(
                            f"[FINDING] API Auth Bypass - High - {url} - Headers: {headers}"
                        )
                except Exception:
                    pass

        except Exception as e:
            self.logger.error(f"[ERROR] API auth bypass test failed: {e}")
            result.status = "error"
            result.error_message = str(e)

        result.execution_time = time.time() - start_time
        self.logger.info(
            f"[TEST] API Auth Bypass - {url} - {result.status} - Findings: {len(result.findings)}"
        )

        return result

    def test_rate_limiting(self, api_endpoint: Dict[str, Any]) -> SecurityTestResult:
        """
        Test API endpoint for rate limiting.

        Args:
            api_endpoint: API endpoint information

        Returns:
            SecurityTestResult with findings
        """
        start_time = time.time()
        url = api_endpoint.get("url", "")

        self.logger.info(f"[TEST] API Rate Limiting - {url} - Started")

        result = SecurityTestResult(
            test_type="API Rate Limiting",
            target_url=url,
            status="safe",
        )

        try:
            # Send multiple rapid requests
            request_count = 100
            success_count = 0
            rate_limited_count = 0

            for i in range(request_count):
                try:
                    response = self.client.get(url)
                    if response.status_code == 200:
                        success_count += 1
                    elif response.status_code == 429:  # Too Many Requests
                        rate_limited_count += 1
                except Exception:
                    pass

            # If most requests succeeded, rate limiting might be weak or missing
            if success_count > request_count * 0.9:
                finding = VulnerabilityFinding(
                    vulnerability_type="Missing Rate Limiting",
                    severity="Medium",
                    affected_url=url,
                    description=f"API endpoint allows {success_count}/{request_count} rapid requests without rate limiting",
                    proof_of_concept=f"Success rate: {success_count}/{request_count}",
                    remediation="Implement rate limiting to prevent abuse and DoS attacks",
                    cwe_id=770,
                    owasp_category=get_owasp_category("Security Misconfiguration"),
                    test_type="API Rate Limiting",
                )
                result.findings.append(finding)
                result.status = "vulnerable"
                self.logger.warning(
                    f"[FINDING] Missing Rate Limiting - Medium - {url}"
                )

        except Exception as e:
            self.logger.error(f"[ERROR] API rate limiting test failed: {e}")
            result.status = "error"
            result.error_message = str(e)

        result.execution_time = time.time() - start_time
        self.logger.info(
            f"[TEST] API Rate Limiting - {url} - {result.status} - Findings: {len(result.findings)}"
        )

        return result

    def test_input_validation(self, api_endpoint: Dict[str, Any]) -> SecurityTestResult:
        """
        Test API endpoint for input validation vulnerabilities.

        Args:
            api_endpoint: API endpoint information

        Returns:
            SecurityTestResult with findings
        """
        start_time = time.time()
        url = api_endpoint.get("url", "")

        self.logger.info(f"[TEST] API Input Validation - {url} - Started")

        result = SecurityTestResult(
            test_type="API Input Validation",
            target_url=url,
            status="safe",
        )

        try:
            # Test with malicious input
            malicious_inputs = [
                "../../../etc/passwd",
                "<script>alert('XSS')</script>",
                "' OR '1'='1",
                "null",
                "undefined",
                "{}",
                "[]",
                "999999999999999999999999",
            ]

            for malicious_input in malicious_inputs:
                try:
                    # Try as query parameter
                    response = self.client.get(url, params={"id": malicious_input})

                    # Check for error messages that might reveal information
                    if response.status_code in [400, 500]:
                        error_text = response.text.lower()
                        if any(
                            keyword in error_text
                            for keyword in ["error", "exception", "stack trace", "sql"]
                        ):
                            finding = VulnerabilityFinding(
                                vulnerability_type="Information Disclosure",
                                severity="Medium",
                                affected_url=url,
                                description=f"API endpoint reveals error information with input: {malicious_input}",
                                proof_of_concept=f"Input: {malicious_input}, Status: {response.status_code}",
                                remediation="Implement proper error handling and sanitize error messages",
                                cwe_id=209,
                                owasp_category=get_owasp_category("Security Misconfiguration"),
                                test_type="API Input Validation",
                            )
                            result.findings.append(finding)
                            result.status = "vulnerable"
                            self.logger.warning(
                                f"[FINDING] Information Disclosure - Medium - {url}"
                            )
                            break
                except Exception:
                    pass

        except Exception as e:
            self.logger.error(f"[ERROR] API input validation test failed: {e}")
            result.status = "error"
            result.error_message = str(e)

        result.execution_time = time.time() - start_time
        self.logger.info(
            f"[TEST] API Input Validation - {url} - {result.status} - Findings: {len(result.findings)}"
        )

        return result

    def test_endpoint(self, api_endpoint: Dict[str, Any]) -> List[SecurityTestResult]:
        """
        Run all tests on an API endpoint.

        Args:
            api_endpoint: API endpoint information

        Returns:
            List of SecurityTestResult objects
        """
        results = []

        # Test authentication bypass
        auth_result = self.test_authentication_bypass(api_endpoint)
        results.append(auth_result)

        # Test rate limiting
        rate_result = self.test_rate_limiting(api_endpoint)
        results.append(rate_result)

        # Test input validation
        input_result = self.test_input_validation(api_endpoint)
        results.append(input_result)

        return results

    def close(self):
        """Close HTTP client."""
        self.client.close()
