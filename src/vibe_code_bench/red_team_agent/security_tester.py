"""Security tester orchestrator that coordinates all testing modules."""

import logging
from typing import List, Dict, Any, Optional

from vibe_code_bench.red_team_agent.models import SecurityTestResult, TestingPlan
from vibe_code_bench.red_team_agent.form_tester import FormTester
from vibe_code_bench.red_team_agent.auth_tester import AuthTester
from vibe_code_bench.red_team_agent.api_tester import APITester
from vibe_code_bench.red_team_agent.tool_integration import ToolIntegration
from vibe_code_bench.red_team_agent.llm_tester import LLMTester
from vibe_code_bench.red_team_agent.logging_config import get_logger

logger = get_logger(__name__)


class SecurityTester:
    """Orchestrates all security testing modules."""

    def __init__(
        self,
        testing_plan: TestingPlan,
        enable_automated_scanning: bool = True,
        enable_llm_testing: bool = True,
        use_anchor_browser: bool = True,
        max_parallel_workers: int = 10,
        llm=None,
    ):
        """
        Initialize security tester.

        Args:
            testing_plan: Testing plan from report analyzer
            enable_automated_scanning: Whether to use external tools (nuclei, wapiti3, nikto)
            enable_llm_testing: Whether to use LLM-guided testing
            use_anchor_browser: Whether to use Anchor Browser tools
            max_parallel_workers: Maximum parallel workers for testing
            llm: LangChain LLM instance for LLM testing
        """
        self.logger = get_logger(f"{__name__}.SecurityTester")
        self.testing_plan = testing_plan
        self.enable_automated_scanning = enable_automated_scanning
        self.enable_llm_testing = enable_llm_testing
        self.use_anchor_browser = use_anchor_browser
        self.max_parallel_workers = max_parallel_workers

        # Initialize testing modules
        self.form_tester = FormTester(use_anchor_browser=use_anchor_browser)
        self.auth_tester = AuthTester(use_anchor_browser=use_anchor_browser)
        self.api_tester = APITester()
        self.tool_integration = ToolIntegration() if enable_automated_scanning else None
        self.llm_tester = LLMTester(llm, use_anchor_browser=use_anchor_browser) if enable_llm_testing and llm else None

        self.all_results: List[SecurityTestResult] = []

    def run_automated_scanning(self) -> List[SecurityTestResult]:
        """
        Run automated vulnerability scanning tools.

        Returns:
            List of SecurityTestResult objects
        """
        if not self.enable_automated_scanning or not self.tool_integration:
            self.logger.info("[PHASE] Automated Scanning - Skipped")
            return []

        self.logger.info("[PHASE] Automated Scanning - Started")

        results = []
        base_url = self.testing_plan.base_url

        # Collect all URLs from attack surfaces
        all_urls = []
        for attack_surface in self.testing_plan.attack_surfaces:
            for item in attack_surface.items:
                if isinstance(item, dict) and "url" in item:
                    all_urls.append(item["url"])

        # If no URLs from attack surfaces, at least test the base URL
        if not all_urls:
            all_urls = [self.testing_plan.base_url]
            self.logger.info(f"[TOOL] No attack surfaces found, testing base URL: {self.testing_plan.base_url}")

        # Run nuclei in batches
        if self.tool_integration.available_tools.get("nuclei", False):
            self.logger.info(f"[TOOL] Running nuclei on {len(all_urls)} URLs")
            nuclei_results = self.tool_integration.run_nuclei(all_urls)
            results.extend(nuclei_results)

        # Run wapiti3
        if self.tool_integration.available_tools.get("wapiti3", False):
            self.logger.info(f"[TOOL] Running wapiti3 on {base_url}")
            wapiti_results = self.tool_integration.run_wapiti3(base_url)
            results.extend(wapiti_results)

        # Run nikto
        if self.tool_integration.available_tools.get("nikto", False):
            self.logger.info(f"[TOOL] Running nikto on {base_url}")
            nikto_results = self.tool_integration.run_nikto(base_url)
            results.extend(nikto_results)

        self.logger.info(f"[PHASE] Automated Scanning - Completed - {len(results)} results")
        return results

    def run_form_testing(self) -> List[SecurityTestResult]:
        """
        Run form testing on all forms.

        Returns:
            List of SecurityTestResult objects
        """
        self.logger.info("[PHASE] Form Testing - Started")

        results = []
        base_url = self.testing_plan.base_url

        # Find form attack surfaces
        form_surfaces = [
            as_ for as_ in self.testing_plan.attack_surfaces
            if as_.category.startswith("forms_")
        ]

        # Test each form group
        for form_surface in form_surfaces:
            # Extract form groups from items
            for item in form_surface.items:
                if isinstance(item, dict) and "type" in item:
                    form_group = item
                    form_results = self.form_tester.test_form_group(form_group, base_url)
                    results.extend(form_results)

        self.logger.info(f"[PHASE] Form Testing - Completed - {len(results)} results")
        return results

    def run_auth_testing(self) -> List[SecurityTestResult]:
        """
        Run authentication testing.

        Returns:
            List of SecurityTestResult objects
        """
        self.logger.info("[PHASE] Authentication Testing - Started")

        results = []
        base_url = self.testing_plan.base_url

        # Find auth endpoints
        auth_surfaces = [
            as_ for as_ in self.testing_plan.attack_surfaces
            if as_.category == "auth_endpoints"
        ]

        for auth_surface in auth_surfaces:
            for endpoint in auth_surface.items:
                if isinstance(endpoint, dict):
                    # Test login form
                    login_result = self.auth_tester.test_login_form(endpoint)
                    results.append(login_result)

        # Test session management
        session_result = self.auth_tester.test_session_management(base_url)
        results.append(session_result)

        # Test authorization bypass on sensitive pages
        sensitive_surfaces = [
            as_ for as_ in self.testing_plan.attack_surfaces
            if as_.category == "sensitive_pages"
        ]

        for sensitive_surface in sensitive_surfaces:
            for page in sensitive_surface.items:
                if isinstance(page, dict):
                    auth_bypass_result = self.auth_tester.test_authorization_bypass(page, base_url)
                    results.append(auth_bypass_result)

        self.logger.info(f"[PHASE] Authentication Testing - Completed - {len(results)} results")
        return results

    def run_api_testing(self) -> List[SecurityTestResult]:
        """
        Run API endpoint testing.

        Returns:
            List of SecurityTestResult objects
        """
        self.logger.info("[PHASE] API Testing - Started")

        results = []

        # Find API endpoints
        api_surfaces = [
            as_ for as_ in self.testing_plan.attack_surfaces
            if as_.category == "api_endpoints"
        ]

        for api_surface in api_surfaces:
            for endpoint in api_surface.items:
                if isinstance(endpoint, dict):
                    endpoint_results = self.api_tester.test_endpoint(endpoint)
                    results.extend(endpoint_results)

        self.logger.info(f"[PHASE] API Testing - Completed - {len(results)} results")
        return results

    def run_llm_testing(self, previous_findings: List) -> List[SecurityTestResult]:
        """
        Run LLM-guided intelligent testing.

        Args:
            previous_findings: Previous vulnerability findings for context

        Returns:
            List of SecurityTestResult objects
        """
        if not self.enable_llm_testing or not self.llm_tester:
            self.logger.info("[PHASE] LLM-Guided Testing - Skipped")
            return []

        self.logger.info("[PHASE] LLM-Guided Testing - Started")

        # Collect pages from attack surfaces
        pages = []
        for attack_surface in self.testing_plan.attack_surfaces:
            for item in attack_surface.items:
                if isinstance(item, dict) and "url" in item:
                    pages.append(item)

        # If no pages from attack surfaces, create a page entry for the base URL
        if not pages:
            # Try to get pages from the original browsing report
            # For now, create a basic page entry for the base URL
            pages = [{
                "url": self.testing_plan.base_url,
                "page_type": "homepage",
                "requires_auth": False,
            }]
            self.logger.info(f"[PHASE] No attack surfaces found, testing base URL with LLM: {self.testing_plan.base_url}")

        results = self.llm_tester.test_pages(pages, previous_findings)

        self.logger.info(f"[PHASE] LLM-Guided Testing - Completed - {len(results)} results")
        return results

    def run_all_tests(self) -> List[SecurityTestResult]:
        """
        Run all security tests in sequence.

        Returns:
            List of all SecurityTestResult objects
        """
        self.logger.info("[PHASE] Security Testing - Complete Test Suite - Started")

        all_results = []

        # Phase 1: Automated scanning (parallel)
        automated_results = self.run_automated_scanning()
        all_results.extend(automated_results)

        # Phase 2: Form testing (parallel batches)
        form_results = self.run_form_testing()
        all_results.extend(form_results)

        # Phase 3: Authentication testing (sequential)
        auth_results = self.run_auth_testing()
        all_results.extend(auth_results)

        # Phase 4: API testing (parallel batches)
        api_results = self.run_api_testing()
        all_results.extend(api_results)

        # Phase 5: LLM-guided testing (sequential, uses previous findings)
        previous_findings = []
        for result in all_results:
            previous_findings.extend(result.findings)

        llm_results = self.run_llm_testing(previous_findings)
        all_results.extend(llm_results)

        self.all_results = all_results

        self.logger.info(f"[PHASE] Security Testing - Complete Test Suite - Completed")
        self.logger.info(f"[PHASE] Total test results: {len(all_results)}")
        self.logger.info(f"[PHASE] Total findings: {sum(len(r.findings) for r in all_results)}")

        return all_results

    def cleanup(self):
        """Cleanup resources."""
        self.form_tester.close()
        self.auth_tester.close()
        self.api_tester.close()
