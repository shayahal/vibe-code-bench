"""Main red team agent class for security testing."""

import os
from datetime import datetime
from typing import Dict, Optional, Any

# Load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip loading .env

from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic

from vibe_code_bench.red_team_agent.report_analyzer import ReportAnalyzer
from vibe_code_bench.red_team_agent.security_tester import SecurityTester
from vibe_code_bench.red_team_agent.report_generator import ReportGenerator
from vibe_code_bench.red_team_agent.models import TestingPlan, RedTeamReport, SecurityTestResult
from vibe_code_bench.red_team_agent.logging_config import setup_red_team_logging, get_logger

logger = get_logger(__name__)


def _create_default_llm():
    """Create a default LLM instance."""
    # Try OpenAI first
    if os.getenv("OPENAI_API_KEY"):
        return ChatOpenAI(model="gpt-4", temperature=0)
    # Try Anthropic
    elif os.getenv("ANTHROPIC_API_KEY"):
        return ChatAnthropic(model="claude-3-sonnet-20240229", temperature=0)
    # Try OpenRouter (supports multiple models)
    elif os.getenv("OPENROUTER_API_KEY"):
        return ChatOpenAI(
            model="openai/gpt-4",
            temperature=0,
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )
    else:
        logger.warning("No LLM API key found. LLM-guided testing will be disabled.")
        return None


class RedTeamAgent:
    """Main red team agent for security testing based on browsing agent reports."""

    def __init__(
        self,
        browsing_report_path: str,
        enable_automated_scanning: bool = True,
        enable_llm_testing: bool = True,
        enable_anchor_browser: bool = True,
        max_parallel_workers: int = 10,
        llm=None,
    ):
        """
        Initialize red team agent.

        Args:
            browsing_report_path: Path to browsing agent JSON report
            enable_automated_scanning: Whether to use external tools (nuclei, wapiti3, nikto)
            enable_llm_testing: Whether to use LLM-guided testing
            enable_anchor_browser: Whether to use Anchor Browser tools
            max_parallel_workers: Maximum parallel workers for testing
            llm: LangChain LLM instance (if None, will try to create default)
        """
        # Setup logging first
        run_id = f"red_team_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.run_dir, self.logger = setup_red_team_logging(run_id)
        self.run_id = run_id

        self.logger.info("[SETUP] Red Team Agent - Initialization - Started")
        self.logger.info(f"[SETUP] Browsing report: {browsing_report_path}")
        self.logger.info(f"[SETUP] Automated scanning: {enable_automated_scanning}")
        self.logger.info(f"[SETUP] LLM testing: {enable_llm_testing}")
        self.logger.info(f"[SETUP] Anchor Browser: {enable_anchor_browser}")

        self.browsing_report_path = browsing_report_path
        self.enable_automated_scanning = enable_automated_scanning
        self.enable_llm_testing = enable_llm_testing
        self.enable_anchor_browser = enable_anchor_browser
        self.max_parallel_workers = max_parallel_workers

        # Initialize LLM
        if llm is None and enable_llm_testing:
            self.llm = _create_default_llm()
        else:
            self.llm = llm

        # Initialize components
        self.report_analyzer = ReportAnalyzer()
        self.testing_plan: Optional[TestingPlan] = None
        self.security_tester: Optional[SecurityTester] = None
        self.report_generator: Optional[ReportGenerator] = None
        self.test_results: list[SecurityTestResult] = []
        self.final_report: Optional[RedTeamReport] = None

        self.logger.info("[SETUP] Red Team Agent - Initialization - Completed")

    def test(self) -> RedTeamReport:
        """
        Run complete security testing workflow.

        Returns:
            RedTeamReport object
        """
        self.logger.info("[WORKFLOW] Red Team Agent - Complete Testing Workflow - Started")

        try:
            # Phase 1: Analyze browsing report
            self.logger.info("[WORKFLOW] Phase 1: Report Analysis")
            self.testing_plan = self.report_analyzer.analyze(self.browsing_report_path)

            # Phase 2: Initialize security tester
            self.logger.info("[WORKFLOW] Phase 2: Initialize Security Tester")
            self.security_tester = SecurityTester(
                testing_plan=self.testing_plan,
                enable_automated_scanning=self.enable_automated_scanning,
                enable_llm_testing=self.enable_llm_testing,
                use_anchor_browser=self.enable_anchor_browser,
                max_parallel_workers=self.max_parallel_workers,
                llm=self.llm,
            )

            # Phase 3: Run all security tests
            self.logger.info("[WORKFLOW] Phase 3: Run Security Tests")
            self.test_results = self.security_tester.run_all_tests()

            # Phase 4: Generate report
            self.logger.info("[WORKFLOW] Phase 4: Generate Report")
            self.report_generator = ReportGenerator(base_url=self.testing_plan.base_url, testing_plan=self.testing_plan)

            testing_methodology = {
                "automated_scanning": self.enable_automated_scanning,
                "llm_testing": self.enable_llm_testing,
                "anchor_browser": self.enable_anchor_browser,
                "test_results_count": len(self.test_results),
            }

            self.final_report = self.report_generator.generate_report(
                self.test_results, testing_methodology
            )

            # Phase 5: Save report
            self.logger.info("[WORKFLOW] Phase 5: Save Report")
            report_path = self.report_generator.save_report(self.final_report, self.run_id, self.run_dir)

            self.logger.info("[WORKFLOW] Red Team Agent - Complete Testing Workflow - Completed")
            self.logger.info(f"[WORKFLOW] Report saved to: {report_path}")

            # Cleanup
            if self.security_tester:
                self.security_tester.cleanup()

            return self.final_report

        except Exception as e:
            self.logger.error(f"[ERROR] Red Team Agent workflow failed: {e}", exc_info=True)
            raise

    def generate_report(self, test_results: Optional[list[SecurityTestResult]] = None) -> str:
        """
        Generate and save security assessment report.

        Args:
            test_results: Optional test results (uses self.test_results if not provided)

        Returns:
            Path to saved report file
        """
        if test_results is None:
            test_results = self.test_results

        if not test_results:
            raise ValueError("No test results available. Run test() first.")

        if not self.report_generator:
            if not self.testing_plan:
                raise ValueError("No testing plan available. Run test() first.")
            self.report_generator = ReportGenerator(base_url=self.testing_plan.base_url, testing_plan=self.testing_plan)

        testing_methodology = {
            "automated_scanning": self.enable_automated_scanning,
            "llm_testing": self.enable_llm_testing,
            "anchor_browser": self.enable_anchor_browser,
            "test_results_count": len(test_results),
        }

        report = self.report_generator.generate_report(test_results, testing_methodology)
        report_path = self.report_generator.save_report(report, self.run_id)

        return str(report_path)
