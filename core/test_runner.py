"""
Test suite execution for the Red Team Agent.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class TestRunner:
    """Handles execution of test scenarios."""
    
    def __init__(
        self,
        agent,
        target_url: str,
        test_results: List[Dict[str, Any]],
        run_dir: Optional[Path] = None,
        log_trail: Optional[callable] = None
    ):
        """
        Initialize the test runner.
        
        Args:
            agent: The LangChain agent to use for execution
            target_url: Target URL being tested
            test_results: List to append test results to
            run_dir: Optional run directory
            log_trail: Optional trail logging function
        """
        self.agent = agent
        self.target_url = target_url
        self.test_results = test_results
        self.run_dir = run_dir
        self.log_trail = log_trail or (lambda *args, **kwargs: None)
    
    def _test_llm_connection(self) -> bool:
        """Test if LLM connection works."""
        try:
            # Quick test with minimal tokens
            from langchain_core.messages import HumanMessage
            test_response = self.agent.llm.invoke([HumanMessage(content="OK")])
            if test_response and hasattr(test_response, 'content'):
                logger.info("✓ LLM connection test successful")
                return True
            return False
        except Exception as e:
            error_msg = str(e)
            # Check for 402 error (insufficient credits) from OpenRouter
            if "402" in error_msg or ("insufficient credits" in error_msg.lower() and self.agent.provider == "openrouter"):
                logger.warning("Detected 402 error (insufficient credits) from OpenRouter during connection test")
                try:
                    self.agent._switch_to_anthropic()
                    logger.info("Retrying connection test with Anthropic provider...")
                    # Retry connection test with Anthropic
                    test_response = self.agent.llm.invoke([HumanMessage(content="OK")])
                    if test_response and hasattr(test_response, 'content'):
                        logger.info("✓ LLM connection test successful after switching to Anthropic")
                        return True
                except Exception as retry_error:
                    logger.error(f"Connection test failed even after switching to Anthropic: {str(retry_error)[:200]}")
                    return False
            # Don't log full error for known endpoint issues
            elif "Not Found" in error_msg or "404" in error_msg:
                logger.error(f"LLM endpoint not available: {self.agent.provider}")
            elif "401" in error_msg or "Unauthorized" in error_msg:
                logger.error(f"LLM authentication failed: {self.agent.provider}")
            else:
                logger.error(f"LLM connection test failed: {error_msg[:200]}")
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
                "provider": self.agent.provider
            }, error_msg)
            raise RuntimeError(error_msg)
        
        self.log_trail("execution_mode_selected", {
            "mode": "llm_agent",
            "provider": self.agent.provider
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
                result = self.agent.agent.invoke({"messages": [("human", scenario)]})
                logger.info(f"Scenario {i} completed successfully")
                logger.debug(f"Result: {str(result)[:200]}...")
                self.log_trail("scenario_completed", {
                    "scenario_number": i,
                    "success": True
                }, f"Scenario {i} completed successfully via LLM agent")
            except Exception as e:
                error_str = str(e)
                error_msg = f"Agent failed for scenario {i}: {error_str[:200]}"
                
                # Check for 402 error (insufficient credits) from OpenRouter
                if "402" in error_str or ("insufficient credits" in error_str.lower() and self.agent.provider == "openrouter"):
                    logger.warning("Detected 402 error (insufficient credits) from OpenRouter")
                    try:
                        self.agent._switch_to_anthropic()
                        logger.info("Retrying scenario with Anthropic provider...")
                        # Retry the scenario with the new provider
                        result = self.agent.agent.invoke({"messages": [("human", scenario)]})
                        logger.info(f"Scenario {i} completed successfully after provider switch")
                        self.log_trail("scenario_completed", {
                            "scenario_number": i,
                            "success": True,
                            "retried_with_anthropic": True
                        }, f"Scenario {i} completed successfully after switching to Anthropic")
                        continue
                    except Exception as retry_error:
                        logger.error(f"Retry with Anthropic also failed: {str(retry_error)[:200]}")
                        error_msg = f"Agent failed for scenario {i} even after switching to Anthropic: {str(retry_error)[:200]}"
                        self.log_trail("scenario_failed", {
                            "scenario_number": i,
                            "error": str(retry_error)[:200],
                            "provider_switch_attempted": True
                        }, error_msg)
                        raise RuntimeError(error_msg) from retry_error
                else:
                    logger.error(error_msg)
                    self.log_trail("scenario_failed", {
                        "scenario_number": i,
                        "error": error_str[:200]
                    }, error_msg)
                    raise RuntimeError(error_msg) from e
        
        return "Test suite completed successfully"

