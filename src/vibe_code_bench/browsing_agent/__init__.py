"""Browsing agent for discovering pages on web applications."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any, List
from urllib.parse import urlparse

# Load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, skip loading .env

from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI as OpenRouterChatOpenAI

from vibe_code_bench.browsing_agent.agent import create_browsing_agent_tools, create_langchain_agent
from vibe_code_bench.browsing_agent.browser import BrowserWrapper
from vibe_code_bench.browsing_agent.discovery import DiscoveryEngine
from vibe_code_bench.browsing_agent.analyzer import PageAnalyzer
from vibe_code_bench.browsing_agent.auth import AuthenticationHandler
from vibe_code_bench.browsing_agent.models import PageInfo, DiscoveryResult

logger = logging.getLogger(__name__)


def _create_default_llm():
    """Create a default LLM instance."""
    import os

    # Try OpenAI first
    if os.getenv("OPENAI_API_KEY"):
        return ChatOpenAI(model="gpt-4", temperature=0)
    # Try Anthropic
    elif os.getenv("ANTHROPIC_API_KEY"):
        return ChatAnthropic(model="claude-3-5-sonnet-20240620", temperature=0)
    # Try OpenRouter (supports multiple models)
    elif os.getenv("OPENROUTER_API_KEY"):
        # OpenRouter uses OpenAI-compatible API
        return ChatOpenAI(
            model="openai/gpt-4",
            temperature=0,
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )
    else:
        # Return None if no API key - agent will use direct crawling instead
        logger.warning("No LLM API key found. Agent will use direct crawling without LLM guidance.")
        return None


class BrowsingAgent:
    """Main browsing agent class for discovering pages on websites."""

    def __init__(
        self,
        max_pages: int = 50,
        respect_robots: bool = False,
        enable_javascript: bool = True,
        headless: bool = True,
        llm=None,
        max_iterations: int = 100,
    ):
        """
        Initialize browsing agent.

        Args:
            max_pages: Maximum number of pages to discover
            respect_robots: Whether to respect robots.txt rules
            enable_javascript: Whether to enable JavaScript rendering
            headless: Run browser in headless mode
            llm: LangChain LLM instance (if None, will try to create default)
            max_iterations: Maximum iterations for LangChain agent
        """
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.enable_javascript = enable_javascript
        self.headless = headless

        # Initialize components
        self.browser = BrowserWrapper(headless=headless, enable_javascript=enable_javascript)
        self.discovery = DiscoveryEngine(respect_robots=respect_robots)
        self.analyzer = PageAnalyzer()
        self.auth_handler = AuthenticationHandler()

        # Initialize LLM
        if llm is None:
            self.llm = _create_default_llm()
        else:
            self.llm = llm

        # Create LangChain agent (only if LLM is available)
        self.langchain_agent = None
        if self.llm is not None:
            tools = create_browsing_agent_tools(
                self.browser, self.discovery, self.analyzer, self.auth_handler
            )
            self.langchain_agent = create_langchain_agent(self.llm, tools, max_iterations=max_iterations)

        # State tracking
        self.discovered_pages: List[PageInfo] = []
        self.visited_urls: set = set()
        self.base_url: Optional[str] = None
        
        # Error logging
        self.error_logger = None

    def discover(
        self, url: str, auth_credentials: Optional[Dict[str, str]] = None, error_log_path: Optional[Path] = None
    ) -> DiscoveryResult:
        """
        Discover pages from a website.

        Args:
            url: Base URL of the website to discover
            auth_credentials: Optional dictionary with 'username' and 'password' for authentication
            error_log_path: Optional path to error log file

        Returns:
            DiscoveryResult with discovered pages
        """
        # Setup error logging if path provided
        if error_log_path:
            from vibe_code_bench.core.error_logger import setup_error_logging
            self.error_logger = setup_error_logging(error_log_path)
        
        self.base_url = url
        self.discovered_pages = []
        self.visited_urls = set()

        try:
            # Start browser
            self.browser.start()

            # Parse robots.txt first
            robots_info = self.discovery.parse_robots(url)
            sitemap_urls = robots_info.get("sitemap_urls", [])

            # Check sitemap
            sitemap_urls_list = self.discovery.check_sitemap(url)
            sitemap_used = len(sitemap_urls_list) > 0

            # Build initial URL queue (only same domain)
            url_queue = set()
            base_parsed = urlparse(url)
            base_domain = base_parsed.netloc.lower()
            
            if sitemap_urls_list:
                # Filter sitemap URLs to only same domain
                same_domain_sitemap_urls = [
                    u for u in sitemap_urls_list[: self.max_pages]
                    if urlparse(u).netloc.lower() == base_domain
                ]
                url_queue.update(same_domain_sitemap_urls)
            
            # Always start with the base URL
            url_queue.add(url)

            # Authenticate if needed
            authentication_required = False
            if auth_credentials:
                # Try to find login page
                homepage_result = self.browser.fetch_page(url)
                if homepage_result.get("success"):
                    login_form = self.auth_handler.detect_login_form(homepage_result["html"], url)
                    if login_form:
                        auth_result = self.auth_handler.authenticate(
                            self.browser, login_form["form_url"], auth_credentials
                        )
                        if auth_result.get("success"):
                            authentication_required = True
                            logger.info("Authentication successful")

            # Use LangChain agent for guidance if available
            if self.langchain_agent is not None:
                agent_input = f"""Discover up to {self.max_pages} pages from {url}.
                Current discovered pages: {len(self.discovered_pages)}.
                Start by checking sitemap and robots.txt, then crawl links systematically.
                Prioritize navigation links. Stop when you reach {self.max_pages} pages."""

                # Run agent for guidance - raise exception on failure
                try:
                    agent_result = self.langchain_agent.invoke({"input": agent_input})
                    logger.info(f"Agent guidance: {agent_result.get('output', '')}")
                except Exception as e:
                    logger.warning(f"LangChain agent invocation failed: {e}")
                    if self.error_logger:
                        self.error_logger.log_exception(
                            e,
                            context="browsing_agent.discover.langchain_agent",
                            metadata={"url": url, "agent_input": agent_input[:200]}
                        )
                    # Continue without agent guidance
                    agent_result = {"output": "Agent guidance unavailable"}

            # Also do direct crawling if agent didn't find enough pages
            # This ensures we reach the max_pages limit
            while len(self.discovered_pages) < self.max_pages and url_queue:
                current_url = url_queue.pop()

                # Skip if already visited
                if self.discovery.is_visited(current_url):
                    continue

                # Check robots.txt
                if not self.discovery.can_fetch(current_url):
                    continue

                # Fetch page - catch exceptions and skip this URL if it fails
                try:
                    page_result = self.browser.fetch_page(current_url)
                    if not page_result.get("success"):
                        logger.debug(f"Skipping {current_url}: fetch returned success=False")
                        continue
                except Exception as e:
                    logger.warning(f"Failed to fetch {current_url}: {e}. Skipping and continuing.")
                    if self.error_logger:
                        self.error_logger.log_exception(
                            e,
                            context=f"browsing_agent.discover.fetch_page",
                            metadata={"url": current_url}
                        )
                    continue

                # Mark as visited
                self.discovery.mark_visited(current_url)
                self.visited_urls.add(current_url)

                # Analyze page - catch exceptions and skip this URL if analysis fails
                try:
                    html = page_result["html"]
                    metadata = self.analyzer.extract_metadata(html)
                    nav_analysis = self.analyzer.analyze_navigation(html, current_url)
                    forms = self.analyzer.extract_forms(html)
                    page_type = self.analyzer.classify_page_type(html, current_url)
                    requires_auth = self.analyzer.detect_authentication_required(
                        html, page_result.get("status_code")
                    )

                    # Extract links (only same domain)
                    links = self.discovery.extract_links(html, current_url, same_domain_only=True)
                except Exception as e:
                    logger.warning(f"Failed to analyze page {current_url}: {e}. Skipping and continuing.")
                    if self.error_logger:
                        self.error_logger.log_exception(
                            e,
                            context=f"browsing_agent.discover.analyze_page",
                            metadata={"url": current_url}
                        )
                    continue

                # Create page info
                page_info = PageInfo(
                    url=current_url,
                    title=metadata.get("title") or page_result.get("title"),
                    status_code=page_result.get("status_code"),
                    discovered_via="sitemap" if current_url in sitemap_urls_list else "link_crawl",
                    links=links[:20],  # Limit links stored
                    has_forms=len(forms) > 0,
                    requires_auth=requires_auth,
                    meta_description=metadata.get("meta_description"),
                    page_type=page_type,
                    forms=[f for f in forms[:5]],  # Limit forms stored
                    navigation_links=nav_analysis.get("navigation_links", [])[:10],
                    content_links=nav_analysis.get("content_links", [])[:20],
                )

                self.discovered_pages.append(page_info)

                # Add new links to queue (prioritize navigation links)
                # Only add links from the same domain
                base_parsed = urlparse(url)
                base_domain = base_parsed.netloc.lower()
                
                for link in nav_analysis.get("navigation_links", []):
                    normalized = self.discovery.normalize_url(link, url)
                    link_parsed = urlparse(normalized)
                    # Only add if same domain
                    if (
                        link_parsed.netloc.lower() == base_domain
                        and normalized not in self.visited_urls
                        and normalized not in url_queue
                        and len(self.discovered_pages) < self.max_pages
                    ):
                        url_queue.add(normalized)

                # Add content links (only same domain)
                for link in nav_analysis.get("content_links", [])[:10]:  # Limit content links
                    normalized = self.discovery.normalize_url(link, url)
                    link_parsed = urlparse(normalized)
                    # Only add if same domain
                    if (
                        link_parsed.netloc.lower() == base_domain
                        and normalized not in self.visited_urls
                        and normalized not in url_queue
                        and len(self.discovered_pages) < self.max_pages
                    ):
                        url_queue.add(normalized)

                # Stop if we've reached max pages
                if len(self.discovered_pages) >= self.max_pages:
                    break

            # Determine if authentication is required based on:
            # 1. Whether we authenticated during discovery (auth_credentials provided)
            # 2. Whether any discovered pages require authentication
            any_page_requires_auth = any(page.requires_auth for page in self.discovered_pages)
            authentication_required = authentication_required or any_page_requires_auth

            # Create result
            discovery_result = DiscoveryResult(
                base_url=url,
                discovered_at=datetime.utcnow().isoformat() + "Z",
                total_pages=len(self.discovered_pages),
                authentication_required=authentication_required,
                pages=self.discovered_pages,
                sitemap_used=sitemap_used,
                robots_respected=self.respect_robots,
            )

            return discovery_result

        except Exception as e:
            logger.error(f"Discovery failed: {e}", exc_info=True)
            if self.error_logger:
                self.error_logger.log_exception(
                    e,
                    context="browsing_agent.discover",
                    metadata={"url": url}
                )
            raise
        finally:
            # Cleanup
            self.browser.close()
            # Error summary will be saved in save_results if error logger exists

    def save_results(
        self, result: DiscoveryResult, output_path: Optional[str] = None, save_summary: bool = True, run_id: Optional[str] = None, error_log_path: Optional[Path] = None
    ) -> Dict[str, str]:
        """
        Save discovery results to JSON files (comprehensive and summary) and generate concise markdown report.

        Args:
            result: DiscoveryResult to save
            output_path: Optional output path prefix (if None, uses default location)
            save_summary: Whether to save a summary report
            run_id: Optional run ID for consistent naming

        Returns:
            Dictionary with paths to saved files: {'comprehensive': path, 'summary': path, 'markdown': path}
        """
        from vibe_code_bench.core.paths import get_reports_dir
        from vibe_code_bench.core.report_models import discovery_result_to_browsing_data
        from vibe_code_bench.core.report_generators import BrowsingReportGenerator

        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if not run_id:
                run_id = f"browsing_{timestamp}"
            # Use day-based folder with unified run-specific subfolder
            from vibe_code_bench.core.paths import get_reports_dir_for_date, extract_base_run_id
            date_str = datetime.now().strftime("%Y-%m-%d")
            reports_dir = get_reports_dir_for_date(date_str)
            # Use unified run folder (extract base run_id without prefix)
            base_run_id = extract_base_run_id(run_id)
            run_folder = reports_dir / base_run_id
            run_folder.mkdir(parents=True, exist_ok=True)
            comprehensive_path = str(run_folder / f"browsing_discovery_{timestamp}_comprehensive.json")
            summary_path = str(run_folder / f"browsing_discovery_{timestamp}_summary.json")
            
            # Setup error logging if not already set
            if not self.error_logger:
                if error_log_path is None:
                    error_log_path = run_folder / "errors.log"
                from vibe_code_bench.core.error_logger import setup_error_logging
                self.error_logger = setup_error_logging(error_log_path)
                self._current_run_id = run_id
        else:
            from vibe_code_bench.core.paths import get_absolute_path

            base_path = get_absolute_path(output_path)
            comprehensive_path = str(base_path.parent / f"{base_path.stem}_comprehensive.json")
            summary_path = str(base_path.parent / f"{base_path.stem}_summary.json")
            if not run_id:
                run_id = base_path.stem

        # Ensure directory exists
        Path(comprehensive_path).parent.mkdir(parents=True, exist_ok=True)

        # Save comprehensive JSON report
        with open(comprehensive_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

        logger.info(f"Comprehensive report saved to {comprehensive_path}")

        # Save summary report
        saved_paths = {"comprehensive": comprehensive_path}
        if save_summary:
            summary = self._create_summary_report(result)
            with open(summary_path, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)

            logger.info(f"Summary report saved to {summary_path}")
            saved_paths["summary"] = summary_path

            # Generate and save concise markdown report
        try:
            # Determine tools used
            tools_used = []
            if self.llm is not None:
                tools_used.append("llm_agent")
            if self.enable_javascript:
                tools_used.append("javascript_rendering")
            tools_used.append("browser_crawl")
            if result.sitemap_used:
                tools_used.append("sitemap")
            
            browsing_data = discovery_result_to_browsing_data(result, run_id=run_id, tools_used=tools_used)
            markdown_path = BrowsingReportGenerator.save_report(browsing_data, run_id=run_id)
            logger.info(f"Concise markdown report saved to {markdown_path}")
            saved_paths["markdown"] = str(markdown_path)
            
            # Save error summary if error logger was used
            if self.error_logger:
                try:
                    error_summary_path = run_folder / "errors.json"
                    self.error_logger.save_summary(error_summary_path)
                    logger.info(f"Error summary saved to {error_summary_path}")
                except Exception as e:
                    logger.warning(f"Failed to save error summary: {e}")
            
            # Generate and save detailed markdown report
            try:
                from vibe_code_bench.core.detailed_report_generators import BrowsingDetailedReportGenerator
                from vibe_code_bench.core.paths import get_reports_dir_for_date
                
                # Extract agent output if available (from langchain agent)
                agent_output = None
                if hasattr(self, 'langchain_agent') and self.langchain_agent is not None:
                    # Try to get last agent output from logs or state
                    agent_output = "Agent guidance was used during discovery process."
                
                # Get testing plan if available (will be None for browsing agent, but included for future use)
                testing_plan = None
                
                # Try to find run directory
                run_dir = None
                try:
                    from vibe_code_bench.core.run_directory import find_report_by_run_id
                    # Run directory would be in runs/browsing_agent/ if it exists
                    from vibe_code_bench.core.paths import get_runs_dir
                    runs_dir = get_runs_dir()
                    browsing_runs = list((runs_dir / "browsing_agent").glob(f"*{run_id.replace('browsing_', '')}*"))
                    if browsing_runs:
                        run_dir = browsing_runs[0]
                except:
                    pass
                
                detailed_path = BrowsingDetailedReportGenerator.save_detailed_report(
                    browsing_data,
                    discovery_result=result,
                    testing_plan=testing_plan,
                    run_dir=run_dir,
                    agent_output=agent_output,
                    run_id=run_id,
                )
                logger.info(f"Detailed markdown report saved to {detailed_path}")
                saved_paths["detailed"] = str(detailed_path)
            except Exception as e:
                logger.warning(f"Failed to generate detailed markdown report: {e}")
        except Exception as e:
            logger.warning(f"Failed to generate concise markdown report: {e}")

        return saved_paths

    def _create_summary_report(self, result: DiscoveryResult) -> Dict[str, Any]:
        """
        Create a summary report with only essential information.

        Args:
            result: DiscoveryResult to summarize

        Returns:
            Dictionary with summary information
        """
        # Count pages by type
        page_types = {}
        status_codes = {}
        discovery_methods = {}
        pages_with_forms = 0
        pages_requiring_auth = 0

        for page in result.pages:
            # Page types
            page_type = page.page_type or "unknown"
            page_types[page_type] = page_types.get(page_type, 0) + 1

            # Status codes
            status = page.status_code or "unknown"
            status_codes[status] = status_codes.get(status, 0) + 1

            # Discovery methods
            method = page.discovered_via or "unknown"
            discovery_methods[method] = discovery_methods.get(method, 0) + 1

            # Forms and auth
            if page.has_forms:
                pages_with_forms += 1
            if page.requires_auth:
                pages_requiring_auth += 1

        # Get unique domains (should be 1 if same-domain filtering worked)
        domains = set()
        for page in result.pages:
            from urllib.parse import urlparse

            parsed = urlparse(page.url)
            domains.add(parsed.netloc)

        summary = {
            "base_url": result.base_url,
            "discovered_at": result.discovered_at,
            "total_pages": result.total_pages,
            "authentication_required": result.authentication_required,
            "sitemap_used": result.sitemap_used,
            "robots_respected": result.robots_respected,
            "domains_discovered": list(domains),
            "statistics": {
                "pages_by_type": page_types,
                "pages_by_status_code": status_codes,
                "pages_by_discovery_method": discovery_methods,
                "pages_with_forms": pages_with_forms,
                "pages_requiring_auth": pages_requiring_auth,
            },
            "page_urls": [page.url for page in result.pages],
            "errors": result.errors if result.errors else [],
        }

        return summary


__all__ = ["BrowsingAgent", "PageInfo", "DiscoveryResult"]
