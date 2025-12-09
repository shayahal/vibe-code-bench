"""Report analyzer for parsing browsing agent reports and mapping attack surfaces."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from vibe_code_bench.core.paths import get_absolute_path, get_reports_dir
from vibe_code_bench.red_team_agent.models import AttackSurface, TestingPlan
from vibe_code_bench.red_team_agent.logging_config import get_logger

logger = get_logger(__name__)


class ReportAnalyzer:
    """Analyzes browsing agent reports and maps attack surfaces."""

    def __init__(self):
        """Initialize the report analyzer."""
        self.logger = logger

    def load_report(self, report_path: str) -> Dict[str, Any]:
        """
        Load and validate browsing agent report.

        Args:
            report_path: Path to the browsing report JSON file

        Returns:
            Parsed report dictionary

        Raises:
            FileNotFoundError: If report file doesn't exist
            ValueError: If report structure is invalid
        """
        self.logger.info(f"[PHASE] Report Analysis - Load Report - Started")
        self.logger.info(f"[PHASE] Loading report from: {report_path}")

        # Resolve absolute path
        abs_path = get_absolute_path(report_path)
        if not abs_path.exists():
            # Try reports directory
            reports_dir = get_reports_dir()
            abs_path = reports_dir / report_path
            if not abs_path.exists():
                raise FileNotFoundError(f"Report file not found: {report_path}")

        with open(abs_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        # Validate report structure
        required_fields = ["base_url", "pages"]
        for field in required_fields:
            if field not in report:
                raise ValueError(f"Invalid report structure: missing field '{field}'")

        self.logger.info(f"[PHASE] Report loaded successfully")
        self.logger.info(f"[PHASE] Base URL: {report['base_url']}")
        self.logger.info(f"[PHASE] Total pages: {len(report.get('pages', []))}")

        return report

    def extract_attack_surfaces(self, report: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract and categorize attack surfaces from the report.

        Args:
            report: Parsed browsing report

        Returns:
            Dictionary mapping attack surface categories to lists of items
        """
        self.logger.info(f"[PHASE] Report Analysis - Extract Attack Surfaces - Started")

        base_url = report["base_url"]
        base_domain = urlparse(base_url).netloc.lower()
        pages = report.get("pages", [])
        
        # Filter pages to only include those from the same domain
        filtered_pages = []
        for page in pages:
            page_url = page.get("url", "")
            page_domain = urlparse(page_url).netloc.lower()
            if page_domain == base_domain:
                filtered_pages.append(page)
            else:
                self.logger.debug(f"[FILTER] Excluding external URL: {page_url} (domain: {page_domain})")
        
        self.logger.info(f"[FILTER] Filtered {len(pages)} pages to {len(filtered_pages)} pages from {base_domain}")
        pages = filtered_pages

        attack_surfaces = {
            "forms": [],
            "api_endpoints": [],
            "auth_endpoints": [],
            "sensitive_pages": [],
            "input_points": [],
        }

        # Extract forms
        forms_by_type = {}
        for page in pages:
            page_url = page.get("url", "")
            forms = page.get("forms", [])

            for form in forms:
                form_type = self._classify_form_type(form, page_url, page.get("page_type"))
                if form_type not in forms_by_type:
                    forms_by_type[form_type] = []

                form_info = {
                    "url": page_url,
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").lower(),
                    "fields": form.get("fields", []),
                    "page_type": page.get("page_type"),
                }
                forms_by_type[form_type].append(form_info)

        # Convert forms_by_type to list format
        for form_type, forms_list in forms_by_type.items():
            attack_surfaces["forms"].append({
                "type": form_type,
                "forms": forms_list,
                "count": len(forms_list),
            })

        # Extract API endpoints
        api_patterns = ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]
        for page in pages:
            url = page.get("url", "")
            if any(pattern in url.lower() for pattern in api_patterns):
                attack_surfaces["api_endpoints"].append({
                    "url": url,
                    "page_type": page.get("page_type"),
                    "status_code": page.get("status_code"),
                })

        # Extract authentication endpoints
        for page in pages:
            url = page.get("url", "")
            page_type = page.get("page_type", "").lower()
            requires_auth = page.get("requires_auth", False)

            if (
                "login" in url.lower()
                or "signin" in url.lower()
                or "auth" in url.lower()
                or page_type == "login"
                or requires_auth
            ):
                attack_surfaces["auth_endpoints"].append({
                    "url": url,
                    "page_type": page_type,
                    "requires_auth": requires_auth,
                    "has_forms": page.get("has_forms", False),
                })

        # Extract sensitive pages
        sensitive_types = ["account", "admin", "checkout", "payment", "profile"]
        for page in pages:
            page_type = page.get("page_type", "").lower()
            url = page.get("url", "")

            if any(st in page_type for st in sensitive_types) or any(
                st in url.lower() for st in sensitive_types
            ):
                attack_surfaces["sensitive_pages"].append({
                    "url": url,
                    "page_type": page_type,
                    "requires_auth": page.get("requires_auth", False),
                })

        # Extract input points (form fields, URL parameters)
        for page in pages:
            forms = page.get("forms", [])
            for form in forms:
                fields = form.get("fields", [])
                for field in fields:
                    attack_surfaces["input_points"].append({
                        "url": page.get("url", ""),
                        "form_action": form.get("action", ""),
                        "field_name": field.get("name", ""),
                        "field_type": field.get("type", "text"),
                    })

        # Log extraction results
        self.logger.info(f"[PHASE] Attack surfaces extracted:")
        self.logger.info(f"[PHASE]   Forms: {len(attack_surfaces['forms'])} types")
        self.logger.info(f"[PHASE]   API Endpoints: {len(attack_surfaces['api_endpoints'])}")
        self.logger.info(f"[PHASE]   Auth Endpoints: {len(attack_surfaces['auth_endpoints'])}")
        self.logger.info(f"[PHASE]   Sensitive Pages: {len(attack_surfaces['sensitive_pages'])}")
        self.logger.info(f"[PHASE]   Input Points: {len(attack_surfaces['input_points'])}")

        return attack_surfaces

    def generate_testing_plan(
        self, report: Dict[str, Any], attack_surfaces: Dict[str, List[Dict[str, Any]]]
    ) -> TestingPlan:
        """
        Generate a unified testing plan from attack surfaces.

        Args:
            report: Parsed browsing report
            attack_surfaces: Extracted attack surfaces

        Returns:
            TestingPlan object
        """
        self.logger.info(f"[PHASE] Report Analysis - Generate Testing Plan - Started")

        base_url = report["base_url"]
        pages = report.get("pages", [])

        plan = TestingPlan(base_url=base_url, total_pages=len(pages))

        # Count forms
        total_forms = sum(
            form_group.get("count", 0) for form_group in attack_surfaces["forms"]
        )
        plan.total_forms = total_forms
        plan.total_api_endpoints = len(attack_surfaces["api_endpoints"])

        # Create attack surface objects with priorities
        # High priority: Authentication, payment, admin
        high_priority_surfaces = []
        medium_priority_surfaces = []
        low_priority_surfaces = []

        # Forms - prioritize by type
        for form_group in attack_surfaces["forms"]:
            form_type = form_group.get("type", "")
            priority = "Medium"
            test_suites = []

            if form_type in ["login", "registration", "password_reset"]:
                priority = "High"
                test_suites = ["SQLi", "XSS", "CSRF", "AuthBypass"]
            elif form_type == "search":
                priority = "Medium"
                test_suites = ["SQLi", "XSS"]
            elif form_type in ["contact", "feedback"]:
                priority = "Medium"
                test_suites = ["XSS", "CSRF"]
            else:
                priority = "Low"
                test_suites = ["XSS", "CSRF"]

            attack_surface = AttackSurface(
                category=f"forms_{form_type}",
                items=form_group.get("forms", []),
                priority=priority,
                test_suites=test_suites,
            )

            if priority == "High":
                high_priority_surfaces.append(attack_surface)
            elif priority == "Medium":
                medium_priority_surfaces.append(attack_surface)
            else:
                low_priority_surfaces.append(attack_surface)

        # API Endpoints - High priority
        if attack_surfaces["api_endpoints"]:
            api_surface = AttackSurface(
                category="api_endpoints",
                items=attack_surfaces["api_endpoints"],
                priority="High",
                test_suites=["AuthBypass", "RateLimiting", "InputValidation", "Authorization"],
            )
            high_priority_surfaces.append(api_surface)

        # Auth Endpoints - High priority
        if attack_surfaces["auth_endpoints"]:
            auth_surface = AttackSurface(
                category="auth_endpoints",
                items=attack_surfaces["auth_endpoints"],
                priority="High",
                test_suites=["BruteForce", "WeakAuth", "SessionManagement", "AuthBypass"],
            )
            high_priority_surfaces.append(auth_surface)

        # Sensitive Pages - High priority
        if attack_surfaces["sensitive_pages"]:
            sensitive_surface = AttackSurface(
                category="sensitive_pages",
                items=attack_surfaces["sensitive_pages"],
                priority="High",
                test_suites=["IDOR", "Authorization", "AccessControl"],
            )
            high_priority_surfaces.append(sensitive_surface)

        # Combine all surfaces in priority order
        plan.attack_surfaces = (
            high_priority_surfaces + medium_priority_surfaces + low_priority_surfaces
        )

        # Log testing plan
        self.logger.info(f"[PHASE] Testing plan generated:")
        self.logger.info(f"[PHASE]   High priority surfaces: {len(high_priority_surfaces)}")
        self.logger.info(f"[PHASE]   Medium priority surfaces: {len(medium_priority_surfaces)}")
        self.logger.info(f"[PHASE]   Low priority surfaces: {len(low_priority_surfaces)}")
        self.logger.info(f"[PHASE]   Total test suites: {sum(len(as_.test_suites) for as_ in plan.attack_surfaces)}")

        return plan

    def analyze(self, report_path: str) -> TestingPlan:
        """
        Complete analysis workflow: load report, extract surfaces, generate plan.

        Args:
            report_path: Path to browsing report JSON

        Returns:
            TestingPlan object
        """
        self.logger.info(f"[PHASE] Report Analysis - Complete Analysis - Started")

        # Load report
        report = self.load_report(report_path)

        # Extract attack surfaces
        attack_surfaces = self.extract_attack_surfaces(report)

        # Generate testing plan
        plan = self.generate_testing_plan(report, attack_surfaces)

        self.logger.info(f"[PHASE] Report Analysis - Complete Analysis - Completed")

        return plan

    def _classify_form_type(
        self, form: Dict[str, Any], page_url: str, page_type: Optional[str]
    ) -> str:
        """
        Classify form type based on form fields and page context.

        Args:
            form: Form dictionary
            page_url: URL of the page containing the form
            page_type: Type of the page

        Returns:
            Form type classification
        """
        url_lower = page_url.lower()
        page_type_lower = (page_type or "").lower()
        fields = form.get("fields", [])
        field_names = [f.get("name", "").lower() for f in fields]
        field_types = [f.get("type", "").lower() for f in fields]

        # Check for login forms
        if (
            "login" in url_lower
            or "signin" in url_lower
            or page_type_lower == "login"
            or ("username" in field_names or "email" in field_names)
            and "password" in field_types
        ):
            return "login"

        # Check for registration forms
        if (
            "register" in url_lower
            or "signup" in url_lower
            or "sign-up" in url_lower
            or page_type_lower == "registration"
        ):
            return "registration"

        # Check for search forms
        if (
            "search" in url_lower
            or "q=" in url_lower
            or "query" in field_names
            or page_type_lower == "search"
        ):
            return "search"

        # Check for contact forms
        if (
            "contact" in url_lower
            or "message" in field_names
            or "comment" in field_names
            or page_type_lower == "contact"
        ):
            return "contact"

        # Check for checkout/payment forms
        if (
            "checkout" in url_lower
            or "payment" in url_lower
            or "card" in field_names
            or page_type_lower in ["checkout", "payment"]
        ):
            return "checkout"

        # Default
        return "generic"
