"""Build testable targets from discovered web resources.

This module converts discovered URLs, forms, and API endpoints into
TestableTarget objects that can be passed to security scanning tools.

KEY FIX: This is what makes vulnerability detection work! Security tools like
SQLMap NEED parameters to test. This module extracts parameters from forms
and URLs to create properly configured test targets.
"""

from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import parse_qs, urlparse, urljoin

from vibe_code_bench.red_team_agent.observability import traced, get_logger
from vibe_code_bench.red_team_agent.exceptions import ValidationError

logger = get_logger(__name__)


@dataclass
class TestableTarget:
    """A target ready for security testing.

    This represents a single testable endpoint with all the information
    needed to run security tools (SQLMap, DalFox, etc.) against it.

    Example:
        # Login form
        target = TestableTarget(
            url="https://example.com/login",
            method="POST",
            parameters={"username": "test", "password": "test123"},
            source="form",
            test_sqli=True,
            test_xss=False,
        )

        # Search with GET parameter
        target = TestableTarget(
            url="https://example.com/search",
            method="GET",
            parameters={"q": "test"},
            source="url_param",
            test_sqli=True,
            test_xss=True,
        )
    """

    url: str
    method: Literal["GET", "POST"]
    parameters: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    # Context about where this target came from
    source: str = "unknown"  # "form", "url_param", "api", "crawl"
    form_action: str | None = None
    has_csrf_token: bool = False

    # Which tests to run
    test_sqli: bool = True
    test_xss: bool = True
    test_auth: bool = False
    test_idor: bool = False

    def to_sqlmap_args(self) -> dict:
        """Convert to SQLMap command arguments.

        Returns:
            Dict with sqlmap arguments ready to use

        Example:
            >>> target.to_sqlmap_args()
            {
                'url': 'https://example.com/login',
                'data': 'username=test&password=test123',
                'method': 'POST',
                'level': 5,
                'risk': 3,
            }
        """
        args = {
            "url": self.url,
            "level": 5,  # Maximum testing depth
            "risk": 3,   # Maximum risk/aggression
        }

        if self.method == "POST" and self.parameters:
            # POST request with data
            args["data"] = "&".join(f"{k}={v}" for k, v in self.parameters.items())
            args["method"] = "POST"

        elif self.method == "GET" and self.parameters:
            # GET request - add parameters to URL
            params = "&".join(f"{k}={v}" for k, v in self.parameters.items())
            separator = "&" if "?" in self.url else "?"
            args["url"] = f"{self.url}{separator}{params}"
            args["method"] = "GET"

        if self.headers:
            args["headers"] = self.headers

        return args

    def to_dalfox_args(self) -> dict:
        """Convert to DalFox (XSS scanner) arguments.

        Returns:
            Dict with dalfox arguments
        """
        args = {"url": self.url}

        if self.method == "POST" and self.parameters:
            args["data"] = "&".join(f"{k}={v}" for k, v in self.parameters.items())
            args["method"] = "POST"
        elif self.parameters:
            # Add parameters to URL for GET
            params = "&".join(f"{k}={v}" for k, v in self.parameters.items())
            separator = "&" if "?" in self.url else "?"
            args["url"] = f"{self.url}{separator}{params}"

        return args

    def to_dict(self) -> dict:
        """Convert to dictionary for LangChain tool input.

        Returns:
            Dict representation compatible with LangChain @tool
        """
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "headers": self.headers,
            "source": self.source,
        }

    def __str__(self) -> str:
        """Human-readable representation."""
        params_str = ", ".join(self.parameters.keys()) if self.parameters else "no params"
        return f"{self.method} {self.url} ({params_str}) from {self.source}"


class TargetBuilder:
    """Build TestableTarget objects from discovered web resources.

    Takes raw discovery data (forms, URLs, APIs) and converts them into
    properly configured TestableTarget objects ready for security testing.
    """

    def __init__(self, base_url: str):
        """Initialize target builder.

        Args:
            base_url: Base URL of the target website
        """
        self.base_url = base_url
        self.logger = get_logger(__name__)

    @traced("build_targets")
    def build_targets(
        self,
        urls: list[str] = None,
        forms: list[dict] = None,
        apis: list[dict] = None,
    ) -> list[TestableTarget]:
        """Build testable targets from discovery results.

        Args:
            urls: List of discovered URLs (may contain parameters)
            forms: List of form dictionaries with action, method, fields
            apis: List of API endpoint dictionaries

        Returns:
            List of TestableTarget objects
        """
        self.logger.info("Building testable targets from discovery")
        self.logger.debug(
            f"Input: {len(urls or [])} URLs, {len(forms or [])} forms, "
            f"{len(apis or [])} APIs"
        )

        targets = []

        # Build targets from forms
        if forms:
            for form in forms:
                try:
                    target = self._build_from_form(form)
                    targets.append(target)

                    self.logger.info(
                        f"Built target from form: {target.url} ({target.method}) "
                        f"with {len(target.parameters)} parameters"
                    )

                except ValidationError as e:
                    # Non-fatal: log and skip malformed forms
                    self.logger.warning(
                        f"Skipping malformed form at {form.get('action', 'unknown')}: {e}"
                    )
                    continue

        # Build targets from URLs with parameters
        if urls:
            for url in urls:
                if "?" in url:  # Has query parameters
                    try:
                        target = self._build_from_url(url)
                        targets.append(target)

                        self.logger.info(
                            f"Built target from URL: {url} with "
                            f"{len(target.parameters)} params"
                        )

                    except ValidationError as e:
                        self.logger.warning(f"Skipping malformed URL {url}: {e}")
                        continue

        # Build targets from API endpoints
        if apis:
            for api in apis:
                try:
                    target = self._build_from_api(api)
                    targets.append(target)

                    self.logger.info(f"Built target from API: {target.url}")

                except ValidationError as e:
                    self.logger.warning(
                        f"Skipping malformed API {api.get('url', 'unknown')}: {e}"
                    )
                    continue

        self.logger.info(f"✓ Built {len(targets)} testable targets")

        # Log summary by source and type
        by_source = {}
        by_method = {}
        for t in targets:
            by_source[t.source] = by_source.get(t.source, 0) + 1
            by_method[t.method] = by_method.get(t.method, 0) + 1

        self.logger.info(f"Targets by source: {by_source}")
        self.logger.info(f"Targets by method: {by_method}")

        return targets

    def _build_from_form(self, form: dict) -> TestableTarget:
        """Build target from HTML form.

        Args:
            form: Dict with 'action', 'method', 'fields'

        Returns:
            TestableTarget for the form

        Raises:
            ValidationError: If form is malformed
        """
        action = form.get("action")
        if not action:
            raise ValidationError("Form missing action attribute")

        # Resolve relative URLs
        full_url = urljoin(self.base_url, action)

        # Extract method (default to POST)
        method = form.get("method", "POST").upper()
        if method not in ["GET", "POST"]:
            method = "POST"

        # Extract parameters from form fields
        parameters = {}
        has_csrf = False

        for field in form.get("fields", []):
            field_name = field.get("name")
            if not field_name:
                continue

            # Check for CSRF token
            if "csrf" in field_name.lower() or "token" in field_name.lower():
                has_csrf = True

            # Use existing value or default test value
            field_value = field.get("value", "")
            if not field_value:
                # Generate appropriate test value based on field type/name
                field_type = field.get("type", "text").lower()
                if "email" in field_name.lower():
                    field_value = "test@example.com"
                elif "password" in field_name.lower():
                    field_value = "test123"
                elif field_type == "number":
                    field_value = "1"
                else:
                    field_value = "test"

            parameters[field_name] = field_value

        self.logger.debug(
            f"Extracted {len(parameters)} parameters from form: "
            f"{list(parameters.keys())}"
        )

        # Determine which tests to run
        test_auth = any(
            "login" in full_url.lower() or
            "auth" in full_url.lower() or
            "password" in param.lower() or
            "username" in param.lower()
            for param in parameters.keys()
        )

        return TestableTarget(
            url=full_url,
            method=method,
            parameters=parameters,
            source="form",
            form_action=action,
            has_csrf_token=has_csrf,
            test_sqli=True,
            test_xss=True,
            test_auth=test_auth,
        )

    def _build_from_url(self, url: str) -> TestableTarget:
        """Build target from URL with query parameters.

        Args:
            url: URL with query string (e.g., /search?q=test&page=1)

        Returns:
            TestableTarget for the URL

        Raises:
            ValidationError: If URL is malformed
        """
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValidationError(f"Invalid URL: {e}")

        # Extract query parameters
        parameters = {}
        if parsed.query:
            params = parse_qs(parsed.query)
            # parse_qs returns lists, take first value
            parameters = {k: v[0] if v else "" for k, v in params.items()}

        if not parameters:
            raise ValidationError("URL has no query parameters")

        # Reconstruct URL without query string
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Determine which tests to run
        test_sqli = any(
            "id" in param.lower() or
            "user" in param.lower() or
            "page" in param.lower()
            for param in parameters.keys()
        )

        test_xss = any(
            "search" in param.lower() or
            "q" in param.lower() or
            "query" in param.lower() or
            "name" in param.lower()
            for param in parameters.keys()
        )

        return TestableTarget(
            url=base_url,
            method="GET",
            parameters=parameters,
            source="url_param",
            test_sqli=test_sqli,
            test_xss=test_xss,
        )

    def _build_from_api(self, api: dict) -> TestableTarget:
        """Build target from API endpoint.

        Args:
            api: Dict with 'url', 'method', 'params' or 'body'

        Returns:
            TestableTarget for the API

        Raises:
            ValidationError: If API definition is malformed
        """
        url = api.get("url")
        if not url:
            raise ValidationError("API missing URL")

        # Resolve relative URLs
        full_url = urljoin(self.base_url, url)

        method = api.get("method", "GET").upper()
        if method not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            method = "GET"

        # Get parameters (could be query params or request body)
        parameters = api.get("params") or api.get("body") or {}

        return TestableTarget(
            url=full_url,
            method=method,
            parameters=parameters,
            source="api",
            test_sqli=True,
            test_idor=True,  # APIs are good targets for IDOR
        )
