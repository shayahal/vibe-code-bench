"""Authentication handler for session-based authentication."""

import logging
from typing import Dict, Optional, Any, List
from urllib.parse import urljoin

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class AuthenticationHandler:
    """Handler for detecting and managing authentication."""

    def detect_login_form(self, html: str, url: str) -> Optional[Dict[str, Any]]:
        """
        Detect login form on a page.

        Args:
            html: HTML content
            url: URL of the page

        Returns:
            Dictionary with login form information, or None if not found
        """
        try:
            soup = BeautifulSoup(html, "lxml")
            forms = soup.find_all("form")

            for form in forms:
                # Look for login indicators
                form_html = str(form).lower()
                login_indicators = [
                    "login",
                    "sign in",
                    "signin",
                    "log in",
                    "username",
                    "password",
                    "email",
                    "authenticate",
                ]

                has_login_indicator = any(indicator in form_html for indicator in login_indicators)

                if has_login_indicator:
                    # Find input fields
                    inputs = form.find_all(["input", "button"])
                    fields = {}
                    submit_button = None

                    for inp in inputs:
                        inp_type = inp.get("type", "").lower()
                        inp_name = inp.get("name", "").lower()
                        inp_id = inp.get("id", "").lower()

                        if inp_type == "submit" or inp.name == "button":
                            submit_button = {
                                "selector": f'button[type="{inp_type}"]' if inp_type else "button",
                                "text": inp.get_text().strip(),
                            }

                        if inp_type in ["text", "email"] or "user" in inp_name or "email" in inp_name:
                            fields["username"] = inp_name or inp_id
                        elif inp_type == "password":
                            fields["password"] = inp_name or inp_id

                    if "password" in fields:
                        action = form.get("action", "")
                        method = form.get("method", "get").lower()
                        form_url = urljoin(url, action) if action else url

                        return {
                            "found": True,
                            "form_url": form_url,
                            "method": method,
                            "fields": fields,
                            "submit_button": submit_button,
                        }

        except Exception as e:
            logger.error(f"Error detecting login form: {e}")

        return None

    def authenticate(
        self, browser_wrapper, login_url: str, credentials: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Authenticate using provided credentials.

        Args:
            browser_wrapper: BrowserWrapper instance
            login_url: URL of the login page
            credentials: Dictionary with username and password

        Returns:
            Dictionary with authentication result
        """
        try:
            # Fetch login page
            page_result = browser_wrapper.fetch_page(login_url)
            if not page_result.get("success"):
                return {"success": False, "error": "Could not fetch login page"}

            html = page_result["html"]
            login_form = self.detect_login_form(html, login_url)

            if not login_form:
                return {"success": False, "error": "Login form not found"}

            # Prepare form data
            form_data = {}
            field_mapping = login_form.get("fields", {})

            # Map credentials to form fields
            if "username" in field_mapping and "username" in credentials:
                form_data[field_mapping["username"]] = credentials["username"]
            elif "email" in credentials:
                # Try common email field names
                for field_name in ["email", "user", "username", "login"]:
                    if field_name in field_mapping:
                        form_data[field_mapping[field_name]] = credentials["email"]
                        break

            if "password" in field_mapping and "password" in credentials:
                form_data[field_mapping["password"]] = credentials["password"]

            if not form_data:
                return {"success": False, "error": "Could not map credentials to form fields"}

            # Submit form
            result = browser_wrapper.fill_form(login_url, form_data, submit=True)

            if result.get("success"):
                # Check if authentication was successful
                final_url = result.get("final_url", "")
                final_html = result.get("html", "").lower()

                # Indicators of successful login
                success_indicators = [
                    "dashboard",
                    "welcome",
                    "logout",
                    "profile",
                    "account",
                    "my account",
                ]

                # Indicators of failed login
                failure_indicators = [
                    "invalid",
                    "incorrect",
                    "wrong",
                    "failed",
                    "error",
                    "try again",
                ]

                has_success = any(indicator in final_html for indicator in success_indicators)
                has_failure = any(indicator in final_html for indicator in failure_indicators)

                # If URL changed significantly, likely successful
                url_changed = final_url != login_url and "login" not in final_url.lower()

                if has_success or (url_changed and not has_failure):
                    return {
                        "success": True,
                        "cookies": result.get("cookies", []),
                        "final_url": final_url,
                    }
                else:
                    return {"success": False, "error": "Authentication may have failed"}

            return {"success": False, "error": result.get("error", "Form submission failed")}

        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            return {"success": False, "error": str(e)}
