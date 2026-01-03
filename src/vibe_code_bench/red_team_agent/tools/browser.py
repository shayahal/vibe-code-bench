"""Browser-based discovery and testing tool.

Uses httpx for HTTP requests and BeautifulSoup for HTML parsing.
This provides basic discovery without requiring external browser tools.
"""

import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from vibe_code_bench.red_team_agent.tools.base import BaseTool
from vibe_code_bench.red_team_agent.models import (
    VulnerabilityFinding,
    Severity,
    get_owasp_category,
    get_cwe_id,
)
from vibe_code_bench.red_team_agent.exceptions import ToolExecutionError


class BrowserTool(BaseTool):
    """Browser-based discovery and basic vulnerability testing."""
    
    name = "browser"
    install_hint = "Built-in tool (no installation required)"
    
    def __init__(self, required: bool = False, timeout: int = 30):
        """Initialize Browser tool.
        
        Args:
            required: If True, raise error if not available
            timeout: HTTP request timeout in seconds
        """
        super().__init__(required=required)
        self.timeout = timeout
        self._client: httpx.Client | None = None
    
    def check_available(self) -> bool:
        """Browser tool is always available."""
        return True
    
    @property
    def client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
                }
            )
        return self._client
    
    def _scan_impl(self, url: str, **kwargs) -> list[VulnerabilityFinding]:
        """Run browser-based security checks.
        
        Args:
            url: Target URL
            check_headers: Check security headers (default True)
            check_forms: Check forms for CSRF (default True)
            check_info_disclosure: Check for information disclosure (default True)
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            response = self.client.get(url)
            html = response.text
            
            # Check security headers
            if kwargs.get("check_headers", True):
                header_findings = self._check_security_headers(url, response.headers)
                findings.extend(header_findings)
            
            # Check for CSRF issues
            if kwargs.get("check_forms", True):
                csrf_findings = self._check_csrf(url, html)
                findings.extend(csrf_findings)
            
            # Check for information disclosure
            if kwargs.get("check_info_disclosure", True):
                info_findings = self._check_info_disclosure(url, html, response)
                findings.extend(info_findings)
            
            return findings
            
        except httpx.RequestError as e:
            raise ToolExecutionError(self.name, f"Request failed: {e}")
    
    def _check_security_headers(self, url: str, headers: httpx.Headers) -> list[VulnerabilityFinding]:
        """Check for missing security headers."""
        findings = []
        
        security_headers = {
            "X-Frame-Options": (
                "Missing X-Frame-Options header",
                "Add X-Frame-Options: DENY or SAMEORIGIN header to prevent clickjacking",
                "Clickjacking",
            ),
            "X-Content-Type-Options": (
                "Missing X-Content-Type-Options header",
                "Add X-Content-Type-Options: nosniff header",
                "Security Misconfiguration",
            ),
            "Content-Security-Policy": (
                "Missing Content-Security-Policy header",
                "Implement Content Security Policy to prevent XSS attacks",
                "Security Misconfiguration",
            ),
            "Strict-Transport-Security": (
                "Missing Strict-Transport-Security header",
                "Add HSTS header to enforce HTTPS",
                "Weak Cryptography",
            ),
            "X-XSS-Protection": (
                "Missing X-XSS-Protection header",
                "Add X-XSS-Protection: 1; mode=block header",
                "Security Misconfiguration",
            ),
        }
        
        for header, (desc, remediation, vuln_type) in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                findings.append(VulnerabilityFinding(
                    vulnerability_type=vuln_type,
                    severity=Severity.LOW,
                    url=url,
                    description=desc,
                    proof_of_concept=f"Header '{header}' not present in response",
                    remediation=remediation,
                    cwe_id=get_cwe_id(vuln_type),
                    owasp_category=get_owasp_category(vuln_type),
                    tool=self.name,
                    raw_output={"missing_header": header},
                ))
        
        return findings
    
    def _check_csrf(self, url: str, html: str) -> list[VulnerabilityFinding]:
        """Check forms for CSRF protection."""
        findings = []
        soup = BeautifulSoup(html, "html.parser")
        
        forms = soup.find_all("form")
        for form in forms:
            method = form.get("method", "get").lower()
            
            # Only check POST forms
            if method != "post":
                continue
            
            # Look for CSRF token
            csrf_indicators = [
                form.find("input", {"name": re.compile(r"csrf|token|_token", re.I)}),
                form.find("input", {"type": "hidden", "name": re.compile(r"authenticity|nonce", re.I)}),
            ]
            
            has_csrf = any(csrf_indicators)
            
            if not has_csrf:
                action = form.get("action", "")
                form_url = urljoin(url, action) if action else url
                
                findings.append(VulnerabilityFinding(
                    vulnerability_type="Cross-Site Request Forgery (CSRF)",
                    severity=Severity.MEDIUM,
                    url=form_url,
                    description="POST form without CSRF protection detected",
                    proof_of_concept=f"Form action: {action or 'same page'}",
                    remediation="Add CSRF tokens to all state-changing forms",
                    cwe_id=352,
                    owasp_category=get_owasp_category("CSRF"),
                    tool=self.name,
                    raw_output={"form_action": action},
                ))
        
        return findings
    
    def _check_info_disclosure(
        self,
        url: str,
        html: str,
        response: httpx.Response
    ) -> list[VulnerabilityFinding]:
        """Check for information disclosure vulnerabilities."""
        findings = []
        
        # Check for server version in headers
        server = response.headers.get("Server", "")
        if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/"]):
            findings.append(VulnerabilityFinding(
                vulnerability_type="Information Disclosure",
                severity=Severity.LOW,
                url=url,
                description=f"Server version disclosed: {server}",
                proof_of_concept=f"Server header: {server}",
                remediation="Remove or obfuscate server version information",
                cwe_id=200,
                owasp_category=get_owasp_category("Information Disclosure"),
                tool=self.name,
                raw_output={"server_header": server},
            ))
        
        # Check for sensitive patterns in HTML
        sensitive_patterns = [
            (r"(?i)password\s*[:=]\s*['\"]?[\w@#$%]+['\"]?", "Hardcoded password"),
            (r"(?i)api[_-]?key\s*[:=]\s*['\"]?[\w-]{20,}['\"]?", "API key exposure"),
            (r"(?i)secret[_-]?key\s*[:=]\s*['\"]?[\w-]{20,}['\"]?", "Secret key exposure"),
            (r"(?i)aws_access_key_id\s*[:=]\s*['\"]?AKI[\w]+['\"]?", "AWS access key"),
            (r"<!--.*(?:password|secret|key|token).*-->", "Sensitive info in comments"),
        ]
        
        for pattern, vuln_desc in sensitive_patterns:
            matches = re.findall(pattern, html[:10000])  # Limit search
            if matches:
                findings.append(VulnerabilityFinding(
                    vulnerability_type="Information Disclosure",
                    severity=Severity.HIGH,
                    url=url,
                    description=f"Potential {vuln_desc} in page source",
                    proof_of_concept=matches[0][:100],
                    remediation="Remove sensitive information from HTML source",
                    cwe_id=200,
                    owasp_category=get_owasp_category("Information Disclosure"),
                    tool=self.name,
                    raw_output={"pattern": pattern, "match_count": len(matches)},
                ))
                break  # One finding per page is enough
        
        return findings
    
    def discover_urls(self, url: str) -> list[str]:
        """Discover URLs on a page.
        
        Args:
            url: Target URL
            
        Returns:
            List of discovered URLs (same domain only)
        """
        try:
            response = self.client.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            
            base_domain = urlparse(url).netloc.lower()
            discovered = set()
            
            # Find all links
            for a in soup.find_all("a", href=True):
                href = a["href"]
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)
                
                # Same domain only
                if parsed.netloc.lower() == base_domain:
                    # Normalize URL
                    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if parsed.query:
                        clean_url += f"?{parsed.query}"
                    discovered.add(clean_url)
            
            return list(discovered)
            
        except Exception as e:
            self.logger.error(f"URL discovery failed: {e}")
            return []
    
    def extract_forms(self, url: str) -> list[dict]:
        """Extract forms from a page.
        
        Args:
            url: Target URL
            
        Returns:
            List of form info dicts
        """
        try:
            response = self.client.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            
            forms = []
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                
                fields = []
                for input_el in form.find_all(["input", "textarea", "select"]):
                    field = {
                        "name": input_el.get("name", ""),
                        "type": input_el.get("type", "text"),
                        "value": input_el.get("value", ""),
                    }
                    if field["name"]:
                        fields.append(field)
                
                forms.append({
                    "action": urljoin(url, action) if action else url,
                    "method": method,
                    "fields": fields,
                })
            
            return forms
            
        except Exception as e:
            self.logger.error(f"Form extraction failed: {e}")
            return []
    
    def close(self) -> None:
        """Close HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None
