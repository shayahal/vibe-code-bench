"""Scan configuration models.

This module defines the configuration for security scans, including
scan depth, testing strategy, tool timeouts, and output preferences.
"""

import os
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from vibe_code_bench.red_team_agent.observability import get_logger
from vibe_code_bench.red_team_agent.exceptions import ValidationError

logger = get_logger(__name__)


class ScanDepth(str, Enum):
    """Scan depth levels controlling thoroughness vs speed."""

    QUICK = "quick"           # 5-10 min: Basic checks
    STANDARD = "standard"     # 15-30 min: Balanced
    DEEP = "deep"            # 30-60 min: Thorough
    COMPREHENSIVE = "comprehensive"  # 1-2 hours: Maximum depth


class TestingStrategy(str, Enum):
    """Testing strategies controlling aggression level."""

    PASSIVE = "passive"       # Discovery + passive checks only
    ACTIVE = "active"         # Active testing (injection, XSS)
    AGGRESSIVE = "aggressive"  # Aggressive testing with exploitation


class ScanConfig(BaseModel):
    """Configuration for a security scan.

    Example:
        # Interactive mode
        config = ScanConfig.from_interactive()

        # Programmatic mode
        config = ScanConfig(
            target_url="https://example.com",
            depth=ScanDepth.DEEP,
            strategy=TestingStrategy.ACTIVE,
        )

        # Quick scan preset
        config = ScanConfig.quick_scan("https://example.com")
    """

    # Target
    target_url: str = Field(description="Target URL to scan")

    # Scan parameters
    depth: ScanDepth = Field(
        default=ScanDepth.STANDARD,
        description="Scan depth (quick, standard, deep, comprehensive)"
    )
    strategy: TestingStrategy = Field(
        default=TestingStrategy.ACTIVE,
        description="Testing strategy (passive, active, aggressive)"
    )

    # Discovery settings
    max_crawl_depth: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Maximum crawl depth for discovery"
    )
    max_urls: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum URLs to discover"
    )
    follow_external: bool = Field(
        default=False,
        description="Follow external links during crawl"
    )

    # Testing settings
    test_sql_injection: bool = Field(default=True, description="Test for SQL injection")
    test_xss: bool = Field(default=True, description="Test for XSS")
    test_auth: bool = Field(default=True, description="Test authentication")
    test_api: bool = Field(default=True, description="Test API security")

    # Tool timeouts (seconds)
    sqlmap_timeout: int = Field(
        default=1800,
        ge=60,
        le=7200,
        description="SQLMap timeout in seconds (default 30 min)"
    )
    wapiti_timeout: int = Field(
        default=1200,
        ge=60,
        le=3600,
        description="Wapiti timeout in seconds (default 20 min)"
    )
    nuclei_timeout: int = Field(
        default=600,
        ge=60,
        le=1800,
        description="Nuclei timeout in seconds (default 10 min)"
    )
    dalfox_timeout: int = Field(
        default=300,
        ge=60,
        le=900,
        description="DalFox timeout in seconds (default 5 min)"
    )

    # SQLMap specific
    sqlmap_level: int = Field(
        default=5,
        ge=1,
        le=5,
        description="SQLMap level (1-5, higher = more thorough)"
    )
    sqlmap_risk: int = Field(
        default=3,
        ge=1,
        le=3,
        description="SQLMap risk (1-3, higher = more aggressive)"
    )

    # Output
    save_markdown: bool = Field(default=True, description="Save markdown report")
    save_json: bool = Field(default=True, description="Save JSON report")
    output_dir: Path | None = Field(
        default=None,
        description="Output directory (default: ~/reports/{date}/run_{id}/)"
    )

    # Agent mode
    use_llm_orchestration: bool = Field(
        default=True,
        description="Use LLM for intelligent test orchestration"
    )

    @field_validator('target_url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate target URL."""
        logger.debug(f"Validating target URL: {v}")

        if not v:
            raise ValidationError("Target URL cannot be empty")

        if not v.startswith(('http://', 'https://')):
            logger.error(f"Invalid URL scheme: {v}")
            raise ValidationError("URL must start with http:// or https://")

        logger.info(f"✓ Valid target URL: {v}")
        return v

    @classmethod
    def from_env(cls, target_url: str) -> "ScanConfig":
        """Create config from environment variables.

        Args:
            target_url: Target URL to scan

        Returns:
            ScanConfig populated from env vars

        Environment variables:
            - DEFAULT_SCAN_DEPTH: quick, standard, deep, comprehensive
            - DEFAULT_TESTING_STRATEGY: passive, active, aggressive
            - SQLMAP_TIMEOUT: Timeout in seconds
            - WAPITI_TIMEOUT: Timeout in seconds
            - NUCLEI_TIMEOUT: Timeout in seconds
            - DALFOX_TIMEOUT: Timeout in seconds
            - SQLMAP_DEFAULT_LEVEL: 1-5
            - SQLMAP_DEFAULT_RISK: 1-3
            - USE_LLM_ORCHESTRATION: true/false
        """
        depth = os.getenv("DEFAULT_SCAN_DEPTH", "standard")
        strategy = os.getenv("DEFAULT_TESTING_STRATEGY", "active")

        return cls(
            target_url=target_url,
            depth=ScanDepth(depth),
            strategy=TestingStrategy(strategy),
            sqlmap_timeout=int(os.getenv("SQLMAP_TIMEOUT", 1800)),
            wapiti_timeout=int(os.getenv("WAPITI_TIMEOUT", 1200)),
            nuclei_timeout=int(os.getenv("NUCLEI_TIMEOUT", 600)),
            dalfox_timeout=int(os.getenv("DALFOX_TIMEOUT", 300)),
            sqlmap_level=int(os.getenv("SQLMAP_DEFAULT_LEVEL", 5)),
            sqlmap_risk=int(os.getenv("SQLMAP_DEFAULT_RISK", 3)),
            use_llm_orchestration=os.getenv("USE_LLM_ORCHESTRATION", "true").lower() == "true",
        )

    @classmethod
    def from_interactive(cls) -> "ScanConfig":
        """Create config from interactive CLI prompts.

        Returns:
            ScanConfig from user input
        """
        from vibe_code_bench.red_team_agent.config.interactive import run_interactive_wizard

        logger.info("Starting interactive configuration wizard")
        config = run_interactive_wizard()
        logger.info(f"Configuration complete: depth={config.depth}, strategy={config.strategy}")

        return config

    @classmethod
    def quick_scan(cls, url: str) -> "ScanConfig":
        """Preset: Quick scan (5-10 min).

        Args:
            url: Target URL

        Returns:
            ScanConfig configured for quick scan
        """
        return cls(
            target_url=url,
            depth=ScanDepth.QUICK,
            strategy=TestingStrategy.ACTIVE,
            max_crawl_depth=1,
            max_urls=10,
            sqlmap_timeout=300,  # 5 min
            wapiti_timeout=300,
            nuclei_timeout=180,
            dalfox_timeout=120,
        )

    @classmethod
    def deep_scan(cls, url: str) -> "ScanConfig":
        """Preset: Deep scan (30-60 min).

        Args:
            url: Target URL

        Returns:
            ScanConfig configured for deep scan
        """
        return cls(
            target_url=url,
            depth=ScanDepth.DEEP,
            strategy=TestingStrategy.AGGRESSIVE,
            max_crawl_depth=3,
            max_urls=100,
            sqlmap_level=5,
            sqlmap_risk=3,
            sqlmap_timeout=1800,  # 30 min
            wapiti_timeout=1200,
            use_llm_orchestration=True,
        )

    def get_timeout_summary(self) -> dict[str, int]:
        """Get summary of all timeouts.

        Returns:
            Dict of tool name to timeout in seconds
        """
        return {
            "sqlmap": self.sqlmap_timeout,
            "wapiti": self.wapiti_timeout,
            "nuclei": self.nuclei_timeout,
            "dalfox": self.dalfox_timeout,
        }

    def get_estimated_duration_minutes(self) -> tuple[int, int]:
        """Get estimated scan duration in minutes.

        Returns:
            Tuple of (min_minutes, max_minutes)
        """
        duration_map = {
            ScanDepth.QUICK: (5, 10),
            ScanDepth.STANDARD: (15, 30),
            ScanDepth.DEEP: (30, 60),
            ScanDepth.COMPREHENSIVE: (60, 120),
        }
        return duration_map.get(self.depth, (15, 30))

    class Config:
        use_enum_values = True
