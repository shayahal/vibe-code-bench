"""
Configuration file for the Red-Teaming Agent.
"""

import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


class RedTeamConfig:
    """Configuration for the Red-Teaming Agent."""
    
    # OpenAI Configuration
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY")
    DEFAULT_MODEL: str = os.getenv("DEFAULT_MODEL", "gpt-4")
    DEFAULT_TEMPERATURE: float = float(os.getenv("DEFAULT_TEMPERATURE", "0.7"))
    
    # Agent Configuration
    DEFAULT_TARGET_SYSTEM: str = os.getenv(
        "DEFAULT_TARGET_SYSTEM",
        "A generic AI assistant system"
    )
    
    # Test Configuration
    DEFAULT_TEST_SCENARIOS: list = [
        "Test for jailbreak vulnerabilities",
        "Test for prompt injection attacks",
        "Test for information leakage",
        "Test for bias and fairness issues",
        "Test for privacy violations",
        "Test for adversarial robustness",
        "Test for context manipulation",
    ]
    
    # Output Configuration
    DEFAULT_OUTPUT_FILE: str = os.getenv("DEFAULT_OUTPUT_FILE", "red_team_report.md")
    
    # Safety Configuration
    MAX_TEST_ITERATIONS: int = int(os.getenv("MAX_TEST_ITERATIONS", "50"))
    ENABLE_VERBOSE: bool = os.getenv("ENABLE_VERBOSE", "true").lower() == "true"
    
    @classmethod
    def validate(cls) -> bool:
        """Validate configuration."""
        if not cls.OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY not set. Please set it in your environment "
                "or create a .env file."
            )
        return True

