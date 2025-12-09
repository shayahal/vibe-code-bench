"""Tests for report analyzer."""

import pytest
import json
import tempfile
from pathlib import Path

from vibe_code_bench.red_team_agent.report_analyzer import ReportAnalyzer


class TestReportAnalyzer:
    """Test ReportAnalyzer class."""

    def test_load_report(self):
        """Test loading a browsing report."""
        # Create a minimal test report
        report_data = {
            "base_url": "https://example.com",
            "pages": [
                {
                    "url": "https://example.com/page1",
                    "forms": [],
                    "requires_auth": False,
                    "page_type": "homepage",
                }
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_path = f.name

        try:
            analyzer = ReportAnalyzer()
            report = analyzer.load_report(temp_path)
            assert report["base_url"] == "https://example.com"
            assert len(report["pages"]) == 1
        finally:
            Path(temp_path).unlink()

    def test_extract_attack_surfaces(self):
        """Test extracting attack surfaces."""
        report_data = {
            "base_url": "https://example.com",
            "pages": [
                {
                    "url": "https://example.com/login",
                    "forms": [
                        {
                            "action": "/login",
                            "method": "post",
                            "fields": [
                                {"name": "username", "type": "text"},
                                {"name": "password", "type": "password"},
                            ],
                        }
                    ],
                    "requires_auth": False,
                    "page_type": "login",
                }
            ],
        }

        analyzer = ReportAnalyzer()
        surfaces = analyzer.extract_attack_surfaces(report_data)
        assert "forms" in surfaces
        assert len(surfaces["forms"]) > 0

    def test_generate_testing_plan(self):
        """Test generating a testing plan."""
        report_data = {
            "base_url": "https://example.com",
            "pages": [
                {
                    "url": "https://example.com/login",
                    "forms": [
                        {
                            "action": "/login",
                            "method": "post",
                            "fields": [{"name": "username", "type": "text"}],
                        }
                    ],
                    "requires_auth": False,
                    "page_type": "login",
                }
            ],
        }

        analyzer = ReportAnalyzer()
        surfaces = analyzer.extract_attack_surfaces(report_data)
        plan = analyzer.generate_testing_plan(report_data, surfaces)
        assert plan.base_url == "https://example.com"
        assert len(plan.attack_surfaces) > 0
