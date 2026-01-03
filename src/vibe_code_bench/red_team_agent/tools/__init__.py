"""Security scanning tools for the red team agent.

All tools follow a consistent interface:
- check_available() -> bool: Check if tool is installed
- scan(url) -> list[VulnerabilityFinding]: Run scan and return findings
"""

from vibe_code_bench.red_team_agent.tools.base import BaseTool, ToolRegistry
from vibe_code_bench.red_team_agent.tools.nuclei import NucleiTool
from vibe_code_bench.red_team_agent.tools.sqlmap import SQLMapTool
from vibe_code_bench.red_team_agent.tools.dalfox import DalFoxTool
from vibe_code_bench.red_team_agent.tools.wapiti import WapitiTool
from vibe_code_bench.red_team_agent.tools.nikto import NiktoTool
from vibe_code_bench.red_team_agent.tools.browser import BrowserTool

__all__ = [
    "BaseTool",
    "ToolRegistry",
    "NucleiTool",
    "SQLMapTool",
    "DalFoxTool",
    "WapitiTool",
    "NiktoTool",
    "BrowserTool",
]
