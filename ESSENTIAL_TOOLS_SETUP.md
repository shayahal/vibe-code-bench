# Essential Tools Setup

## Overview
The codebase has been refactored to use only **5 essential tools** by default, with all other tools moved to an "advanced" module that can be enabled on demand.

## Top 5 Essential Tools

1. **fetch_page** - Fetch and parse web pages (foundation)
2. **scan_with_nuclei** - Fast, comprehensive vulnerability scanner (10,000+ templates)
3. **scan_with_sqlmap** - SQL injection testing
4. **scan_xss_with_dalfox** - XSS vulnerability testing
5. **generate_report** - Generate security reports

## Usage

### Default (Essential Tools Only)
```python
from red_team_agent import RedTeamAgent

agent = RedTeamAgent(target_url="https://example.com")
# Only 5 essential tools are loaded
```

### Enable Advanced Tools
```python
agent = RedTeamAgent(target_url="https://example.com")
agent.enable_advanced_tools()  # Now all tools are available
```

## Advanced Tools (Available on Demand)

When `enable_advanced_tools()` is called, these additional tools become available:

- **Additional Web App Scanners**: XSStrike, OWASP ZAP, Nikto, Wapiti
- **Network Tools**: Nmap, Masscan, RustScan
- **Reconnaissance**: Subfinder, Amass, theHarvester, ParamSpider, Arjun
- **Directory Brute Forcing**: Gobuster, FFuF
- **Fuzzing**: Wfuzz
- **Active Directory**: BloodHound, CrackMapExec
- **Exploitation**: Metasploit
- **Password Tools**: Hashcat, John the Ripper, Hydra
- **Post-Exploitation**: LinPEAS, WinPEAS
- **API Security**: REST-Attacker
- **Cloud Security**: Pacu, Scout Suite
- **Additional Utilities**: analyze_response_security

## Files Changed

1. **tools/essential_tools.py** - New file with top 5 essential tools
2. **tools/advanced_tools.py** - New file with all advanced tools
3. **tools/tool_loader.py** - Updated to support essential/advanced loading
4. **red_team_agent.py** - Updated to load only essential tools by default, added `enable_advanced_tools()` method

## Benefits

- **Faster startup** - Only loads 5 tools instead of 30+
- **Cleaner agent** - Simpler tool selection for basic testing
- **On-demand advanced** - Enable advanced tools only when needed
- **Better performance** - Fewer tools = faster LLM decision making
