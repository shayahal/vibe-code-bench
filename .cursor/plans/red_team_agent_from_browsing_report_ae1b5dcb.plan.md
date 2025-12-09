---
name: Red Team Agent from Browsing Report
overview: ""
todos: []
---

# Red Teaming Process from Browsing Agent Report

## Overview

The red team agent will consume the browsing agent's comprehensive JSON report and perform security testing on discovered pages, forms, authentication endpoints, and API endpoints. The agent combines automated scripted testing with LLM-guided intelligent testing.

## Agentic vs Automated Components

### AGENTIC (LLM-Guided, Autonomous Decision Making)

- **LLM-Guided Testing** (`llm_tester.py`): Uses LangChain agent to make autonomous decisions
  - Analyzes page content and generates custom test cases
  - Decides which pages to test and in what order
  - Generates context-aware payloads based on page content
  - Tests business logic vulnerabilities
  - Uses Anchor Browser tools interactively through agent
  - Makes decisions about when to stop testing

### AUTOMATED (Scripted, Systematic)

- **Form Testing** (`form_tester.py`): Systematic testing with predefined payloads
- **Authentication Testing** (`auth_tester.py`): Scripted authentication and session tests
- **API Testing** (`api_tester.py`): Automated API endpoint testing
- **Automated Scanning**: nuclei, wapiti3, nikto scans
- **Report Analysis** (`report_analyzer.py`): Structured parsing and categorization
- **Tool Integration** (`tool_integration.py`): Subprocess execution of external tools

### HYBRID

- Some automated tests use Anchor Browser tools for JavaScript-heavy pages, but execution is scripted
- Agentic component can call automated testing functions as LangChain tools

## Input: Browsing Agent Report Structure

The report contains:

- `base_url`: Target website base URL
- `pages`: Array of page objects with:
  - `url`: Page URL
  - `forms`: Array of form objects (action, method, fields)
  - `requires_auth`: Boolean indicating authentication requirement
  - `page_type`: Classification (product, account, login, etc.)
  - `links`: All links found on page
  - `navigation_links` / `content_links`: Categorized links
  - `status_code`: HTTP response code
- `authentication_required`: Global authentication flag
- `sitemap_used`: Whether sitemap was discovered
- `robots_respected`: Whether robots.txt was respected

## Workflow

### Phase 1: Report Analysis & Attack Surface Mapping (AUTOMATED)

**Location**: `src/vibe_code_bench/red_team_agent/report_analyzer.py`

1. **Load and Parse Report**

   - Read browsing agent JSON report from `data/reports/`
   - Validate report structure
   - Log: Report file loaded, validation status
   - Extract key information:
     - All unique URLs
     - All forms (login, registration, search, contact, etc.)
     - Authentication endpoints
     - API endpoints (from URL patterns like `/api/`, `/v1/`, etc.)
     - Page types requiring special attention (account, checkout, admin)
   - Log: Number of pages found, forms discovered, endpoints identified

2. **Categorize Attack Surfaces (Grouped, Not Per-Page)**

   - **Forms**: Group by type (login, registration, search, contact, checkout) across ALL pages
   - **Authentication**: Identify login/logout endpoints
   - **API Endpoints**: Extract REST/GraphQL endpoints
   - **Sensitive Pages**: Account, admin, payment pages
   - **Input Points**: All form fields, URL parameters, query strings
   - Log: Attack surfaces grouped by type, counts per category

3. **Generate Unified Testing Plan**

   - **NOT per-page**: Instead, create a single comprehensive plan grouped by attack surface type
   - Prioritize attack surfaces by risk level:
     - High: Authentication endpoints, payment forms, admin pages
     - Medium: All forms (grouped by type), API endpoints, search functionality
     - Low: Static content pages (minimal testing)
   - Create test suites for each attack surface category:
     - Test Suite 1: All login forms (SQLi, XSS, auth bypass)
     - Test Suite 2: All search forms (XSS, injection)
     - Test Suite 3: All API endpoints (auth, rate limiting, validation)
     - Test Suite 4: All account/admin pages (IDOR, authorization)
   - Log: Testing plan generated with priorities and test suite breakdown

### Phase 2: Security Testing Execution

**Location**: `src/vibe_code_bench/red_team_agent/security_tester.py`

#### 2.1 Form Testing (AUTOMATED)

**Tools**: Self-generated Python scripts + Anchor Browser tools + External tools

- **SQL Injection Testing** (Automated)
  - Test all form fields across all forms of same type with SQL injection payloads
  - Use tools: 
    - Self-generated Python script (httpx/requests) for basic testing
    - Anchor Browser tools (AnchorContentTool, AnchorScreenshotTool) for JavaScript-heavy forms
    - sqlmap (subprocess) if available for deep testing
  - Test both GET and POST parameters
  - Execute in parallel batches (all login forms, then all search forms, etc.)
  - Log: Each form type being tested, payload used, result (vulnerable/safe/error)

- **XSS (Cross-Site Scripting) Testing** (Automated)
  - Test all input fields with XSS payloads
  - Use tools:
    - Self-generated Python script for reflected XSS
    - Anchor Browser tools for DOM-based XSS (JavaScript execution)
    - dalfox (subprocess) if available for comprehensive scanning
  - Test reflected, stored, and DOM-based XSS
  - Use browser automation for JavaScript-heavy pages
  - Log: Each XSS test, payload, result, type (reflected/stored/DOM)

- **CSRF (Cross-Site Request Forgery) Testing** (Automated)
  - Check for CSRF tokens in forms
  - Test if forms can be submitted without tokens
  - Use tools: Self-generated Python script + Anchor Browser tools for interactive testing
  - Log: CSRF token presence, test results

- **Authentication Testing** (Automated)
  - Brute force login forms (if credentials provided)
  - Test for weak authentication mechanisms
  - Session management testing
  - Use tools: 
    - Self-generated Python script for session testing
    - Anchor Browser tools for interactive authentication flows
    - hydra (subprocess) if available for brute force
  - Log: Each auth test, session state, test results

#### 2.2 URL/Endpoint Testing (AUTOMATED)

**Tools**: Self-generated scripts + Anchor Browser + External tools

- **Path Traversal** (Automated)
  - Test URL parameters for directory traversal
  - Use tools: Self-generated Python script + Anchor Browser for verification
  - Log: URL tested, payload, result

- **IDOR (Insecure Direct Object Reference)** (Automated)
  - Test URL parameters with different IDs
  - Use tools: Self-generated Python script + Anchor Browser for verification
  - Log: IDOR test, IDs tested, result

- **API Security Testing** (Automated)
  - Test API endpoints for:
    - Authentication bypass
    - Rate limiting
    - Input validation
    - Authorization issues
  - Use tools: 
    - Self-generated Python script (httpx)
    - rest-attacker (subprocess) if available
  - Log: Each API endpoint tested, test type, result

#### 2.3 Automated Scanning (AUTOMATED, Parallel Execution)

**Tools**: nuclei, wapiti3, nikto (if available)

- **Vulnerability Scanning** (Automated)
  - Run nuclei templates against all discovered URLs in parallel batches
  - Use wapiti3 for comprehensive web app scanning (single process)
  - Use nikto for server-level vulnerabilities
  - Parse and aggregate results
  - Execute scans in parallel where possible
  - Log: Start/end of each scan, URLs tested, findings count, scan duration

#### 2.4 LLM-Guided Testing (AGENTIC, Sequential, Context-Aware)

**Location**: `src/vibe_code_bench/red_team_agent/llm_tester.py`

**Tools**: LangChain Agent + Anchor Browser tools

- **This is the AGENTIC component** - uses LLM to make decisions and guide testing
- Use LangChain agent with tools to:
  - Analyze page content for security issues (using Anchor Browser to fetch pages)
  - Generate custom test cases based on page type and content
  - Identify business logic vulnerabilities
  - Test for authorization bypasses (using Anchor Browser for interactive testing)
  - Generate context-aware payloads
  - Execute tests interactively through browser
- Agent has access to:
  - Anchor Browser tools (AnchorContentTool, AnchorScreenshotTool, SimpleAnchorWebTaskTool)
  - Self-generated testing functions (as LangChain tools)
  - Previous test results for context
- Agent makes autonomous decisions about:
  - Which pages to test next
  - What test cases to generate
  - How to interact with pages
  - When to stop testing
- Log: Agent decisions, reasoning, tool calls, pages analyzed, test cases generated, findings

### Phase 3: Results Aggregation & Reporting (AUTOMATED)

**Location**: `src/vibe_code_bench/red_team_agent/report_generator.py`

1. **Collect All Findings**

   - Aggregate results from all testing phases
   - Deduplicate findings
   - Categorize by vulnerability type (OWASP Top 10)
   - Log: Total findings collected, deduplication stats, categorization

2. **Severity Assessment**

   - Classify findings by severity:
     - Critical: SQL injection, authentication bypass, RCE
     - High: XSS, CSRF, IDOR, sensitive data exposure
     - Medium: Information disclosure, weak authentication
     - Low: Missing security headers, verbose error messages
   - Log: Severity distribution

3. **Generate Report**

   - Create comprehensive JSON report
   - Include:
     - Executive summary
     - Vulnerability details (description, severity, affected pages, proof of concept)
     - Recommendations for remediation
     - Testing methodology
   - Save to `data/reports/red_team_<timestamp>.json`
   - Log: Report generation start/end, report file path

## Logging Mechanism

**Location**: `src/vibe_code_bench/red_team_agent/logging_config.py`

### Logging Setup

1. **Initialize Logging at Agent Start**
   ```python
   from vibe_code_bench.core.paths import get_runs_dir
   from pathlib import Path
   import logging
   from datetime import datetime
   
   # Create run directory
   run_dir = get_runs_dir() / "red_team_agent" / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
   run_dir.mkdir(parents=True, exist_ok=True)
   
   # Setup logging
   log_file = run_dir / "logs" / "red_team.log"
   log_file.parent.mkdir(parents=True, exist_ok=True)
   
   # Configure logging
   logging.basicConfig(
       level=logging.INFO,
       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
       handlers=[
           logging.FileHandler(log_file),
           logging.StreamHandler()
       ]
   )
   ```

2. **Structured Logging Format**
   ```python
   logger.info(f"[PHASE] {phase_name} - {step_name} - Started")
   logger.info(f"[TEST] {test_type} - {target_url} - {status} - {details}")
   logger.info(f"[FINDING] {vulnerability_type} - {severity} - {affected_url}")
   logger.info(f"[AGENT] Decision: {decision} - Reason: {reason}")
   logger.info(f"[AGENT] Tool Call: {tool_name} - Input: {input} - Output: {output}")
   logger.error(f"[ERROR] {component} - {error_message} - {traceback}")
   ```

3. **Log Files Structure**
   ```
   data/runs/red_team_agent/run_TIMESTAMP/
   ├── logs/
   │   ├── red_team.log              # Main log file
   │   ├── automated_scanning.log    # Automated scan results
   │   ├── form_testing.log          # Form test results
   │   ├── auth_testing.log          # Auth test results
   │   ├── api_testing.log           # API test results
   │   └── llm_testing.log           # LLM agent decisions and actions
   ├── findings/                     # Individual finding JSON files
   └── intermediate_results/          # Intermediate test results
   ```

4. **Logging Requirements for Each Step**

**Phase 1: Report Analysis**

   - Log: Report file loaded, number of pages found, attack surfaces identified
   - Log: Forms grouped by type, API endpoints discovered, sensitive pages identified
   - Log: Testing plan generated with priorities

**Phase 2: Security Testing**

   - **Automated Scanning**: Log start/end of each scan (nuclei, wapiti3, nikto), URLs tested, findings count
   - **Form Testing**: Log each form type being tested, payload used, result (vulnerable/safe/error)
   - **Authentication Testing**: Log each auth test, session state, test results
   - **API Testing**: Log each API endpoint tested, test type, result
   - **LLM-Guided Testing**: Log agent decisions, pages analyzed, test cases generated, findings

**Phase 3: Results Aggregation**

   - Log: Total findings collected, deduplication stats, severity distribution
   - Log: Report generation start/end, report file path

## Tools Integration

### Tool Categories

#### 1. Self-Generated Python Tools (Primary, AUTOMATED)

**Location**: `src/vibe_code_bench/red_team_agent/form_tester.py`, `auth_tester.py`, `api_tester.py`

- **Custom Python Scripts**: 
  - Form testing (SQLi, XSS, CSRF payloads)
  - Authentication testing (session management, brute force)
  - API endpoint testing
  - URL parameter testing (IDOR, path traversal)
- **Libraries**:
  - `requests/httpx`: HTTP client for testing
  - `BeautifulSoup`: HTML parsing for form extraction
  - `playwright`: Browser automation for JavaScript-heavy testing (fallback if Anchor Browser unavailable)

#### 2. Anchor Browser Tools (Interactive Testing, AUTOMATED + AGENTIC)

**Location**: Integration in `src/vibe_code_bench/red_team_agent/llm_tester.py` and `form_tester.py`

- **langchain-anchorbrowser**: 
  - `AnchorContentTool`: Get page content (HTML, text)
  - `AnchorScreenshotTool`: Capture page screenshots
  - `SimpleAnchorWebTaskTool`: Execute web tasks (navigate, interact)
- **Usage**: 
  - LLM-guided interactive testing (agentic)
  - JavaScript-heavy form testing (automated + agentic)
  - DOM-based XSS verification (automated + agentic)
  - Interactive authentication flows (automated + agentic)
  - Business logic testing (agentic)
- **Initialization**: Requires `ANCHORBROWSER_API_KEY` environment variable

#### 3. External Security Tools (Optional, via Subprocess, AUTOMATED)

**Location**: `src/vibe_code_bench/red_team_agent/tool_integration.py`

- **nuclei**: Vulnerability scanner (Go-based, via subprocess)
  - Run templates against all URLs in parallel batches
  - Parse JSON output
- **dalfox**: XSS scanner (Go-based, via subprocess)
  - Scan forms and URLs for XSS
- **sqlmap**: SQL injection testing (Python-based, via subprocess)
  - Deep SQL injection testing on identified forms
- **wapiti3**: Web vulnerability scanner (Python-based)
  - Comprehensive web app scanning
- **nikto**: Web server scanner (Perl-based, via subprocess)
  - Server-level vulnerabilities
- **hydra**: Brute force tool (if available)
  - Login form brute forcing

#### 4. LLM Integration (Intelligent Testing, AGENTIC)

**Location**: `src/vibe_code_bench/red_team_agent/llm_tester.py`

- **LangChain**: Agent framework for intelligent testing
- **LLM Provider**: OpenAI/Anthropic/OpenRouter
- **Agent Tools**: 
  - Anchor Browser tools (for interactive testing)
  - Self-generated testing functions (for automated tests)
  - Report analysis functions (for context)
- **Purpose**: 
  - Generate context-aware test cases
  - Analyze page content for vulnerabilities
  - Guide interactive testing through browser
  - Identify business logic flaws

### Tool Selection Strategy

1. **Always Available**: Self-generated Python scripts (core functionality, automated)
2. **Preferred for Interactive**: Anchor Browser tools (when available, used by both automated and agentic)
3. **Fallback**: Playwright (if Anchor Browser unavailable)
4. **Enhancement**: External tools (if installed, enhance coverage, automated)
5. **Intelligence**: LLM agent (guides testing, generates custom cases, agentic)

## File Structure

```
src/vibe_code_bench/red_team_agent/
├── __init__.py
├── agent.py              # Main RedTeamAgent class
├── report_analyzer.py    # Parse and analyze browsing report (AUTOMATED)
├── security_tester.py    # Execute security tests (orchestrator)
├── form_tester.py        # Form-specific testing (SQLi, XSS, CSRF) (AUTOMATED)
├── api_tester.py         # API endpoint testing (AUTOMATED)
├── auth_tester.py        # Authentication testing (AUTOMATED)
├── llm_tester.py         # LLM-guided testing (AGENTIC)
├── tool_integration.py   # Integration with external security tools (AUTOMATED)
├── report_generator.py   # Generate final security report (AUTOMATED)
├── logging_config.py     # Logging setup and configuration
├── models.py             # Data models (Vulnerability, Finding, etc.)
└── utils.py              # Utility functions
```

## Data Models

**Vulnerability Finding**:

- vulnerability_type: str (SQLi, XSS, CSRF, etc.)
- severity: str (Critical, High, Medium, Low)
- affected_url: str
- description: str
- proof_of_concept: str
- remediation: str
- cwe_id: Optional[int]
- owasp_category: str

**Security Test Result**:

- test_type: str
- target_url: str
- status: str (vulnerable, safe, error)
- findings: List[VulnerabilityFinding]
- execution_time: float

## Detailed Execution Flow

### Step-by-Step Process

1. **Report Analysis** (Sequential, AUTOMATED)

   - Load browsing report JSON
   - Parse and validate structure
   - Extract all attack surfaces
   - Group by type (forms, APIs, auth endpoints, etc.)
   - Generate unified testing plan
   - Log: All steps

2. **Automated Scanning** (Parallel batches, AUTOMATED)

   - Run nuclei against all URLs (parallel batches of 10-20 URLs)
   - Run wapiti3 scan (single process, comprehensive)
   - Run nikto scan (single process)
   - Collect and parse results
   - Log: Each scan start/end, results

3. **Form Testing** (Parallel by form type, sequential within type, AUTOMATED)

   - **Batch 1**: All login forms → SQLi, XSS, CSRF tests (parallel)
   - **Batch 2**: All search forms → SQLi, XSS tests (parallel)
   - **Batch 3**: All contact forms → XSS, CSRF tests (parallel)
   - Each batch uses: Self-generated scripts + Anchor Browser (if needed)
   - Log: Each test, payload, result

4. **Authentication Testing** (Sequential, requires state, AUTOMATED)

   - Test login endpoints (brute force, weak auth)
   - Test session management (requires authenticated session)
   - Test authorization bypasses (requires multiple user contexts)
   - Log: Each test, session state, results

5. **API Testing** (Parallel batches, AUTOMATED)

   - Test all API endpoints in parallel batches
   - Authentication bypass tests
   - Rate limiting tests
   - Input validation tests
   - Log: Each endpoint tested, result

6. **LLM-Guided Testing** (Sequential, context-aware, AGENTIC)

   - LLM agent analyzes findings so far
   - Generates custom test cases based on page content
   - Uses Anchor Browser tools for interactive testing
   - Tests business logic vulnerabilities
   - Tests authorization bypasses
   - Makes autonomous decisions about testing strategy
   - Log: Agent decisions, reasoning, tool calls, results

7. **Results Aggregation** (Sequential, AUTOMATED)

   - Collect all findings from all phases
   - Deduplicate findings
   - Assess severity
   - Generate comprehensive report
   - Log: Aggregation steps, report generation

## Usage Flow

```python
from vibe_code_bench.red_team_agent import RedTeamAgent

# Initialize agent
agent = RedTeamAgent(
    browsing_report_path="data/reports/browsing_discovery_20251209_143122_comprehensive.json",
    enable_automated_scanning=True,  # Use nuclei, wapiti3, nikto
    enable_llm_testing=True,          # Use LLM agent with Anchor Browser
    enable_anchor_browser=True,        # Use Anchor Browser tools (if available)
    max_parallel_workers=10           # Parallel execution limit
)

# Run security testing (orchestrates all phases)
results = agent.test()

# Generate report
report_path = agent.generate_report(results)
```

## Integration Points

- **Input**: Browsing agent JSON report from `data/reports/`
- **Output**: Security assessment report to `data/reports/red_team_<timestamp>.json`
- **Logging**: Run-specific logs in `data/runs/red_team_agent/run_TIMESTAMP/logs/`
- **Paths**: Use `get_reports_dir()`, `get_runs_dir()` from `vibe_code_bench.core.paths`