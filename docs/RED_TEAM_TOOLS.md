# Red Team Agent - Auto-Red Teaming Tools

## Best Tools for Auto-Red Teaming

The red team agent uses a combination of internal Python tools and external security scanning tools. Here's a breakdown of the best tools and their usage:

### 1. **nuclei** ✅ (Already Integrated)
- **Purpose**: Fast vulnerability scanner with extensive template library
- **Usage**: Scans all discovered URLs for known vulnerabilities
- **When Used**: Automated scanning phase (`run_automated_scanning()`)
- **Strengths**: 
  - Large template database covering many vulnerability types
  - Fast parallel scanning
  - JSON output for easy parsing
- **Installation**: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

### 2. **dalfox** ✅ (Now Integrated)
- **Purpose**: Specialized XSS (Cross-Site Scripting) scanner
- **Usage**: 
  - **Form Testing**: Enhanced XSS testing on forms (called after basic XSS tests)
  - **Automated Scanning**: URL-based XSS testing on all discovered URLs
- **When Used**: 
  - During form testing phase (`test_xss()` method)
  - During automated scanning phase (`run_automated_scanning()`)
- **Strengths**:
  - Specialized for XSS detection
  - Better at finding complex XSS vulnerabilities than basic payload testing
  - Supports various XSS types (reflected, stored, DOM-based)
- **Installation**: `go install github.com/hahwul/dalfox/v2@latest`

### 3. **sqlmap** ✅ (Now Integrated)
- **Purpose**: Deep SQL injection testing tool
- **Usage**: Deep SQL injection testing on forms that pass initial tests
- **When Used**: During form testing phase (`test_sql_injection()` method)
- **Strengths**:
  - Comprehensive SQL injection detection
  - Supports multiple database types (MySQL, PostgreSQL, SQLite, etc.)
  - Can identify injection points that basic payloads might miss
- **Installation**: `pip install sqlmap` or download from https://sqlmap.org/

### 4. **wapiti3** ✅ (Already Integrated)
- **Purpose**: Comprehensive web application vulnerability scanner
- **Usage**: Full web app scan on base URL
- **When Used**: Automated scanning phase (`run_automated_scanning()`)
- **Strengths**:
  - Comprehensive coverage of multiple vulnerability types
  - Good for overall security assessment
- **Installation**: `pip install wapiti3`

### 5. **nikto** ✅ (Already Integrated)
- **Purpose**: Web server vulnerability scanner
- **Usage**: Server-level vulnerability scanning
- **When Used**: Automated scanning phase (`run_automated_scanning()`)
- **Strengths**:
  - Server configuration issues
  - Outdated software detection
  - Security headers analysis
- **Installation**: `brew install nikto` (macOS) or `apt-get install nikto` (Linux)

## Tool Integration Strategy

### Phase 1: Automated Scanning
- **nuclei**: Fast vulnerability scanning on all URLs
- **wapiti3**: Comprehensive web app scanning
- **nikto**: Server-level scanning
- **dalfox**: URL-based XSS testing on all discovered URLs

### Phase 2: Form Testing
- **Custom Python Scripts**: Basic SQL injection, XSS, and CSRF testing
- **sqlmap**: Deep SQL injection testing (if basic tests don't find issues)
- **dalfox**: Enhanced XSS testing (complements basic XSS tests)
- **Anchor Browser**: DOM-based XSS verification and JavaScript-heavy testing

### Phase 3: Authentication & API Testing
- **Custom Python Scripts**: Session management, authorization bypass, API endpoint testing

### Phase 4: LLM-Guided Testing
- **LangChain Agent**: Intelligent, context-aware testing
- **Anchor Browser**: Interactive browser-based testing

## Recent Changes

### ✅ Integrated dalfox
- Added to form testing (`FormTester.test_xss()`) for enhanced XSS detection
- Added to automated scanning phase for URL-based XSS testing
- Automatically used when available, complements basic XSS payload testing

### ✅ Integrated sqlmap
- Added to form testing (`FormTester.test_sql_injection()`) for deep SQL injection testing
- Runs after basic SQL injection tests if no findings are detected
- Provides comprehensive SQL injection detection beyond basic payloads

### Implementation Details

1. **FormTester** now accepts optional `tool_integration` parameter
2. **SecurityTester** passes `tool_integration` to `FormTester` so it can use dalfox and sqlmap
3. Tools are automatically detected and used when available (no manual configuration needed)
4. Tool results are merged with custom Python test results for comprehensive coverage

## Tool Priority

1. **Always Available**: Custom Python scripts (core functionality)
2. **Highly Recommended**: nuclei, dalfox, sqlmap (significantly enhance detection)
3. **Recommended**: wapiti3, nikto (comprehensive coverage)
4. **Optional**: Anchor Browser (for JavaScript-heavy testing)

## Installation Recommendations

### Quick Installation Script

We provide an installation script that installs all recommended tools:

```bash
# Run the installation script
./scripts/install_red_team_tools.sh
```

This script will:
- Install **wapiti3** via pip (already in requirements.txt)
- Install **nikto** via Homebrew (macOS) or apt-get (Linux)
- Optionally install **nuclei** and **dalfox** if Go is available
- Optionally install **sqlmap** via pip

### Manual Installation

For best results, install these tools:

```bash
# wapiti3 (pip-installable, already in requirements.txt)
pip install wapiti3

# nikto (macOS)
brew install nikto
# nikto (Linux)
sudo apt-get install nikto

# Optional: nuclei (requires Go)
brew install go  # macOS
sudo apt-get install golang-go  # Linux
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:$HOME/go/bin  # Add to ~/.zshrc or ~/.bashrc

# Optional: dalfox (requires Go)
go install github.com/hahwul/dalfox/v2@latest

# Optional: sqlmap
pip install sqlmap
```

### Installation via pip/requirements.txt

The following tools are included in `requirements.txt` and `pyproject.toml`:

- **wapiti3** - Automatically installed with `pip install -e .` or `pip install -r requirements.txt`

Other tools (nikto, nuclei, dalfox, sqlmap) require system-level installation and are not pip-installable.

### Verification

After installation, verify tools are available:

```bash
which wapiti    # Should show path to wapiti command
which nikto     # Should show path to nikto command
which nuclei    # Should show path if installed
which dalfox    # Should show path if installed
which sqlmap    # Should show path if installed
```

The agent will automatically detect and use these tools when available. No configuration needed!

### Note on wapiti3

The `wapiti3` package installs as the `wapiti` command. The code has been updated to correctly detect this (checks for "wapiti" command when looking for "wapiti3" tool).
