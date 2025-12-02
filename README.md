# vibe-code-bench
Benchmark for the security of vibe coded apps

---

## Red Team Agent

A lightweight, focused LangChain-based agent for automated web security testing. The red team agent performs comprehensive security assessments using a curated set of security testing tools, powered by Claude Mini (anthropic/claude-3-haiku) via OpenRouter.

### Features

- **Focused Security Testing**: 6 essential security testing tools
- **Intelligent Tool Selection**: LLM-powered agent selects appropriate tools based on target analysis
- **Comprehensive Reporting**: Detailed security reports with vulnerability classifications
- **Observability**: Full trace tracking with LangFuse integration
- **Lightweight**: Fast execution with minimal dependencies

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│              Red Team Agent (LangChain)                         │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Security Testing Tools                       │  │
│  │                                                           │  │
│  │  • browse_url - Page structure analysis                  │  │
│  │  • analyze_security_headers - HTTP security headers     │  │
│  │  • test_xss_patterns - XSS vulnerability testing         │  │
│  │  • test_sql_injection_patterns - SQLi testing            │  │
│  │  • analyze_authentication - Auth mechanism analysis      │  │
│  │  • generate_security_report - Report generation          │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │         LLM Agent (Claude Mini via OpenRouter)           │  │
│  │         Intelligent tool selection and orchestration      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              LangFuse Observability                      │  │
│  │         Full trace tracking and monitoring               │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   Target Web App │
                    └──────────────────┘
```

### Testing Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Red Team Workflow                                │
└─────────────────────────────────────────────────────────────────────┘

1. RECONNAISSANCE
   │
   └─► Browse URL to understand structure, forms, and inputs
   │
   ▼
2. SECURITY HEADERS ANALYSIS
   │
   └─► Analyze HTTP security headers (CSP, HSTS, etc.)
   │
   ▼
3. VULNERABILITY TESTING
   │
   ├─► XSS Testing (if inputs found)
   ├─► SQL Injection Testing (if database-driven)
   └─► Authentication Analysis (if auth mechanisms found)
   │
   ▼
4. REPORTING
   │
   └─► Generate comprehensive security report
```

---

## Security Testing Tools

The red team agent includes 6 focused security testing tools:

### 1. **browse_url**
- Fetches and parses web page content
- Extracts HTML, forms, links, and metadata
- Identifies input fields and authentication mechanisms
- **Use**: First step to understand target structure

### 2. **analyze_security_headers**
- Checks HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- Identifies missing or misconfigured headers
- **Use**: Early assessment of security posture

### 3. **test_xss_patterns**
- Tests for Cross-Site Scripting vulnerabilities
- Injects XSS payloads into URL parameters and form fields
- Detects reflected XSS vulnerabilities
- **Use**: When input fields or URL parameters are found

### 4. **test_sql_injection_patterns**
- Tests for SQL injection vulnerabilities
- Injects SQLi payloads to detect error-based and blind SQL injection
- Tests URL parameters and form fields
- **Use**: When database-driven functionality is detected

### 5. **analyze_authentication**
- Analyzes authentication mechanisms
- Identifies login forms, session management, and auth vulnerabilities
- Checks for HTTPS usage, cookie security, CSRF protection
- **Use**: When authentication endpoints are discovered

### 6. **generate_security_report**
- Compiles all findings, vulnerabilities, and recommendations
- Creates structured markdown report
- **Use**: Final step to document all findings

---

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd vibe-code-bench
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Up Environment Variables

Create a `.env` file in the project root:

```bash
# Required: OpenRouter API key (for Claude Mini)
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Required: LangFuse credentials (for observability)
LANGFUSE_SECRET_KEY=your_langfuse_secret_key
LANGFUSE_PUBLIC_KEY=your_langfuse_public_key

# Optional: Custom LangFuse host (defaults to cloud.langfuse.com)
LANGFUSE_HOST=https://cloud.langfuse.com
```

**Get API Keys:**
- OpenRouter: https://openrouter.ai/
- LangFuse: https://cloud.langfuse.com

---

## Usage

### Command-Line Usage

#### Basic Security Assessment

```bash
python mini/red_team_agent.py --url https://example.com
```

#### With Custom API Key

```bash
python mini/red_team_agent.py \
  --url https://example.com \
  --api-key your_openrouter_api_key
```

### Programmatic Usage

```python
from mini.red_team_agent import main
import sys

# Set up arguments
sys.argv = ['red_team_agent.py', '--url', 'https://example.com']
main()
```

---

## Output & Reporting

The agent generates comprehensive security reports in Markdown format:

### Report Structure

```
┌─────────────────────────────────────────────────────────────┐
│              Security Report Structure                       │
└─────────────────────────────────────────────────────────────┘

1. Executive Summary
   ├─ Total tests performed
   ├─ Vulnerabilities found
   ├─ Risk level assessment
   └─ Key findings

2. Vulnerability Breakdown
   ├─ Critical Vulnerabilities
   ├─ High Severity Vulnerabilities
   ├─ Medium Severity Vulnerabilities
   └─ Low Severity Vulnerabilities

3. Detailed Findings
   ├─ Security headers analysis
   ├─ XSS test results
   ├─ SQL injection test results
   └─ Authentication analysis

4. Recommendations
   └─ Actionable security improvements
```

### Report Location

- Reports are saved in `mini/reports/run_report_YYYYMMDD_HHMMSS.md`
- Each run generates a timestamped report file

### LangFuse Observability

All agent runs are automatically tracked in LangFuse:
- **Full trace tracking**: All LLM calls, tool calls, and agent actions
- **Cost tracking**: Token usage and API costs
- **Performance metrics**: Execution time and latency
- **Debugging**: Complete execution traces for troubleshooting

Access your traces at: https://cloud.langfuse.com

---

## Configuration

### Environment Variables

**Required:**
- `OPENROUTER_API_KEY`: Your OpenRouter API key
- `LANGFUSE_SECRET_KEY`: Your LangFuse secret key
- `LANGFUSE_PUBLIC_KEY`: Your LangFuse public key

**Optional:**
- `LANGFUSE_HOST`: Custom LangFuse host (default: `https://cloud.langfuse.com`)

### Model Configuration

The agent uses:
- **Model**: `anthropic/claude-3-haiku` (Claude Mini)
- **Provider**: OpenRouter
- **Temperature**: 0.7
- **Max Tokens**: 2000

---

## Testing

Run the test suite:

```bash
pytest mini/test_mini_agent.py -v
```

Tests cover:
- Tool functionality
- Tools registry
- Report generation
- Main agent execution (with mocks)

---

## Vulnerability Types Tested

### Web Application Vulnerabilities

- **XSS (Cross-Site Scripting)**: Multiple payload types tested
- **SQL Injection**: Error-based and blind SQL injection detection
- **Security Headers**: Missing or misconfigured HTTP security headers
- **Authentication Issues**: Weak authentication mechanisms, session management
- **Sensitive Data Exposure**: Detection of exposed sensitive information

---

## Ethical Considerations

This tool is designed for **ethical security testing** only. Use it to:

✅ **DO:**
- Improve the security of your own web applications
- Test systems you have permission to test
- Identify vulnerabilities in a controlled environment
- Conduct authorized penetration testing
- Educational purposes in controlled environments

❌ **DON'T:**
- Attack systems without authorization
- Cause harm or damage
- Violate terms of service
- Engage in malicious activities
- Test systems you don't own or have explicit permission to test

**Legal Notice:** Unauthorized access to computer systems is illegal. Always obtain written permission before testing any system. The authors and contributors are not responsible for misuse of this tool.

---

## Troubleshooting

### API Key Errors

If you see API key errors:

1. **Check .env file exists:**
   ```bash
   ls -la .env
   ```

2. **Verify API key format:**
   ```bash
   cat .env | grep API_KEY
   ```

3. **Test API connection:**
   ```python
   import os
   from dotenv import load_dotenv
   load_dotenv()
   print(os.getenv("OPENROUTER_API_KEY"))
   ```

### LangFuse Errors

If LangFuse initialization fails:

1. **Verify credentials:**
   ```bash
   cat .env | grep LANGFUSE
   ```

2. **Check LangFuse dashboard:** https://cloud.langfuse.com

3. **Verify network connectivity** to LangFuse host

### Import Errors

If you see import errors:

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Check Python version:** Requires Python 3.8+

---

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Adding New Tools

To add a new security testing tool:

1. **Create tool module** in `mini/tools/`:
   ```python
   # mini/tools/new_tool.py
   def test_new_vulnerability(url: str) -> str:
       # Tool implementation
       pass
   
   def get_new_tool() -> StructuredTool:
       return StructuredTool.from_function(
           func=test_new_vulnerability,
           name="test_new_vulnerability",
           description="Description of what the tool does"
       )
   ```

2. **Register tool** in `mini/tools/__init__.py`:
   ```python
   from .new_tool import test_new_vulnerability, get_new_tool
   
   TOOLS_REGISTRY["test_new_vulnerability"] = get_new_tool
   ```

3. **Update prompt** in `mini/red_team_prompt.py` to include the new tool

4. **Add tests** in `mini/test_mini_agent.py`

---

## License

[Add your license here]

---

## Acknowledgments

This project uses:
- [LangChain](https://www.langchain.com/) - LLM application framework
- [Claude Mini (Haiku)](https://www.anthropic.com/) - Fast, efficient LLM via OpenRouter
- [LangFuse](https://langfuse.com/) - Observability and monitoring
- [OpenRouter](https://openrouter.ai/) - Unified API for LLMs

Thank you to all the security researchers and developers who created the tools and frameworks that make this project possible!
