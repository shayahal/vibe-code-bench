# vibe-code-bench
Benchmark for the security of vibe coded apps

## CursorRIPER Framework

This project uses the [CursorRIPER Framework](https://github.com/johnpeterman72/CursorRIPER) for structured AI-assisted development. The framework provides:

- **Structured Workflow**: START phase for initialization, RIPER workflow for development
- **Memory Bank**: Persistent knowledge across coding sessions
- **State Management**: Track current development phase and tasks
- **Decision Logging**: Document important decisions and rationale

### Quick Start with CursorRIPER

1. **Initialize Project**: Use `/start` command in Cursor
2. **Begin Development**: Use `/riper` command to enter RIPER workflow
3. **Track State**: Use `/state` command to see current status
4. **Manage Memory**: Use `/memory` command to access knowledge base

See `.cursor/README.mdc` for complete framework documentation.

---

## LangChain Red-Teaming Agent for Web Security

A comprehensive LangChain-based agent that integrates **30+ open-source red-team security tools** for performing comprehensive security testing and red-teaming on web applications, networks, and cloud environments.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Red Team Agent (LangChain)                    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Tool Factory (RedTeamToolFactory)            │  │
│  │                                                           │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │  │
│  │  │   Web App    │  │   Network    │  │  Cloud/AD    │ │  │
│  │  │    Tools     │  │    Tools     │  │    Tools     │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘ │  │
│  │                                                           │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │  │
│  │  │ Reconnaissance│  │ Exploitation │  │ Post-Exploit │ │  │
│  │  │    Tools     │  │   Frameworks │  │    Tools     │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              LLM Agent (Claude/GPT-4)                   │  │
│  │         Orchestrates tool selection and execution       │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Target System   │
                    │  (Web/Network/   │
                    │   Cloud/AD)      │
                    └──────────────────┘
```

### Tool Categories & Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Red Team Workflow                             │
└─────────────────────────────────────────────────────────────────────┘

1. RECONNAISSANCE
   │
   ├─► Subdomain Discovery (Subfinder, Amass, theHarvester)
   ├─► Parameter Discovery (ParamSpider, Arjun)
   └─► Information Gathering (theHarvester, Shodan)
   │
   ▼
2. SCANNING & ENUMERATION
   │
   ├─► Web Application Scanning (Nuclei, OWASP ZAP, Nikto, Wapiti)
   ├─► Network Scanning (Nmap, Masscan, RustScan)
   ├─► Directory Brute Forcing (Gobuster, FFuF)
   └─► Vulnerability Detection (Nuclei templates, SQLMap, Dalfox)
   │
   ▼
3. EXPLOITATION
   │
   ├─► XSS Testing (Dalfox, XSStrike)
   ├─► SQL Injection (SQLMap)
   ├─► Command Injection (Custom payloads)
   ├─► Path Traversal (Custom payloads)
   └─► Metasploit Exploits
   │
   ▼
4. POST-EXPLOITATION
   │
   ├─► Privilege Escalation (LinPEAS, WinPEAS)
   ├─► Active Directory (BloodHound, CrackMapExec)
   └─► Password Cracking (Hashcat, John the Ripper, Hydra)
   │
   ▼
5. REPORTING
   │
   └─► Comprehensive Security Report Generation
```

### Features

- **30+ Integrated Tools**: All major open-source red-team tools integrated
- **Multi-Domain Testing**: Web applications, networks, Active Directory, cloud environments
- **Intelligent Orchestration**: LLM-powered agent selects appropriate tools based on context
- **Comprehensive Reporting**: Detailed security reports with vulnerability classifications
- **Extensible Architecture**: Easy to add new tools and testing scenarios

---

## Integrated Red-Team Tools

### 🌐 Web Application Security Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Nuclei** | Fast vulnerability scanner with community templates | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **SQLMap** | Automated SQL injection testing | `pip install sqlmap` |
| **Dalfox** | XSS vulnerability scanner | `go install github.com/hahwul/dalfox/v2@latest` |
| **XSStrike** | Advanced XSS detection | `pip install xsstrike` |
| **OWASP ZAP** | Web application security scanner | Download from [OWASP ZAP](https://www.zaproxy.org/) |
| **Nikto** | Web server scanner | `apt install nikto` or `brew install nikto` |
| **Wapiti** | Web vulnerability scanner | `pip install wapiti3` |
| **ParamSpider** | Parameter discovery | `pip install paramspider` |
| **Arjun** | Parameter discovery | `pip install arjun` |
| **Wfuzz** | Web fuzzer | `pip install wfuzz` |

**Usage Example:**
```python
# Scan for vulnerabilities with Nuclei
result = agent.scan_with_nuclei("https://example.com", template_tags="xss,sqli")

# Test SQL injection with SQLMap
result = agent.scan_with_sqlmap("https://example.com/page?id=1", parameter="id")

# Discover XSS with Dalfox
result = agent.scan_xss_with_dalfox("https://example.com/search?q=test")
```

### 🔍 Network & Infrastructure Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Nmap** | Network discovery and port scanning | `apt install nmap` or `brew install nmap` |
| **Masscan** | Fast port scanner | `apt install masscan` or `brew install masscan` |
| **RustScan** | Ultra-fast port scanner | `cargo install rustscan` |

**Usage Example:**
```python
# Network scan with Nmap
result = agent.scan_with_nmap("192.168.1.0/24", scan_type="vuln")

# Fast port scan with Masscan
result = agent.scan_with_masscan("192.168.1.1", ports="1-1000", rate="1000")
```

### 🔎 Reconnaissance Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Subfinder** | Subdomain discovery | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **Amass** | Subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |
| **theHarvester** | Email/subdomain/people discovery | `pip install theHarvester` |

**Usage Example:**
```python
# Discover subdomains
result = agent.discover_subdomains("example.com")

# Information gathering with theHarvester
result = agent.discover_with_theharvester("example.com", sources="all")
```

### 📁 Directory & File Discovery

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Gobuster** | Directory/file brute forcing | `go install github.com/OJ/gobuster/v3@latest` |
| **FFuF** | Fast web fuzzer | `go install github.com/ffuf/ffuf/v2@latest` |

**Usage Example:**
```python
# Brute force directories
result = agent.brute_force_directories("https://example.com", wordlist="/path/to/wordlist.txt")
```

### 🏢 Active Directory Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **BloodHound** | AD attack path mapping | `pip install bloodhound` |
| **CrackMapExec** | Network pentesting framework | `pip install crackmapexec` |

**Usage Example:**
```python
# Collect BloodHound data
result = agent.bloodhound_ingest("domain.local", collection_method="all")

# Scan with CrackMapExec
result = agent.crackmapexec_scan("192.168.1.0/24", scan_type="smb")
```

### 💣 Exploitation Frameworks

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Metasploit** | Exploitation framework | `apt install metasploit-framework` |

**Usage Example:**
```python
# Execute Metasploit exploit
result = agent.metasploit_exploit("192.168.1.100", exploit="exploit/windows/smb/ms17_010_eternalblue")
```

### 🔐 Password & Credential Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Hashcat** | Advanced password recovery | `apt install hashcat` or `brew install hashcat` |
| **John the Ripper** | Password cracker | `apt install john` or `brew install john-jumbo` |
| **Hydra** | Network login cracker | `apt install hydra` or `brew install hydra` |

**Usage Example:**
```python
# Crack passwords with Hashcat
result = agent.crack_password_hashcat("/path/to/hashes.txt", hash_type="0")

# Brute force login with Hydra
result = agent.brute_force_login_hydra("192.168.1.100", service="ssh", username="admin")
```

### 🛠️ Post-Exploitation Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **LinPEAS** | Linux privilege escalation | Download from [PEASS](https://github.com/carlospolop/PEASS-ng) |
| **WinPEAS** | Windows privilege escalation | Download from [PEASS](https://github.com/carlospolop/PEASS-ng) |

**Usage Example:**
```python
# Run LinPEAS scan (requires SSH access)
result = agent.linpeas_scan("192.168.1.100")
```

### ☁️ Cloud Security Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Pacu** | AWS exploitation framework | `pip install pacu` |
| **Scout Suite** | Multi-cloud security auditing | `pip install scoutsuite` |

**Usage Example:**
```python
# Scan AWS with Pacu
result = agent.scan_aws_pacu(aws_key="...", aws_secret="...", region="us-east-1")

# Scan cloud with Scout Suite
result = agent.scan_cloud_scout_suite("aws", credentials={...})
```

### 🔌 API Security Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **REST-Attacker** | REST API security testing | `pip install rest-attacker` |

---

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd vibe-code-bench
```

### 2. Install All Tools (Recommended)

**Option A: Automated Installation Script (Recommended)**

We provide installation scripts that automatically install all tools:

**Bash Script (Linux/macOS):**
```bash
./install_tools.sh
```

**Python Script (Cross-platform):**
```bash
python3 install_tools.py
# or
./install_tools.py
```

The scripts will:
1. ✅ Install all Python packages from `requirements.txt`
2. ✅ Install system packages (nmap, nikto, hashcat, etc.) using your package manager
3. ✅ Install Go-based tools (nuclei, dalfox, subfinder, etc.) if Go is installed
4. ✅ Install Rust-based tools (rustscan) if Rust/Cargo is installed
5. ✅ Verify all installations and report status

**Option B: Manual Installation**

If you prefer manual installation or the script doesn't work for your system:

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install system packages (choose based on your OS)

# macOS (using Homebrew)
brew install nmap nikto masscan hashcat john-jumbo hydra

# Linux - Debian/Ubuntu (using apt)
sudo apt-get update
sudo apt-get install -y nmap masscan nikto hashcat john hydra metasploit-framework

# Linux - RHEL/CentOS (using yum)
sudo yum install -y nmap nikto hashcat john hydra

# 3. Install Go-based tools (requires Go: https://go.dev/dl/)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest

# Make sure Go bin directory is in PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# 4. Install Rust-based tools (requires Rust: https://rustup.rs/)
cargo install rustscan
```

#### Verify Installation

```bash
# Check if tools are available
which nuclei sqlmap dalfox nmap subfinder gobuster hashcat rustscan

# Or run the verification from the install script
python3 install_tools.py  # Will verify at the end
```

### 4. Set Up Environment Variables

```bash
cp .env.example .env
# Edit .env and add your API keys:
# OPENROUTER_API_KEY=your_key_here
# ANTHROPIC_API_KEY=your_key_here  # Optional
# OPENAI_API_KEY=your_key_here      # Optional
```

---

## Usage

### Command-Line Usage

#### Basic Web Application Scan

```bash
python red_team_agent.py --url https://example.com
```

#### Comprehensive Security Assessment

```bash
python red_team_agent.py \
  --url https://example.com \
  --provider openrouter \
  --model anthropic/claude-3.5-sonnet \
  --scenario "Perform comprehensive security testing including XSS, SQL injection, and directory enumeration"
```

#### Network Scanning

```bash
python red_team_agent.py \
  --url 192.168.1.0/24 \
  --scenario "Scan network for open ports and vulnerabilities"
```

#### Custom Headers

```bash
python red_team_agent.py \
  --url https://example.com \
  --headers '{"Authorization": "Bearer token123", "User-Agent": "CustomAgent/1.0"}'
```

### Programmatic Usage

```python
from red_team_agent import RedTeamAgent

# Initialize the agent
agent = RedTeamAgent(
    target_url="https://example.com",
    provider="openrouter",
    model_name="anthropic/claude-3.5-sonnet",
    headers={"User-Agent": "SecurityScanner/1.0"}
)

# Run comprehensive test suite
report = agent.run_test_suite()

# Or use specific tools directly
result = agent.scan_with_nuclei("https://example.com", template_tags="xss,sqli")
result = agent.discover_subdomains("example.com")
result = agent.scan_with_nmap("192.168.1.1", scan_type="vuln")
```

---

## Tool Selection Flow

```
┌─────────────────────────────────────────────────────────────┐
│              Agent Receives Security Task                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │   LLM Analyzes Task Requirements      │
        └───────────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
        ▼                                       ▼
┌───────────────┐                      ┌───────────────┐
│  Web App      │                      │  Network      │
│  Testing      │                      │  Testing      │
└───────────────┘                      └───────────────┘
        │                                       │
        ▼                                       ▼
┌───────────────────────────────────────────────────────────┐
│  Tool Selection Logic:                                    │
│                                                           │
│  IF target is URL:                                        │
│    → Use web tools (Nuclei, SQLMap, Dalfox, etc.)        │
│                                                           │
│  IF target is IP/Network:                                │
│    → Use network tools (Nmap, Masscan, RustScan)         │
│                                                           │
│  IF task is "discover subdomains":                       │
│    → Use Subfinder, Amass, theHarvester                  │
│                                                           │
│  IF task is "brute force":                              │
│    → Use Gobuster, FFuF, Hydra                           │
│                                                           │
│  IF task is "crack passwords":                           │
│    → Use Hashcat, John the Ripper                       │
└───────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │   Execute Selected Tools             │
        └───────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │   Aggregate Results & Generate Report │
        └───────────────────────────────────────┘
```

---

## Configuration

### Environment Variables

**API Keys (one required based on provider):**
- `OPENROUTER_API_KEY`: Your OpenRouter API key (for openrouter provider)
- `ANTHROPIC_API_KEY`: Your Anthropic API key (for anthropic provider)
- `OPENAI_API_KEY`: Your OpenAI API key (for openai provider)

**Provider Options:**
- `--provider`: Choose provider: `openrouter` (default), `anthropic`, or `openai`
- `--model`: Model name (defaults based on provider)
  - OpenRouter: `anthropic/claude-3.5-sonnet` (default)
  - Anthropic: `claude-3-5-sonnet-20241022` (default)
  - OpenAI: `gpt-4` (default)

**Other Configuration:**
- `DEFAULT_TEMPERATURE`: LLM temperature (default: 0.7)
- `MAX_TEST_ITERATIONS`: Maximum number of test iterations
- `ENABLE_VERBOSE`: Enable verbose output

---

## Output & Reporting

The agent generates comprehensive security reports in Markdown format:

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Report Structure                  │
└─────────────────────────────────────────────────────────────┘

1. Executive Summary
   ├─ Total tests performed
   ├─ Vulnerabilities found
   ├─ Critical vulnerabilities count
   └─ High severity vulnerabilities count

2. Vulnerability Breakdown
   ├─ Critical Vulnerabilities
   │   ├─ Issue description
   │   ├─ Affected URL/Resource
   │   ├─ Parameter/Vector
   │   ├─ Payload used
   │   └─ Timestamp
   │
   └─ High Severity Vulnerabilities
       └─ (Same structure as above)

3. Detailed Test Results
   ├─ Test type
   ├─ Target URL/Resource
   ├─ Vulnerability status
   ├─ Issue details
   └─ Timestamp

4. Tool-Specific Findings
   ├─ Nuclei findings
   ├─ SQLMap results
   ├─ Nmap scan results
   └─ Other tool outputs
```

**Report Location:**
- Reports are saved in `runs/run_YYYYMMDD_HHMMSS/reports/red_team_report.md`
- Logs are saved in `runs/run_YYYYMMDD_HHMMSS/logs/`

---

## Tool Integration Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    RedTeamToolFactory                         │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Tool Creation Methods (create_*)                    │   │
│  │                                                       │   │
│  │  • create_scan_with_nuclei()                         │   │
│  │  • create_scan_with_sqlmap()                         │   │
│  │  • create_scan_with_nmap()                           │   │
│  │  • create_discover_subdomains()                       │   │
│  │  • ... (30+ tool methods)                            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Shared Dependencies                                  │   │
│  │  • HTTP Session                                       │   │
│  │  • Test Results Storage                               │   │
│  │  • Logging Trail                                      │   │
│  │  • Headers & Cookies                                  │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │   Tool Execution                      │
        │   • Check tool availability           │
        │   • Run subprocess commands           │
        │   • Parse output                      │
        │   • Return structured results         │
        └───────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │   LangChain Agent                     │
        │   • Receives tool results             │
        │   • Decides next actions               │
        │   • Orchestrates tool chain            │
        └───────────────────────────────────────┘
```

---

## Vulnerability Types Tested

### Web Application Vulnerabilities

- **XSS (Cross-Site Scripting)**: Multiple payload types (script tags, event handlers, SVG, iframe)
- **SQL Injection**: Union-based, boolean-based, time-based, and comment-based attacks
- **Command Injection**: Unix and Windows command injection vectors
- **Path Traversal**: Directory traversal attacks
- **CSRF (Cross-Site Request Forgery)**: Form submission without proper tokens
- **Authentication Bypass**: Weak passwords, account enumeration, brute force
- **Authorization Bypass**: Access control testing
- **Sensitive Data Exposure**: Detection of emails, credit cards, API keys, passwords

### Network Vulnerabilities

- **Open Ports**: Port scanning and service enumeration
- **Service Vulnerabilities**: Version detection and known vulnerability scanning
- **Network Misconfigurations**: Security header analysis, exposed services

### Cloud & Infrastructure Vulnerabilities

- **AWS Misconfigurations**: IAM policies, S3 buckets, security groups
- **Active Directory**: Attack path mapping, privilege escalation vectors
- **API Security**: REST API vulnerability testing

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

### Tool Not Found Errors

If you see errors like "Tool not found in PATH":

1. **Verify Installation:**
   ```bash
   which nuclei sqlmap nmap
   ```

2. **Add to PATH:**
   ```bash
   # For Go tools
   export PATH=$PATH:$(go env GOPATH)/bin
   
   # For Python tools
   export PATH=$PATH:~/.local/bin
   ```

3. **Install Missing Tools:**
   Refer to the installation section above for each tool.

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

### Timeout Errors

Some tools may timeout on large targets:

1. **Increase timeout in code** (default: 300 seconds)
2. **Use smaller target scopes** (e.g., single IP instead of entire subnet)
3. **Run tools individually** instead of comprehensive scans

---

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Adding New Tools

To add a new tool integration:

1. **Add tool method to `RedTeamToolFactory`:**
   ```python
   def create_scan_with_newtool(self) -> Callable:
       def scan_with_newtool(target: str) -> Dict[str, Any]:
           # Tool implementation
           pass
       return scan_with_newtool
   ```

2. **Register tool in `red_team_agent.py`:**
   ```python
   scan_with_newtool = tool_factory.create_scan_with_newtool()
   
   tools.append(StructuredTool.from_function(
       func=scan_with_newtool,
       name="scan_with_newtool",
       description="Description of what the tool does"
   ))
   ```

3. **Update this README** with tool information

---

## License

[Add your license here]

---

## Acknowledgments

This project integrates the following open-source security tools:

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Fast vulnerability scanner
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - SQL injection testing
- [Nmap](https://nmap.org/) - Network mapper
- [Metasploit](https://www.metasploit.com/) - Exploitation framework
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Active Directory analysis
- And 25+ other excellent open-source security tools

Thank you to all the security researchers and developers who created these tools!
