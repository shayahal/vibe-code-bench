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

## LangChain Orchestrator

A flexible orchestrator for coordinating multiple LangChain agents and chains. The orchestrator enables task delegation, parallel execution, state management, and intelligent agent selection.

### Features

- **Multi-Agent Coordination**: Register and manage multiple specialized agents
- **Task Management**: Create, queue, and track tasks with status monitoring
- **Parallel Execution**: Execute multiple tasks simultaneously
- **Shared State**: Maintain shared context across agents and tasks
- **Automatic Agent Selection**: Intelligently route tasks to appropriate agents
- **Conversation History**: Maintain context across multiple interactions
- **Extensible**: Easy to add custom agents and tools

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd vibe-code-bench
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Quick Start

```python
from orchestrator import LangChainOrchestrator
from example_agents import setup_example_agents
import asyncio

async def main():
    # Initialize orchestrator
    orchestrator = LangChainOrchestrator(verbose=True)
    
    # Setup example agents
    setup_example_agents(orchestrator)
    
    # Create a task
    task_id = orchestrator.create_task(
        description="Calculate 25 * 4 + 100 / 2",
        agent_name="math_agent"
    )
    
    # Execute the task
    result = await orchestrator.execute_task(task_id)
    print(f"Result: {result}")

asyncio.run(main())
```

### Usage Examples

Run the example script to see various use cases:
```bash
python example_usage.py
```

The examples demonstrate:
- Basic task execution
- Parallel task execution
- Shared state management
- Automatic agent selection

### API Reference

#### Creating an Orchestrator

```python
orchestrator = LangChainOrchestrator(
    llm=None,  # Optional: Custom LLM instance
    temperature=0.7,
    max_iterations=15,
    verbose=True
)
```

#### Registering Agents

```python
orchestrator.register_agent(
    name="my_agent",
    tools=[tool1, tool2],  # List of LangChain tools
    system_prompt="You are a helpful assistant...",
    description="Agent description"
)
```

#### Creating and Executing Tasks

```python
# Create a task
task_id = orchestrator.create_task(
    description="Task description",
    agent_name="my_agent",  # Optional
    metadata={"key": "value"}  # Optional
)

# Execute a single task
result = await orchestrator.execute_task(task_id, context={"key": "value"})

# Execute multiple tasks
results = await orchestrator.execute_tasks(
    task_ids=[task1_id, task2_id],
    parallel=True  # or False for sequential
)
```

#### Managing State

```python
# Set shared state
orchestrator.set_shared_state("user_name", "Alice")

# Get shared state
name = orchestrator.get_shared_state("user_name")

# Clear conversation history
orchestrator.clear_history()
```

### Architecture

The orchestrator consists of:

- **LangChainOrchestrator**: Main orchestrator class
- **Task**: Task representation with status tracking
- **Agent Registry**: Manages registered agents and their capabilities
- **Task Queue**: Manages pending and executing tasks
- **Shared State**: Context shared across all agents
- **Conversation History**: Maintains context for agents

### Custom Agents

Create custom agents by defining tools and system prompts:

```python
from langchain.tools import tool

@tool
def my_custom_tool(input: str) -> str:
    """Tool description."""
    return "result"

orchestrator.register_agent(
    name="custom_agent",
    tools=[my_custom_tool],
    system_prompt="You are a custom agent...",
    description="Custom agent description"
)
```

---

## LangChain Red-Teaming Agent for Web Security

A comprehensive LangChain-based agent for performing security testing and red-teaming on web pages. The agent can identify web vulnerabilities, test for XSS, SQL injection, CSRF, and other common web security issues, and generate detailed security reports.

### Related Files

- **`red_team_tools.md`**: Comprehensive reference guide of the best red-teaming tools available (100+ tools organized by category)
- **`red_team_tool_integrations.py`**: Python utilities for integrating with popular red-teaming tools (SQLMap, Nmap, Nuclei, WPScan, FFuf)

### Features

- **XSS Testing**: Craft and test XSS (Cross-Site Scripting) payloads across multiple vectors
- **SQL Injection Testing**: Test for SQL injection vulnerabilities in URL parameters and forms
- **Form Security Testing**: Automatically discover and test forms for vulnerabilities
- **Response Analysis**: Analyze HTTP responses for security headers and sensitive data exposure
- **Comprehensive Reporting**: Generate detailed security reports with vulnerability classifications
- **Extensible Tools**: Easy to add custom testing tools and scenarios

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd vibe-code-bench
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Usage

#### Basic Usage

Test a web page with default test scenarios:
```bash
python red_team_agent.py --url https://example.com
```

#### Single Test Scenario

Run a specific test:
```bash
python red_team_agent.py --url https://example.com --scenario "Test all URL parameters for XSS vulnerabilities"
```

#### Custom Output File

Specify where to save the report:
```bash
python red_team_agent.py --url https://example.com --output my_report.md
```

#### Using Different Providers

Use OpenRouter (default, supports multiple models):
```bash
python red_team_agent.py --url https://example.com --provider openrouter --model anthropic/claude-3.5-sonnet
```

Use Anthropic Claude directly:
```bash
python red_team_agent.py --url https://example.com --provider anthropic --model claude-3-5-sonnet-20241022
```

Use OpenAI:
```bash
python red_team_agent.py --url https://example.com --provider openai --model gpt-4
```

#### Custom Headers

Include custom HTTP headers:
```bash
python red_team_agent.py --url https://example.com --headers '{"Authorization": "Bearer token123"}'
```

### Programmatic Usage

You can also use the agent programmatically:

```python
from red_team_agent import RedTeamAgent

# Initialize the agent with OpenRouter (default)
agent = RedTeamAgent(
    target_url="https://example.com",
    provider="openrouter",
    model_name="anthropic/claude-3.5-sonnet",
    headers={"User-Agent": "CustomAgent/1.0"}
)

# Or use Anthropic directly
agent = RedTeamAgent(
    target_url="https://example.com",
    provider="anthropic",
    model_name="claude-3-5-sonnet-20241022"
)

# Or use OpenAI
agent = RedTeamAgent(
    target_url="https://example.com",
    provider="openai",
    model_name="gpt-4"
)

# Run comprehensive test suite
report = agent.run_test_suite()

# Or test a single URL
result = agent.test_single_url("https://example.com/page?id=123", test_type="xss")

# Get all test results
results = agent.get_results()
```

### Configuration

The agent can be configured via environment variables:

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

### Test Scenarios

The agent includes several built-in test scenarios:

1. Page structure analysis (forms, links, inputs)
2. XSS (Cross-Site Scripting) vulnerability testing
3. SQL injection vulnerability testing
4. Form security testing
5. Security header analysis
6. Sensitive data exposure detection
7. Authentication and authorization testing

### Agent Tools

The agent has access to the following tools:

- `fetch_page`: Fetch and analyze web pages, extract forms and links
- `craft_xss_payload`: Create XSS payloads (basic, event-based, SVG, etc.)
- `craft_sql_injection_payload`: Create SQL injection payloads (union, boolean, time-based, etc.)
- `test_xss`: Test URL parameters for XSS vulnerabilities
- `test_sql_injection`: Test URL parameters for SQL injection vulnerabilities
- `test_form_submission`: Test form submissions with malicious payloads
- `analyze_response_security`: Analyze HTTP responses for security issues
- `generate_report`: Create comprehensive security reports

### Output

The agent generates detailed security reports in Markdown format, including:

- Executive summary with vulnerability counts
- Critical and high-severity vulnerability details
- Test results for each vulnerability found
- URLs, parameters, and payloads used in testing
- Timestamps for all tests performed

### Vulnerability Types Tested

- **XSS (Cross-Site Scripting)**: Multiple payload types including script tags, event handlers, SVG, iframe
- **SQL Injection**: Union-based, boolean-based, time-based, and comment-based attacks
- **Form Security**: Testing all form inputs for injection vulnerabilities
- **Security Headers**: Missing security headers (X-Frame-Options, CSP, HSTS, etc.)
- **Sensitive Data Exposure**: Detection of emails, credit cards, API keys, passwords in responses

### Ethical Considerations

This tool is designed for **ethical security testing** only. Use it to:

- Improve the security of your own web applications
- Test systems you have permission to test
- Identify vulnerabilities in a controlled environment
- Conduct authorized penetration testing

**Do not use this tool to:**

- Attack systems without authorization
- Cause harm or damage
- Violate terms of service
- Engage in malicious activities

### Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### License

[Add your license here]
