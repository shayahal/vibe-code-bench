# Langfuse Integration - Complete Trace Hierarchy

## Setup

### 1. Install Langfuse
```bash
pip install langfuse
```

### 2. Set Environment Variables
Create/update `.env`:
```bash
# Required for Langfuse tracing
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_HOST=https://cloud.langfuse.com  # Optional, defaults to cloud

# Required for LLM (pick one)
OPENAI_API_KEY=sk-...
```

### 3. Run a Scan
```python
from vibe_code_bench.red_team_agent import scan

report = scan("https://example.com")
```

### 4. View in Langfuse
- Go to https://cloud.langfuse.com
- Navigate to "Traces" → Filter by session ID (e.g., `red_team_20251231_193210`)
- See complete scan execution tree

---

## Trace Hierarchy

### Session-Based Organization
**Every scan = 1 session** with unique ID: `red_team_YYYYMMDD_HHMMSS`

All traces/spans within a scan share this session ID, allowing you to:
- View all operations for a single scan together
- Filter by session in Langfuse UI
- Track costs per scan
- Debug specific scans

### Complete Trace Tree

```
Session: red_team_20251231_143022
│
├─ Trace: scan (ROOT)
│  │  Metadata: {url, scan_depth, run_id}
│  │  Duration: 45.3s
│  │
│  ├─ Span: configure_scan
│  │  │  Metadata: {depth: "deep", strategy: "active"}
│  │  │  Duration: 0.12s
│  │  └─ Output: ScanConfig object
│  │
│  ├─ Span: discover_targets
│  │  │  Metadata: {target_url, max_pages}
│  │  │  Duration: 15.8s
│  │  │
│  │  ├─ Span: BrowsingAgent.discover (auto-traced)
│  │  │  ├─ LLM Generation: "Discover pages systematically"
│  │  │  │  ├─ Prompt: 450 tokens
│  │  │  │  ├─ Completion: 230 tokens
│  │  │  │  └─ Cost: $0.0034
│  │  │  ├─ Tool: visit_page (x23)
│  │  │  └─ Tool: extract_forms (x8)
│  │  │
│  │  ├─ Span: TargetBuilder.build_targets
│  │  │  └─ Metadata: {urls: 47, forms: 8, targets_built: 23}
│  │  │
│  │  └─ Output: [23 TestableTarget objects]
│  │
│  ├─ Span: execute_testing
│  │  │  Metadata: {num_targets: 23, mode: "llm_orchestration"}
│  │  │  Duration: 28.4s
│  │  │
│  │  └─ Span: llm_orchestrated_testing
│  │     │
│  │     ├─ LLM Generation #1: "Analyze discovered targets"
│  │     │  ├─ Prompt: 1,850 tokens (includes all 23 targets)
│  │     │  ├─ Completion: 420 tokens
│  │     │  ├─ Model: gpt-4o
│  │     │  ├─ Cost: $0.0142
│  │     │  └─ Output: "Start with login form at /login..."
│  │     │
│  │     ├─ Tool Call: scan_with_sqlmap
│  │     │  │  Input: {url: "/login", method: "POST", parameters: {...}}
│  │     │  │
│  │     │  └─ Span: sqlmap_langchain_tool
│  │     │     │  Metadata: {tool: "sqlmap", level: 5, risk: 3}
│  │     │     │  Duration: 12.3s
│  │     │     │
│  │     │     ├─ Subprocess: sqlmap command execution
│  │     │     ├─ Output parsing with regex
│  │     │     └─ Output: {"success": true, "findings": [
│  │     │        {
│  │     │          "vulnerability_type": "SQL Injection",
│  │     │          "severity": "Critical",
│  │     │          "url": "/login",
│  │     │          "parameter": "username",
│  │     │          "injection_type": "boolean-based blind"
│  │     │        }
│  │     │     ]}
│  │     │
│  │     ├─ LLM Generation #2: "Process SQLMap finding"
│  │     │  ├─ Prompt: 620 tokens
│  │     │  ├─ Completion: 180 tokens
│  │     │  └─ Cost: $0.0051
│  │     │
│  │     ├─ Tool Call: scan_with_sqlmap (follow-up)
│  │     │  │  Input: {url: "/login", parameters: {password: "..."}}
│  │     │  └─ Span: sqlmap_langchain_tool
│  │     │     └─ Output: {"findings": []} (password not vulnerable)
│  │     │
│  │     ├─ Tool Call: scan_with_dalfox
│  │     │  │  Input: {url: "/search", parameters: {q: "test"}}
│  │     │  │
│  │     │  └─ Span: dalfox_langchain_tool
│  │     │     │  Duration: 3.2s
│  │     │     └─ Output: {"findings": [{
│  │     │        "vulnerability_type": "XSS",
│  │     │        "severity": "High"
│  │     │     }]}
│  │     │
│  │     └─ LLM Generation #3: "Summarize findings"
│  │        ├─ Prompt: 890 tokens
│  │        ├─ Completion: 210 tokens
│  │        └─ Cost: $0.0067
│  │
│  └─ Span: generate_report
│     │  Duration: 1.2s
│     └─ Output: ScanReport (2 vulnerabilities)
│
└─ Total Cost: $0.0294
   Total Duration: 45.3s
   Total LLM Calls: 4
   Total Tool Calls: 4
```

---

## What Gets Traced

### 1. Manual Spans (@traced decorator)
Every function decorated with `@traced()`:
- `scan()` - Root span
- `configure_scan()` - Configuration phase
- `discover_targets()` - Discovery phase
- `execute_testing()` - Testing phase
- `llm_orchestrated_testing()` - LLM agent orchestration
- `sequential_testing()` - Sequential mode fallback
- `generate_report()` - Reporting phase
- `sqlmap_langchain_tool()` - SQLMap wrapper
- `dalfox_langchain_tool()` - DalFox wrapper

### 2. LangGraph Auto-Tracing (via CallbackHandler)
All LangChain/LangGraph operations:
- **LLM Calls**: Every GPT-4/Claude invocation
  - Prompt (full text)
  - Completion (full text)
  - Tokens (prompt/completion/total)
  - Cost (calculated automatically)
  - Latency
  - Model name

- **Tool Invocations**: Every `@tool` call
  - Input arguments (serialized)
  - Output (serialized)
  - Execution time
  - Success/failure status

- **Agent Steps**: ReAct reasoning
  - Thought: "The login form is a prime SQLi target"
  - Action: `scan_with_sqlmap`
  - Action Input: `{url: "/login", ...}`
  - Observation: `{"findings": [...]}`

### 3. Structured Logs
All `logger.info/warning/error` calls:
- Logged to file: `data/runs/red_team_agent/{run_id}/logs/red_team.log`
- Also visible in Langfuse as events

### 4. Metadata Captured
- **Session level**: `run_id`, scan start time
- **Scan level**: Target URL, scan depth, strategy
- **Discovery level**: Pages found, forms extracted, targets built
- **Testing level**: Number of targets, tools used, mode (LLM/sequential)
- **Tool level**: Tool name, timeout, level, risk, findings count
- **LLM level**: Model, tokens, cost, latency

---

## How Spans Nest (Parent-Child Relationships)

### Automatic Nesting
Langfuse automatically creates parent-child relationships when:
1. Spans are created within the context of another span
2. Using `@traced` decorator on nested function calls

Example:
```python
@traced("scan")
def scan(url):
    config = self._configure_scan()  # Child span
    targets = self._discover_targets()  # Child span
    results = self._execute_testing()  # Child span
    return self._generate_report()  # Child span
```

Result in Langfuse:
```
scan (parent)
├─ configure_scan (child of scan)
├─ discover_targets (child of scan)
├─ execute_testing (child of scan)
│  └─ llm_orchestrated_testing (child of execute_testing)
│     └─ sqlmap_langchain_tool (child of llm_orchestrated_testing)
└─ generate_report (child of scan)
```

---

## Viewing Traces in Langfuse

### 1. Session View
**Filter by Session ID**:
- Click "Sessions" in Langfuse UI
- Find session: `red_team_20251231_143022`
- See all scans from that run grouped together

### 2. Trace View
**Click on a specific trace** to see:
- Complete execution tree (expandable)
- Timeline visualization
- Token usage per LLM call
- Total cost
- Error messages (if any)

### 3. Performance Analysis
**Identify bottlenecks**:
- Sort spans by duration
- See which tools take longest
- Optimize based on data

Example insights:
- SQLMap takes 12s → Consider reducing timeout for faster scans
- Discovery takes 15s → BrowsingAgent found 47 pages, might be overkill
- LLM calls cost $0.03 → Reasonable for deep scan

### 4. Cost Tracking
**Monitor spending**:
- Total cost per scan
- Cost per LLM call
- Cost per tool execution
- Monthly totals

---

## Session ID Management

### How Session IDs Work
```python
# In ObservabilityManager.__init__:
self.run_id = f"red_team_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# Used for:
1. LangfuseCallbackHandler(session_id=self.run_id)
2. langfuse.span(session_id=self.run_id)
3. Log file path: data/runs/red_team_agent/{run_id}/
```

### Benefits
- **Correlation**: All operations for one scan share same session
- **Debugging**: Filter to specific problematic scan
- **Analytics**: Aggregate metrics per scan
- **Cost attribution**: Know exact cost per scan

---

## Integration Points

### 1. Agent Initialization
```python
# src/vibe_code_bench/red_team_agent/agent.py
class RedTeamAgent:
    def __init__(self):
        # ObservabilityManager auto-initializes
        self.obs = ObservabilityManager.get_instance(run_id)
        self.logger = get_logger(__name__)
```

### 2. LangGraph Agent
```python
# Get callback handler for Langfuse
callbacks = [get_callback_handler()]

# Invoke agent with tracing
result = self.agent.invoke(
    {"messages": [HumanMessage(content=prompt)]},
    config={"callbacks": callbacks}  # ← All LLM/tool calls traced!
)
```

### 3. Tool Wrappers
```python
@tool
@traced("sqlmap_langchain_tool")  # ← Creates span
def scan_with_sqlmap(target: dict) -> str:
    logger.info(f"SQLMap called")  # ← Logged
    sqlmap = SQLMapTool(timeout=1800)
    result = sqlmap.scan(...)  # ← Timed
    return json.dumps(result)  # ← Output captured
```

---

## Complete Setup Checklist

- [ ] Install Langfuse: `pip install langfuse`
- [ ] Set environment variables in `.env`:
  - `LANGFUSE_PUBLIC_KEY`
  - `LANGFUSE_SECRET_KEY`
  - `OPENAI_API_KEY` (or Anthropic/OpenRouter)
- [ ] Run a test scan: `python -c "from vibe_code_bench.red_team_agent import scan; scan('https://example.com')"`
- [ ] Check Langfuse UI for traces
- [ ] Verify session ID appears
- [ ] Confirm LLM calls are logged
- [ ] Check cost calculation

---

## Troubleshooting

### No Traces Appearing
**Check**:
1. Langfuse keys correct? → `echo $LANGFUSE_PUBLIC_KEY`
2. Langfuse installed? → `pip list | grep langfuse`
3. Look for warning in logs: "Langfuse not installed" or "keys not set"

### Session Not Grouping
**Check**:
- Session ID in callback handler: Line 138 in observability.py
- Session ID in manual spans: Line 292 in observability.py
- Both should use `self.run_id`

### LLM Calls Not Traced
**Check**:
- Callback handler passed to agent.invoke()
- Agent initialized with LangGraph: `create_react_agent()`
- LLM API key set

### Costs Not Calculated
**Check**:
- Using OpenAI model? (Anthropic/OpenRouter may not auto-calculate)
- Langfuse has pricing data for model
- Check Langfuse model configuration

---

## Benefits of This Integration

1. **Full Transparency**: See exactly what the agent does
2. **Cost Control**: Know what each scan costs before scaling
3. **Performance Optimization**: Identify slow tools/LLM calls
4. **Debugging**: Trace execution when scans fail
5. **Analytics**: Track vulnerability detection rates
6. **Compliance**: Audit trail of all operations
7. **Iteration**: A/B test different prompts/strategies

**Every scan is fully observable from start to finish!**
