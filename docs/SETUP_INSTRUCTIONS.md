# Setup Instructions

The package is now properly configured with all dependencies in `pyproject.toml`.

## Quick Setup

1. **Create a fresh virtual environment:**
   ```powershell
   python -m venv venv
   ```

2. **Activate the virtual environment:**
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```
   (If you get an execution policy error, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`)

3. **Install the package with all dependencies:**
   ```powershell
   pip install -e .
   ```
   This will automatically install all dependencies listed in `pyproject.toml`.

4. **Test the installation:**
   ```powershell
   python test_setup.py
   ```

## What's Configured

- ✅ All packages moved to `src/vibe_code_bench/`
- ✅ `pyproject.toml` with all dependencies
- ✅ All imports use absolute `vibe_code_bench.` prefix
- ✅ No try/except blocks for imports
- ✅ Package is installable via `pip install -e .`

## Dependencies

All dependencies are specified in `pyproject.toml` under `[project.dependencies]`. The package will automatically install:
- LangChain and related packages
- LangFuse for observability
- Flask for web serving
- BeautifulSoup4 for HTML parsing
- Testing tools (pytest, etc.)

## Verification

After installation, you should be able to import:
```python
from vibe_code_bench.core.llm_setup import initialize_llm
from vibe_code_bench.red_team_agent.agent_common import initialize_langfuse
from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.website_generator.prompts import SYSTEM_PROMPT
```

