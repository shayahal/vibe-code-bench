# Test Suite Documentation

This directory contains comprehensive tests for the LangChain agents and orchestrator.

## Test Structure

### Test Files

- **`test_red_team_agent.py`**: Comprehensive tests for the `RedTeamAgent` class
  - Initialization tests
  - Tool creation and functionality tests
  - Method tests
  - Edge cases and error handling

- **`test_orchestrator.py`**: Tests for the `LangChainOrchestrator` class
  - Agent registration
  - Task management
  - Task execution (sequential and parallel)
  - State management
  - Callback handling

- **`test_example_agents.py`**: Tests for example agent tools and configurations
  - Calculator tool tests
  - Text analyzer tool tests
  - Data formatter tool tests
  - Agent configuration tests

- **`test_integration.py`**: Integration tests for agent interactions
  - Orchestrator with example agents
  - RedTeamAgent workflows
  - End-to-end workflows
  - Concurrent operations

- **`conftest.py`**: Shared fixtures and test configuration
  - Mock objects
  - Sample data fixtures
  - Environment setup

## Running Tests

### Run all tests
```bash
pytest
```

### Run specific test file
```bash
pytest tests/test_red_team_agent.py
```

### Run specific test class
```bash
pytest tests/test_red_team_agent.py::TestRedTeamAgentInitialization
```

### Run specific test
```bash
pytest tests/test_red_team_agent.py::TestRedTeamAgentInitialization::test_init_with_api_key
```

### Run with coverage
```bash
pytest --cov=. --cov-report=html
```

### Run in verbose mode
```bash
pytest -v
```

### Run only unit tests
```bash
pytest -m unit
```

### Run only integration tests
```bash
pytest -m integration
```

## Test Coverage

The test suite aims to achieve comprehensive coverage of:

- ✅ Agent initialization and configuration
- ✅ Tool creation and functionality
- ✅ Task management and execution
- ✅ Error handling and edge cases
- ✅ Integration workflows
- ✅ Concurrent operations
- ✅ State management

## Mocking

Tests use extensive mocking to avoid:
- Actual API calls to OpenAI
- Real HTTP requests
- External dependencies

All external dependencies are mocked using `unittest.mock` and `pytest-mock`.

## Fixtures

Common fixtures available in `conftest.py`:

- `mock_openai_api_key`: Mock API key for testing
- `mock_llm`: Mock LangChain LLM
- `sample_html_page`: Sample HTML for testing
- `mock_session`: Mock requests session
- `sample_test_results`: Sample test results
- `mock_agent_executor`: Mock agent executor

## Writing New Tests

When adding new tests:

1. Follow the naming convention: `test_*.py` for files, `test_*` for functions
2. Use fixtures from `conftest.py` when possible
3. Mock external dependencies
4. Add docstrings to test classes and methods
5. Group related tests in test classes
6. Use appropriate pytest markers

## Requirements

Test dependencies are listed in `requirements.txt`:

- pytest>=7.4.0
- pytest-asyncio>=0.21.0
- pytest-mock>=3.11.0
- pytest-cov>=4.1.0
- responses>=0.23.0

Install with:
```bash
pip install -r requirements.txt
```

