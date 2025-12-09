# Browsing Agent

A comprehensive web browsing agent for discovering pages on web applications using LangChain and Anchor Browser tools.

## Features

- **Hybrid Discovery**: Uses sitemap.xml, robots.txt, and link crawling
- **JavaScript Support**: Full JavaScript rendering with Anchor Browser tools
- **Authentication**: Session-based authentication handling
- **Intelligent Navigation**: LangChain agent makes decisions about which pages to visit
- **Comprehensive Analysis**: Extracts metadata, links, forms, and navigation patterns
- **Anchor Browser Integration**: Uses LangChain Anchor Browser tools for AI-driven browser automation

## Usage

```python
from vibe_code_bench.browsing_agent import BrowsingAgent

# Initialize agent
agent = BrowsingAgent(
    max_pages=50,
    respect_robots=True,
    enable_javascript=True,
    headless=True
)

# Discover pages
result = agent.discover(
    "https://example.com",
    auth_credentials={"username": "user", "password": "pass"}  # Optional
)

# Save results
output_path = agent.save_results(result)
print(f"Discovered {result.total_pages} pages")
print(f"Results saved to {output_path}")
```

## Architecture

- **BrowsingAgent** (`__init__.py`): Main orchestrator class
- **LangChain Agent** (`agent.py`): Decision-making agent with tools (includes Anchor Browser tools)
- **BrowserWrapper** (`browser.py`): Anchor Browser wrapper using LangChain Anchor Browser tools
- **DiscoveryEngine** (`discovery.py`): Sitemap/robots/link discovery
- **PageAnalyzer** (`analyzer.py`): Page content analysis
- **AuthenticationHandler** (`auth.py`): Authentication management
- **Models** (`models.py`): Data models (PageInfo, DiscoveryResult)

## Requirements

- Python 3.8+
- `langchain-anchorbrowser` - Anchor Browser integration for LangChain
- LangChain and LLM provider (OpenAI or Anthropic API key)

## Environment Variables

Set the following (in `.env` file):
- `ANCHORBROWSER_API_KEY` - **Required** - Anchor Browser API key (get from https://app.anchorbrowser.io/api-keys)
- One of the following for LLM:
  - `OPENAI_API_KEY` - For OpenAI models
  - `ANTHROPIC_API_KEY` - For Anthropic models
  - `OPENROUTER_API_KEY` - For OpenRouter (supports multiple models)
