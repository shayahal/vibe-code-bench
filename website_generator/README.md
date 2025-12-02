# Website Generator

An LLM-powered code generator that creates complete, functional websites based on predefined prompts or custom requirements.

## Features

- **Simple & Efficient**: Generates all website code in a single LLM call
- **LLM-Powered**: Uses LangChain with multiple LLM providers (OpenRouter, Anthropic, OpenAI)
- **Multiple Templates**: Pre-built prompts for different website types
- **Complete Websites**: Creates HTML, CSS, and JavaScript files
- **Organized Output**: Each run creates a unique directory with logs and metadata
- **Flexible**: Use templates or provide custom prompts

## Installation

The generator uses the same dependencies as the main project. Ensure you have:

```bash
pip install -r requirements.txt
```

Set up your API keys in a `.env` file:

```env
OPENROUTER_API_KEY=your_key_here
# OR
ANTHROPIC_API_KEY=your_key_here
# OR
OPENAI_API_KEY=your_key_here
```

## Usage

### Command Line

```bash
# Create a default website
python -m website_generator.main --template default

# Create an e-commerce website
python -m website_generator.main --template ecommerce

# Create a portfolio website
python -m website_generator.main --template portfolio

# Create a blog website
python -m website_generator.main --template blog

# Create a landing page
python -m website_generator.main --template landing

# Use a custom prompt
python -m website_generator.main --prompt "Create a simple restaurant website with menu and contact form"

# Specify LLM provider
python -m website_generator.main --template default --provider anthropic

# Specify output directory
python -m website_generator.main --template default --output ./my_website
```

### Python API

```python
# The generator is primarily CLI-based
# Run via: python -m website_generator.main
```

## Available Templates

- **default**: Modern, beautiful website with header, hero, content sections, and footer
- **ecommerce**: E-commerce website with product listings, cart, and checkout
- **portfolio**: Professional portfolio with projects, skills, and contact form
- **blog**: Blog website with post listings, categories, and search
- **landing**: High-converting landing page with CTAs and testimonials

## Output Structure

Each run creates a directory structure:

```
runs/
  run_TIMESTAMP/
    website/              # Website files (HTML, CSS, JS)
      index.html
      styles.css
      script.js
    logs/                 # Log files
      agent.log
      debug.log
      info.log
      warnings.log
      errors.log
    metadata.json         # Run metadata
```

## How It Works

The generator:
1. Sends a prompt to the LLM requesting complete website code
2. LLM generates all code in JSON format with file contents
3. Generator parses the JSON response to extract HTML, CSS, JavaScript, and Python files
4. Files are written directly to the output directory

Simple and efficient - just one LLM call, parse JSON, and write files!

## Examples

### Example 1: Default Website

```bash
python -m website_generator.main --template default
```

Creates a modern, responsive website with:
- Header with navigation
- Hero section
- Content sections
- Footer

### Example 2: Custom Prompt

```bash
python -m website_generator.main --prompt "Create a simple calculator website with a modern UI"
```

Creates a website based on your specific requirements.

### Example 3: Using Different Provider

```bash
python -m website_generator.main --template portfolio --provider anthropic --model claude-3-haiku-20240307
```

Uses Anthropic's Claude model instead of the default.

## Configuration

The generator supports the same LLM providers as the red team agent:

- **OpenRouter**: Access to multiple models via OpenRouter
- **Anthropic**: Claude models
- **OpenAI**: GPT models

Default model selection:
- OpenRouter: `openai/gpt-3.5-turbo`
- Anthropic: `claude-3-haiku-20240307`
- OpenAI: `gpt-3.5-turbo`

## Troubleshooting

### API Key Issues

Make sure your API key is set in the environment or `.env` file:

```bash
export OPENROUTER_API_KEY=your_key_here
```

### Output Directory Permissions

Ensure you have write permissions to the output directory.

### LLM Errors

If you encounter API errors:
- Check your API key is valid
- Verify you have sufficient credits/quota
- Try a different provider with `--provider`

## License

Same license as the main project.

