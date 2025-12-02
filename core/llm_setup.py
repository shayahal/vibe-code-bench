"""
LLM initialization and configuration.
"""

import os
import logging
from typing import Optional, Tuple, Any

logger = logging.getLogger(__name__)

# Try importing LLM providers
try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None

try:
    from langchain_anthropic import ChatAnthropic
except ImportError:
    ChatAnthropic = None


def initialize_llm(
    provider: str,
    model_name: Optional[str],
    temperature: float,
    api_key: Optional[str]
) -> Tuple[Any, str]:
    """
    Initialize the LLM based on the specified provider.
    
    Args:
        provider: LLM provider ('openrouter', 'anthropic', or 'openai')
        model_name: Model name (optional, defaults based on provider)
        temperature: Temperature for the LLM
        api_key: API key (optional, can use env vars)
    
    Returns:
        Tuple of (llm instance, model_name used)
    """
    if provider == "openrouter":
        api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError(
                "OpenRouter API key required. Set OPENROUTER_API_KEY env var "
                "or pass api_key parameter."
            )
        default_model = "openai/gpt-3.5-turbo"
        model_name = model_name or default_model
        
        if ChatOpenAI is None:
            raise ImportError(
                "langchain-openai is required for OpenRouter support. "
                "Install with: pip install langchain-openai"
            )
        
        llm = ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            max_tokens=1024,  # Limit tokens to stay within credit limits
            default_headers={
                "HTTP-Referer": "https://github.com/shayahal/vibe-code-bench",
                "X-Title": "Red-Team Agent"
            }
        )
        
    elif provider == "anthropic":
        api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY env var "
                "or pass api_key parameter."
            )
        default_model = os.getenv("ANTHROPIC_MODEL", "claude-3-haiku-20240307")
        model_name = model_name or default_model
        
        # Check if custom base URL is provided (for custom endpoints like yovy.app)
        base_url = os.getenv("ANTHROPIC_BASE_URL")
        if base_url:
            if ChatOpenAI is None:
                raise ImportError(
                    "langchain-openai is required for custom Anthropic endpoints. "
                    "Install with: pip install langchain-openai"
                )
            
            # Remove quotes if present and ensure /v1 suffix
            base_url = base_url.strip('"\'')
            if not base_url.endswith('/v1') and not base_url.endswith('/v1/'):
                base_url = f"{base_url}/v1" if not base_url.endswith('/') else f"{base_url}v1"
            
            logger.info(f"Using custom Anthropic base URL: {base_url}")
            llm = ChatOpenAI(
                model=model_name,
                temperature=temperature,
                api_key=api_key,
                base_url=base_url,
                max_tokens=1024  # Limit tokens to stay within credit limits
            )
        else:
            if ChatAnthropic is None:
                raise ImportError(
                    "langchain-anthropic is required. "
                    "Install with: pip install langchain-anthropic"
                )
            
            llm = ChatAnthropic(
                model=model_name,
                temperature=temperature,
                api_key=api_key,
                max_tokens=1024  # Limit tokens to stay within credit limits
            )
        
    elif provider == "openai":
        api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OpenAI API key required. Set OPENAI_API_KEY env var "
                "or pass api_key parameter."
            )
        default_model = "gpt-3.5-turbo"
        model_name = model_name or default_model
        
        if ChatOpenAI is None:
            raise ImportError(
                "langchain-openai is required. "
                "Install with: pip install langchain-openai"
            )
        
        llm = ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key,
            max_tokens=1024  # Limit tokens to stay within credit limits
        )
    else:
        raise ValueError(
            f"Unknown provider: {provider}. "
            f"Supported providers: 'openrouter', 'anthropic', 'openai'"
        )
    
    return llm, model_name

