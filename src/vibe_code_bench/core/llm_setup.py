"""
LLM initialization and configuration.
"""

import os
import logging
from typing import Optional, Tuple, Any

logger = logging.getLogger(__name__)

from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic


def initialize_llm(
    provider: str,
    model_name: Optional[str],
    temperature: float,
    api_key: Optional[str],
    max_tokens: Optional[int] = None,
    timeout: Optional[int] = None
) -> Tuple[Any, str]:
    """
    Initialize the LLM based on the specified provider.
    
    Args:
        provider: LLM provider ('openrouter', 'anthropic', or 'openai')
        model_name: Model name (optional, defaults based on provider)
        temperature: Temperature for the LLM
        api_key: API key (optional, can use env vars)
        max_tokens: Maximum tokens for response (optional, defaults based on provider)
        timeout: Timeout in seconds (optional, defaults based on provider)
    
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
        
        
        # Default values for red team agent (low limits)
        default_max_tokens = max_tokens if max_tokens is not None else 100
        default_timeout = timeout if timeout is not None else 60
        
        llm = ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            max_tokens=default_max_tokens,
            timeout=default_timeout,
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
            
            # Remove quotes if present and ensure /v1 suffix
            base_url = base_url.strip('"\'')
            if not base_url.endswith('/v1') and not base_url.endswith('/v1/'):
                base_url = f"{base_url}/v1" if not base_url.endswith('/') else f"{base_url}v1"
            
            logger.info(f"Using custom Anthropic base URL: {base_url}")
            default_max_tokens = max_tokens if max_tokens is not None else 1024
            llm = ChatOpenAI(
                model=model_name,
                temperature=temperature,
                api_key=api_key,
                base_url=base_url,
                max_tokens=default_max_tokens,
                timeout=timeout if timeout is not None else 60
            )
        else:
            
            default_max_tokens = max_tokens if max_tokens is not None else 1024
            llm = ChatAnthropic(
                model=model_name,
                temperature=temperature,
                api_key=api_key,
                max_tokens=default_max_tokens
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
        
        
        default_max_tokens = max_tokens if max_tokens is not None else 1024
        llm = ChatOpenAI(
            model=model_name,
            temperature=temperature,
            api_key=api_key,
            max_tokens=default_max_tokens,
            timeout=timeout if timeout is not None else 60
        )
    else:
        raise ValueError(
            f"Unknown provider: {provider}. "
            f"Supported providers: 'openrouter', 'anthropic', 'openai'"
        )
    
    return llm, model_name

