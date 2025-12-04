"""
Cached LLM Wrapper

Wraps LangChain LLM instances to add transparent caching.
"""

import logging
from typing import Any, Optional, Dict, List

from vibe_code_bench.core.llm_cache import get_cache

logger = logging.getLogger(__name__)


class CachedLLM:
    """
    Wrapper around LangChain LLM that adds transparent caching.
    
    This wrapper intercepts invoke() calls and checks the cache before
    making API calls. All other methods are passed through to the underlying LLM.
    """
    
    def __init__(self, llm: Any):
        """
        Initialize cached LLM wrapper.
        
        Args:
            llm: LangChain LLM instance to wrap
        """
        object.__setattr__(self, '_llm', llm)
        object.__setattr__(self, '_cache', get_cache())
    
    def __getattr__(self, name: str) -> Any:
        """
        Delegate attribute access to underlying LLM.
        
        Args:
            name: Attribute name
            
        Returns:
            Attribute value from underlying LLM
        """
        return getattr(self._llm, name)
    
    def __setattr__(self, name: str, value: Any) -> None:
        """
        Forward attribute setting to underlying LLM.
        
        Args:
            name: Attribute name
            value: Attribute value
        """
        # Protect wrapper's own attributes
        if name in ('_llm', '_cache'):
            object.__setattr__(self, name, value)
        else:
            # Forward to underlying LLM
            setattr(self._llm, name, value)
    
    def invoke(
        self,
        input: Any,
        config: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Any:
        """
        Invoke LLM with caching.
        
        Args:
            input: Input messages or prompt
            config: Optional configuration dict
            **kwargs: Additional arguments
            
        Returns:
            LLM response
        """
        # Extract model parameters
        model = getattr(self._llm, 'model_name', None) or getattr(self._llm, 'model', 'unknown')
        temperature = getattr(self._llm, 'temperature', None)
        max_tokens = getattr(self._llm, 'max_tokens', None)
        
        # Handle different input formats
        if isinstance(input, list):
            messages = input
        elif hasattr(input, 'messages'):
            messages = input.messages
        elif isinstance(input, dict) and 'messages' in input:
            messages = input['messages']
        else:
            # Convert to message format
            from langchain_core.messages import HumanMessage
            messages = [HumanMessage(content=str(input))]
        
        # Check cache
        cached_response = self._cache.get(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
        
        if cached_response is not None:
            return cached_response
        
        # Cache miss - make actual API call
        logger.info(f"Cache miss - making API call to {model}")
        response = self._llm.invoke(input, config=config, **kwargs)
        
        # Store in cache
        self._cache.set(
            model=model,
            messages=messages,
            response=response,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )
        
        return response
    
    def stream(
        self,
        input: Any,
        config: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Any:
        """
        Stream LLM responses (not cached, passes through).
        
        Args:
            input: Input messages or prompt
            config: Optional configuration dict
            **kwargs: Additional arguments
            
        Returns:
            Streaming response
        """
        # Streaming is not cached - pass through
        return self._llm.stream(input, config=config, **kwargs)
    
    def batch(
        self,
        inputs: List[Any],
        config: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> List[Any]:
        """
        Batch invoke LLM (cached per input).
        
        Args:
            inputs: List of input messages or prompts
            config: Optional configuration dict
            **kwargs: Additional arguments
            
        Returns:
            List of LLM responses
        """
        # Process each input individually to leverage caching
        results = []
        for input_item in inputs:
            results.append(self.invoke(input_item, config=config, **kwargs))
        return results


def wrap_llm_with_cache(llm: Any) -> CachedLLM:
    """
    Wrap a LangChain LLM instance with caching.
    
    Args:
        llm: LangChain LLM instance
        
    Returns:
        CachedLLM wrapper instance
    """
    return CachedLLM(llm)

