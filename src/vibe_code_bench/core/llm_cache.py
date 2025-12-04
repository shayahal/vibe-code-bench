"""
LLM Response Caching Module

Provides file-based caching for LLM API calls to avoid redundant API requests
and reduce costs. Caches responses based on a hash of the input parameters.
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Any, Optional, Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)

from vibe_code_bench.core.paths import get_cache_dir

# Default cache directory (absolute from repo root)
CACHE_DIR = get_cache_dir() / "llm"


class LLMCache:
    """
    File-based cache for LLM responses.
    
    Caches responses based on a hash of:
    - Model name
    - Messages content
    - Temperature
    - Max tokens
    - Other relevant parameters
    """
    
    def __init__(self, cache_dir: Optional[Path] = None, enabled: bool = True):
        """
        Initialize the LLM cache.
        
        Args:
            cache_dir: Directory to store cache files (default: .llm_cache)
            enabled: Whether caching is enabled (default: True)
        """
        if cache_dir:
            from vibe_code_bench.core.paths import get_absolute_path
            self.cache_dir = get_absolute_path(cache_dir)
        else:
            self.cache_dir = CACHE_DIR
        
        self.enabled = enabled
        
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"LLM cache initialized at: {self.cache_dir}")
        else:
            logger.info("LLM cache disabled")
    
    def _serialize_messages(self, messages: Any) -> List[Dict[str, Any]]:
        """
        Serialize messages to a JSON-serializable format.
        
        Args:
            messages: LangChain messages (list of message objects)
            
        Returns:
            List of serialized message dictionaries
        """
        serialized = []
        for msg in messages:
            if hasattr(msg, 'content'):
                content = msg.content
                msg_type = type(msg).__name__
            elif isinstance(msg, tuple):
                # Handle tuple format: ("human", "message")
                msg_type, content = msg[0], msg[1]
            elif isinstance(msg, dict):
                # Handle dict format
                msg_type = msg.get('type', 'unknown')
                content = msg.get('content', str(msg))
            else:
                msg_type = 'unknown'
                content = str(msg)
            
            serialized.append({
                'type': msg_type,
                'content': content
            })
        return serialized
    
    def _create_cache_key(
        self,
        model: str,
        messages: Any,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        """
        Create a cache key from the input parameters.
        
        Args:
            model: Model name
            messages: Input messages
            temperature: Temperature setting
            max_tokens: Max tokens setting
            **kwargs: Additional parameters
            
        Returns:
            SHA256 hash string as cache key
        """
        # Serialize messages
        serialized_messages = self._serialize_messages(messages)
        
        # Create a dictionary of all relevant parameters
        cache_data = {
            'model': model,
            'messages': serialized_messages,
            'temperature': temperature,
            'max_tokens': max_tokens,
        }
        
        # Add any additional kwargs that might affect the response
        # Filter out non-serializable or irrelevant parameters
        relevant_kwargs = {}
        for key, value in kwargs.items():
            # Skip callbacks, config, and other runtime parameters
            if key not in ['callbacks', 'config', 'tags', 'metadata', 'run_name']:
                try:
                    json.dumps(value)
                    relevant_kwargs[key] = value
                except (TypeError, ValueError):
                    pass
        
        cache_data.update(relevant_kwargs)
        
        # Create hash
        cache_str = json.dumps(cache_data, sort_keys=True, ensure_ascii=False)
        cache_hash = hashlib.sha256(cache_str.encode('utf-8')).hexdigest()
        
        return cache_hash
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """
        Get the file path for a cache key.
        
        Args:
            cache_key: Cache key (hash)
            
        Returns:
            Path to cache file
        """
        return self.cache_dir / f"{cache_key}.json"
    
    def get(
        self,
        model: str,
        messages: Any,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> Optional[Any]:
        """
        Get cached response if available.
        
        Args:
            model: Model name
            messages: Input messages
            temperature: Temperature setting
            max_tokens: Max tokens setting
            **kwargs: Additional parameters
            
        Returns:
            Cached response object if found, None otherwise
        """
        if not self.enabled:
            return None
        
        try:
            cache_key = self._create_cache_key(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs
            )
            
            cache_path = self._get_cache_path(cache_key)
            
            if cache_path.exists():
                logger.debug(f"Cache hit for key: {cache_key[:16]}...")
                with open(cache_path, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                # Reconstruct the response object
                # LangChain responses typically have a 'content' attribute
                from langchain_core.messages import AIMessage
                
                response_content = cache_data.get('content', '')
                response = AIMessage(content=response_content)
                
                logger.info(f"✓ Cache hit - using cached response (saved {cache_data.get('timestamp', 'unknown')})")
                return response
            else:
                logger.debug(f"Cache miss for key: {cache_key[:16]}...")
                return None
                
        except Exception as e:
            logger.warning(f"Error reading from cache: {e}")
            return None
    
    def set(
        self,
        model: str,
        messages: Any,
        response: Any,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> None:
        """
        Store response in cache.
        
        Args:
            model: Model name
            messages: Input messages
            response: Response object to cache
            temperature: Temperature setting
            max_tokens: Max tokens setting
            **kwargs: Additional parameters
        """
        if not self.enabled:
            return
        
        try:
            cache_key = self._create_cache_key(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs
            )
            
            cache_path = self._get_cache_path(cache_key)
            
            # Extract content from response
            if hasattr(response, 'content'):
                content = response.content
            else:
                content = str(response)
            
            # Store cache data
            cache_data = {
                'model': model,
                'content': content,
                'timestamp': datetime.now().isoformat(),
                'temperature': temperature,
                'max_tokens': max_tokens,
            }
            
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"Cached response with key: {cache_key[:16]}...")
            
        except Exception as e:
            logger.warning(f"Error writing to cache: {e}")


# Global cache instance
_global_cache: Optional[LLMCache] = None


def get_cache() -> LLMCache:
    """
    Get the global LLM cache instance.
    
    Returns:
        Global LLMCache instance
    """
    global _global_cache
    if _global_cache is None:
        # Check if caching is disabled via environment variable
        cache_enabled = os.getenv("LLM_CACHE_ENABLED", "true").lower() == "true"
        cache_dir = os.getenv("LLM_CACHE_DIR")
        cache_path = Path(cache_dir) if cache_dir else None
        
        _global_cache = LLMCache(cache_dir=cache_path, enabled=cache_enabled)
    
    return _global_cache


def clear_cache() -> int:
    """
    Clear all cached responses.
    
    Returns:
        Number of cache files deleted
    """
    cache = get_cache()
    if not cache.cache_dir.exists():
        return 0
    
    count = 0
    for cache_file in cache.cache_dir.glob("*.json"):
        try:
            cache_file.unlink()
            count += 1
        except Exception as e:
            logger.warning(f"Error deleting cache file {cache_file}: {e}")
    
    logger.info(f"Cleared {count} cache files")
    return count

