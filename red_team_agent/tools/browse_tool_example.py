"""
Example: Using @tool decorator instead of StructuredTool.from_function()

This shows the alternative approach using @tool decorator.
"""

import requests
from bs4 import BeautifulSoup
from langchain_core.tools import tool  # Import @tool decorator


@tool
def browse_url_with_decorator(url: str) -> str:
    """
    Browse a URL and return the first 3 lines of visible text content.
    
    Args:
        url: The URL to browse
        
    Returns:
        First 3 lines of the website's visible text content
    """
    try:
        # Fetch the URL
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Parse HTML and extract visible text content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text content
        text = soup.get_text()
        
        # Extract first 3 non-empty lines
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        
        # Return first 3 lines
        first_3_lines = '\n'.join(lines[:3]) if len(lines) >= 3 else '\n'.join(lines)
        
        return f"First 3 lines from {url}:\n{first_3_lines}"
    except Exception as e:
        return f"Error browsing {url}: {str(e)}"


# With @tool, the function IS the tool - no need for get_browse_tool() function!
# You can use browse_url_with_decorator directly as a tool

