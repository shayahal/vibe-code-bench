"""
Website Creator Agent

Generates all website code in a single LLM call and then
parses and writes the files directly. Simple and efficient.
"""

import os
import logging
import json
import re
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from langchain_core.messages import HumanMessage, SystemMessage

from core.llm_setup import initialize_llm
from core.run_directory import setup_run_directory
from core.logging_setup import setup_file_logging
from website_generator.prompts import get_prompt, PROMPT_TEMPLATES

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class SimpleWebsiteCreatorAgent:
    """
    Website creator agent that generates all code in one LLM call.
    No tools needed - just generate, parse, and write files.
    """
    
    def __init__(
        self,
        provider: str = "openrouter",
        model_name: Optional[str] = None,
        temperature: float = 0.7,
        api_key: Optional[str] = None,
        run_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None
    ):
        """
        Initialize the Simple Website Creator Agent.
        
        Args:
            provider: LLM provider ('openrouter', 'anthropic', or 'openai')
            model_name: The model to use (defaults based on provider)
            temperature: Temperature for the LLM
            api_key: API key (or set in env vars)
            run_dir: Optional run directory (if None, creates a new one)
            output_dir: Optional output directory for website files
        """
        self.provider = provider.lower()
        self.run_dir = run_dir or setup_run_directory(base_dir="runs/website_generator")
        self.output_dir = output_dir or (self.run_dir / "website")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initializing SimpleWebsiteCreatorAgent")
        logger.info(f"Using provider: {self.provider}")
        logger.info(f"Output directory: {self.output_dir}")
        
        # Set up file logging
        setup_file_logging(self.run_dir)
        
        # Store API key
        if self.provider == "openrouter":
            self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        elif self.provider == "anthropic":
            self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        elif self.provider == "openai":
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        
        # Initialize LLM (no agent, just the LLM)
        self.llm, model_name = initialize_llm(
            provider=self.provider,
            model_name=model_name,
            temperature=temperature,
            api_key=self.api_key
        )
        
        logger.info(f"Initialized LLM: {model_name}")
    
    def _parse_code_blocks(self, text: str) -> Dict[str, str]:
        """
        Parse code blocks from LLM response.
        Looks for markdown code blocks with language tags.
        
        Args:
            text: LLM response text
        
        Returns:
            Dictionary mapping filenames to code content
        """
        files = {}
        
        # Pattern to match code blocks: ```language or ```filename.ext
        # Examples: ```html, ```css, ```javascript, ```index.html
        pattern = r'```(?:html|css|javascript|js|txt|markdown|md)?\s*(?:filename:\s*)?([^\n]*)\n(.*?)```'
        
        matches = re.finditer(pattern, text, re.DOTALL | re.IGNORECASE)
        
        for match in matches:
            filename_hint = match.group(1).strip()
            code_content = match.group(2).strip()
            
            # Determine filename from hint or language
            if filename_hint and '.' in filename_hint:
                # Explicit filename provided
                filename = filename_hint.split()[0]  # Take first word if multiple
            elif 'html' in match.group(0).lower():
                filename = 'index.html'
            elif 'css' in match.group(0).lower():
                filename = 'styles.css'
            elif 'js' in match.group(0).lower() or 'javascript' in match.group(0).lower():
                filename = 'script.js'
            elif 'md' in match.group(0).lower() or 'markdown' in match.group(0).lower():
                filename = 'README.md'
            else:
                # Default based on content
                if '<html' in code_content or '<!DOCTYPE' in code_content:
                    filename = 'index.html'
                elif 'function' in code_content or 'const' in code_content or 'let' in code_content:
                    filename = 'script.js'
                elif '{' in code_content and ':' in code_content and ';' in code_content:
                    filename = 'styles.css'
                else:
                    continue  # Skip if we can't determine
            
            files[filename] = code_content
            logger.debug(f"Parsed code block: {filename} ({len(code_content)} chars)")
        
        # Fallback: if no code blocks found, try to extract HTML/CSS/JS from plain text
        if not files:
            logger.warning("No code blocks found, attempting fallback parsing...")
            # Look for HTML structure
            html_match = re.search(r'(<!DOCTYPE.*?</html>)', text, re.DOTALL | re.IGNORECASE)
            if html_match:
                files['index.html'] = html_match.group(1).strip()
            
            # Look for CSS (between <style> tags or standalone)
            css_match = re.search(r'(<style[^>]*>.*?</style>|(?:\.[^{]+{[^}]+})+.*)', text, re.DOTALL)
            if css_match and '<style' not in css_match.group(1):
                files['styles.css'] = css_match.group(1).strip()
        
        return files
    
    def _write_files(self, files: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Write parsed files to disk.
        
        Args:
            files: Dictionary mapping filenames to content
        
        Returns:
            List of file information dictionaries
        """
        created_files = []
        
        for filename, content in files.items():
            try:
                file_path = self.output_dir / filename
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                file_info = {
                    "name": filename,
                    "path": str(file_path),
                    "size": len(content.encode('utf-8'))
                }
                created_files.append(file_info)
                
                logger.info(f"Created file: {filename} ({file_info['size']} bytes)")
                
            except Exception as e:
                logger.error(f"Error writing file {filename}: {str(e)}")
        
        return created_files
    
    def create_website(
        self,
        prompt: Optional[str] = None,
        template: str = "default",
        custom_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a website by generating all code in one LLM call.
        
        Args:
            prompt: Custom prompt to use (overrides template)
            template: Template name to use
            custom_prompt: Custom prompt (alternative to prompt parameter)
        
        Returns:
            Dictionary with creation results
        """
        logger.info("=" * 60)
        logger.info("Starting website creation (simple mode)")
        logger.info("=" * 60)
        
        # Get the prompt
        if prompt:
            website_prompt = prompt
        elif custom_prompt:
            website_prompt = custom_prompt
        else:
            website_prompt = get_prompt(template_name=template)
        
        # Enhance prompt to request structured output
        enhanced_prompt = f"""{website_prompt}

Please provide all the code in markdown code blocks with appropriate language tags:
- Use ```html or ```index.html for HTML files
- Use ```css or ```styles.css for CSS files  
- Use ```javascript or ```script.js for JavaScript files
- Use ```markdown or ```README.md for documentation

Example format:
```html
<!DOCTYPE html>
...
```

```css
/* styles */
...
```

```javascript
// script
...
```

Generate all necessary files for a complete, functional website."""
        
        logger.info(f"Using template: {template}")
        logger.info(f"Prompt length: {len(enhanced_prompt)} characters")
        
        try:
            # Generate code with LLM
            logger.info("Generating website code with LLM...")
            response = self.llm.invoke([
                SystemMessage(content="You are an expert web developer. Generate complete, functional website code."),
                HumanMessage(content=enhanced_prompt)
            ])
            
            # Extract content from response
            if hasattr(response, 'content'):
                generated_text = response.content
            else:
                generated_text = str(response)
            
            logger.info(f"Generated {len(generated_text)} characters of code")
            
            # Parse code blocks
            logger.info("Parsing code blocks...")
            files = self._parse_code_blocks(generated_text)
            
            if not files:
                logger.warning("No files parsed from LLM response. Saving raw response...")
                # Save raw response as fallback
                files = {"generated_code.txt": generated_text}
            
            # Write files
            logger.info(f"Writing {len(files)} files...")
            created_files = self._write_files(files)
            
            # Save metadata
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "template": template,
                "prompt_preview": website_prompt[:200] + "..." if len(website_prompt) > 200 else website_prompt,
                "output_directory": str(self.output_dir),
                "created_files": [
                    {
                        "name": f["name"],
                        "size": f["size"]
                    } for f in created_files
                ],
                "total_files": len(created_files),
                "status": "success",
                "method": "simple_llm_call"
            }
            
            metadata_path = self.run_dir / "metadata.json"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info("=" * 60)
            logger.info("Website creation completed!")
            logger.info(f"Created {len(created_files)} files")
            logger.info(f"Output: {self.output_dir}")
            logger.info("=" * 60)
            
            return {
                "status": "success",
                "output_directory": str(self.output_dir),
                "created_files": created_files,
                "total_files": len(created_files),
                "metadata_path": str(metadata_path)
            }
            
        except Exception as e:
            error_msg = f"Error creating website: {str(e)}"
            logger.error(error_msg)
            logger.exception(e)
            
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "template": template,
                "status": "error",
                "error": str(e),
                "method": "simple_llm_call"
            }
            
            metadata_path = self.run_dir / "metadata.json"
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            
            return {
                "status": "error",
                "error": error_msg,
                "metadata_path": str(metadata_path)
            }

