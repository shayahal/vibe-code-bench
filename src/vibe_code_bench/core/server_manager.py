"""
Server Management Module

Manages Flask server lifecycle for generated websites.
"""

import os
import sys
import time
import subprocess
import socket
from pathlib import Path
from typing import Optional
import requests

from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


class WebsiteServer:
    """Manages a Flask server for the generated website."""
    
    def __init__(self, website_dir: Path, port: int = 5000):
        """
        Initialize website server.
        
        Args:
            website_dir: Directory containing website files (including main.py)
            port: Port to run server on (will try next port if in use)
        """
        self.website_dir = Path(website_dir)
        self.port = port
        self.process: Optional[subprocess.Popen] = None
        self.url = f"http://localhost:{port}"
    
    @staticmethod
    def is_port_available(port: int) -> bool:
        """
        Check if a port is available.
        
        Args:
            port: Port number to check
            
        Returns:
            True if port is available, False otherwise
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                return True
            except OSError:
                return False
    
    def find_available_port(self, start_port: int = None, max_attempts: int = 100) -> int:
        """
        Find an available port starting from the given port.
        
        Args:
            start_port: Starting port number (defaults to self.port)
            max_attempts: Maximum number of ports to try
            
        Returns:
            Available port number
            
        Raises:
            RuntimeError: If no available port found
        """
        if start_port is None:
            start_port = self.port
        
        for i in range(max_attempts):
            port = start_port + i
            if self.is_port_available(port):
                return port
        
        raise RuntimeError(f"Could not find an available port starting from {start_port}")
    
    def start(self, timeout: int = 60) -> bool:
        """
        Start the Flask server.
        
        If the requested port is in use, automatically tries the next available port.
        
        Args:
            timeout: Maximum time to wait for server to start
            
        Returns:
            True if server started successfully
        """
        main_py = self.website_dir / "main.py"
        if not main_py.exists():
            logger.error(f"main.py not found in {self.website_dir}")
            return False
        
        # Check if requested port is available, find next available if not
        original_port = self.port
        if not self.is_port_available(self.port):
            logger.info(f"Port {self.port} is in use, finding next available port...")
            try:
                self.port = self.find_available_port()
                self.url = f"http://localhost:{self.port}"
                logger.info(f"Using port {self.port} instead of {original_port}")
            except RuntimeError as e:
                logger.error(f"Could not find an available port: {e}")
                return False
        
        # Change to website directory and start Flask
        env = os.environ.copy()
        env['FLASK_APP'] = 'main.py'
        env['FLASK_ENV'] = 'development'
        env['FLASK_PORT'] = str(self.port)  # Pass port to Flask app
        
        try:
            # Use relative path since we're setting cwd
            self.process = subprocess.Popen(
                [sys.executable, "main.py"],
                cwd=str(self.website_dir),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Give Flask a brief moment to initialize
            time.sleep(0.5)
            
            # Wait for server to start with faster polling
            poll_interval = 0.2  # Check every 200ms for faster startup detection
            max_iterations = int(timeout / poll_interval)
            
            for i in range(max_iterations):
                # Check if process is still running
                if self.process.poll() is not None:
                    # Process exited - read error
                    stdout, stderr = self.process.communicate()
                    error_output = (stderr or stdout or b"").decode('utf-8', errors='ignore')
                    if error_output:
                        logger.error(f"Server process exited. Error output:\n{error_output[:500]}")
                        # Check if it's a port binding error and try next port
                        if "Address already in use" in error_output or "port" in error_output.lower():
                            logger.info(f"Port {self.port} binding failed, trying next port...")
                            try:
                                self.port = self.find_available_port(start_port=self.port + 1)
                                self.url = f"http://localhost:{self.port}"
                                logger.info(f"Retrying with port {self.port}")
                                # Retry starting the server
                                return self.start(timeout=timeout)
                            except RuntimeError:
                                return False
                    return False
                
                try:
                    response = requests.get(self.url, timeout=1)
                    # Accept 200 (OK) or 403 (Forbidden - server is running but may have access issues)
                    # The important thing is that the server responded
                    if response.status_code in [200, 403]:
                        logger.info(f"Website server started on {self.url}")
                        return True
                except requests.exceptions.RequestException:
                    pass
                
                # Print progress every 5 seconds
                elapsed = i * poll_interval
                if elapsed > 0 and elapsed % 5 < poll_interval:
                    logger.info(f"Waiting for server... ({elapsed:.1f}/{timeout}s)")
                
                time.sleep(poll_interval)
            
            logger.warning(f"Server did not start within {timeout} seconds")
            # Try to get error output
            if self.process.poll() is None:
                # Process still running but not responding - might be stuck
                logger.warning("Server process is running but not responding to requests")
            return False
            
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            return False
    
    def stop(self):
        """Stop the Flask server."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                logger.info("Website server stopped")
            except subprocess.TimeoutExpired:
                self.process.kill()
                logger.info("Website server force stopped")
            except Exception as e:
                logger.error(f"Error stopping server: {e}")
    
    def is_running(self) -> bool:
        """Check if server is running."""
        try:
            response = requests.get(self.url, timeout=1)
            return response.status_code == 200
        except:
            return False

