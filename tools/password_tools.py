"""
Password & Credential Testing Tools

This module contains integrations for password cracking and credential testing tools.

Tool Selection Rationale:
- Hashcat: Fastest password recovery tool. GPU-accelerated with extensive hash support.
- John the Ripper: Versatile password cracker with multiple cracking modes.
- Hydra: Network login cracker supporting 50+ protocols. Excellent for brute-force testing.
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from .tool_factory import RedTeamToolFactory

logger = logging.getLogger(__name__)


def register_password_tools(factory: RedTeamToolFactory) -> Dict[str, Callable]:
    """
    Register password & credential testing tools with the factory.
    
    Args:
        factory: RedTeamToolFactory instance
        
    Returns:
        Dictionary mapping tool names to functions
    """
    tools = {}
    
    def create_crack_password_hashcat():
        """
        Create crack_password_hashcat tool.
        
        Why Hashcat: Fastest password recovery tool with GPU acceleration.
        Supports 300+ hash types and advanced attack modes.
        """
        def crack_password_hashcat(hash_file: str, wordlist: Optional[str] = None, hash_type: str = "0") -> Dict[str, Any]:
            """Crack password hashes with Hashcat."""
            logger.info(f"Cracking passwords with Hashcat: {hash_file}")
            if not factory._check_tool_available("hashcat"):
                logger.warning("Hashcat not found. Install: apt install hashcat or brew install hashcat")
                return {"error": "Hashcat not installed", "hash_file": hash_file}
            
            try:
                cmd = ["hashcat", "-m", hash_type, hash_file]
                if wordlist:
                    cmd.append(wordlist)
                else:
                    cmd.append("/usr/share/wordlists/rockyou.txt")
                cmd.extend(["-o", "/tmp/hashcat_output.txt"])
                
                result = factory._run_command(cmd, timeout=20)
                
                cracked = []
                if os.path.exists("/tmp/hashcat_output.txt"):
                    with open("/tmp/hashcat_output.txt", 'r') as f:
                        cracked = [line.strip() for line in f if line.strip()]
                
                return {
                    "hash_file": hash_file,
                    "tool": "hashcat",
                    "hash_type": hash_type,
                    "cracked_count": len(cracked),
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Hashcat: {str(e)}")
                return {"error": str(e), "hash_file": hash_file}
        
        return crack_password_hashcat
    
    def create_crack_password_john():
        """
        Create crack_password_john tool.
        
        Why John the Ripper: Versatile password cracker with multiple cracking modes.
        Excellent for various hash types and attack strategies.
        """
        def crack_password_john(hash_file: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
            """Crack password hashes with John the Ripper."""
            logger.info(f"Cracking passwords with John: {hash_file}")
            if not factory._check_tool_available("john"):
                logger.warning("John the Ripper not found. Install: apt install john or brew install john-jumbo")
                return {"error": "John the Ripper not installed", "hash_file": hash_file}
            
            try:
                cmd = ["john", hash_file]
                if wordlist:
                    cmd.extend(["--wordlist", wordlist])
                else:
                    cmd.extend(["--wordlist", "/usr/share/wordlists/rockyou.txt"])
                
                result = factory._run_command(cmd, timeout=20)
                
                # Show cracked passwords
                show_cmd = ["john", "--show", hash_file]
                show_result = factory._run_command(show_cmd, timeout=20)
                
                return {
                    "hash_file": hash_file,
                    "tool": "john",
                    "output": show_result.stdout,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running John: {str(e)}")
                return {"error": str(e), "hash_file": hash_file}
        
        return crack_password_john
    
    def create_brute_force_login_hydra():
        """
        Create brute_force_login_hydra tool.
        
        Why Hydra: Network login cracker supporting 50+ protocols.
        Excellent for brute-force testing of authentication mechanisms.
        """
        def brute_force_login_hydra(
            target: str,
            service: str,
            username: str,
            password_list: Optional[str] = None
        ) -> Dict[str, Any]:
            """Brute force login with Hydra."""
            logger.info(f"Brute forcing login with Hydra: {target} ({service})")
            if not factory._check_tool_available("hydra"):
                logger.warning("Hydra not found. Install: apt install hydra or brew install hydra")
                return {"error": "Hydra not installed", "target": target}
            
            try:
                cmd = ["hydra", "-l", username, "-P"]
                if password_list:
                    cmd.append(password_list)
                else:
                    cmd.append("/usr/share/wordlists/rockyou.txt")
                cmd.extend([target, service])
                
                result = factory._run_command(cmd, timeout=20)
                
                found = "password:" in result.stdout.lower() or "login:" in result.stdout.lower()
                
                return {
                    "target": target,
                    "tool": "hydra",
                    "service": service,
                    "username": username,
                    "found": found,
                    "output": result.stdout[:500],
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error running Hydra: {str(e)}")
                return {"error": str(e), "target": target}
        
        return brute_force_login_hydra
    
    # Register password tools
    tools['crack_password_hashcat'] = create_crack_password_hashcat()
    tools['crack_password_john'] = create_crack_password_john()
    tools['brute_force_login_hydra'] = create_brute_force_login_hydra()
    
    return tools


# Export tool names for this category
__all__ = [
    'register_password_tools',
    'crack_password_hashcat',
    'crack_password_john',
    'brute_force_login_hydra',
]

