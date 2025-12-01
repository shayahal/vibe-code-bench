#!/usr/bin/env python3
"""
Red Team Agent - Cross-Platform Tool Installation Script

This script installs all SOTA tools required for the red-team agent.
Supports macOS, Linux, and provides guidance for Windows.
"""

import os
import sys
import subprocess
import shutil
import platform
from pathlib import Path

# Colors for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

def print_info(msg):
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")

def print_success(msg):
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {msg}")

def print_error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")

def command_exists(cmd):
    """Check if a command exists in PATH."""
    return shutil.which(cmd) is not None

def run_command(cmd, check=True, shell=False):
    """Run a shell command."""
    try:
        if isinstance(cmd, str):
            cmd = cmd.split()
        result = subprocess.run(
            cmd,
            check=check,
            shell=shell,
            capture_output=True,
            text=True
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr
    except FileNotFoundError:
        return False, "", "Command not found"

def detect_platform():
    """Detect the operating system and package manager."""
    system = platform.system().lower()
    
    if system == "darwin":
        return "macos", "brew"
    elif system == "linux":
        if command_exists("apt-get"):
            return "linux", "apt"
        elif command_exists("yum"):
            return "linux", "yum"
        elif command_exists("pacman"):
            return "linux", "pacman"
        else:
            return "linux", "unknown"
    elif system == "windows":
        return "windows", "choco"  # Chocolatey, but may not be installed
    else:
        return "unknown", "unknown"

def install_python_packages():
    """Install Python packages from requirements.txt."""
    print_info("Installing Python packages from requirements.txt...")
    
    req_file = Path("requirements.txt")
    if not req_file.exists():
        print_error("requirements.txt not found!")
        return False
    
    success, stdout, stderr = run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    if success:
        print_success("Python packages installed successfully")
        return True
    else:
        print_error(f"Failed to install Python packages: {stderr}")
        return False

def install_system_packages(os_type, pkg_manager):
    """Install system packages based on OS and package manager."""
    print_info(f"Installing system packages using {pkg_manager}...")
    
    if os_type == "macos" and pkg_manager == "brew":
        packages = ["nmap", "nikto", "masscan", "hashcat", "john-jumbo", "hydra"]
        for pkg in packages:
            if command_exists(pkg.replace("-jumbo", "")):
                print_success(f"{pkg} is already installed")
            else:
                print_info(f"Installing {pkg}...")
                success, _, _ = run_command(["brew", "install", pkg])
                if not success:
                    print_warning(f"Failed to install {pkg} (may need manual installation)")
    
    elif os_type == "linux" and pkg_manager == "apt":
        print_info("Updating package list...")
        run_command(["sudo", "apt-get", "update"], check=False)
        
        packages = ["nmap", "masscan", "nikto", "hashcat", "john", "hydra", "metasploit-framework"]
        for pkg in packages:
            if command_exists(pkg):
                print_success(f"{pkg} is already installed")
            else:
                print_info(f"Installing {pkg}...")
                success, _, _ = run_command(["sudo", "apt-get", "install", "-y", pkg])
                if not success:
                    print_warning(f"Failed to install {pkg}")
    
    elif os_type == "linux" and pkg_manager == "yum":
        packages = ["nmap", "nikto", "hashcat", "john", "hydra"]
        for pkg in packages:
            if command_exists(pkg):
                print_success(f"{pkg} is already installed")
            else:
                print_info(f"Installing {pkg}...")
                success, _, _ = run_command(["sudo", "yum", "install", "-y", pkg])
                if not success:
                    print_warning(f"Failed to install {pkg}")
    
    elif os_type == "windows":
        print_warning("Windows detected. System packages need manual installation:")
        print_warning("  - Install Chocolatey: https://chocolatey.org/")
        print_warning("  - Then: choco install nmap nikto")
        print_warning("  - Or install tools manually from their websites")
    
    else:
        print_warning(f"Unknown package manager: {pkg_manager}")
        print_warning("Please install system packages manually:")
        print_warning("  - nmap, masscan, nikto, hashcat, john, hydra, metasploit-framework")

def install_go_tools():
    """Install Go-based tools."""
    if not command_exists("go"):
        print_warning("Go is not installed. Skipping Go-based tools.")
        print_warning("Install Go from: https://go.dev/dl/")
        return
    
    print_info("Installing Go-based tools...")
    
    # Ensure GOPATH/bin is in PATH
    go_path = os.path.expanduser("~/go/bin")
    if go_path not in os.environ.get("PATH", ""):
        print_warning(f"Add {go_path} to your PATH for Go tools to work")
    
    go_tools = [
        ("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "nuclei"),
        ("github.com/hahwul/dalfox/v2@latest", "dalfox"),
        ("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "subfinder"),
        ("github.com/owasp-amass/amass/v4/...@master", "amass"),
        ("github.com/OJ/gobuster/v3@latest", "gobuster"),
        ("github.com/ffuf/ffuf/v2@latest", "ffuf"),
    ]
    
    for repo, tool_name in go_tools:
        if command_exists(tool_name):
            print_success(f"{tool_name} is already installed")
        else:
            print_info(f"Installing {tool_name}...")
            success, _, stderr = run_command(["go", "install", "-v", repo])
            if success:
                print_success(f"{tool_name} installed")
            else:
                print_warning(f"Failed to install {tool_name}: {stderr}")

def install_rust_tools():
    """Install Rust-based tools."""
    if not command_exists("cargo"):
        print_warning("Rust/Cargo is not installed. Skipping Rust-based tools.")
        print_warning("Install Rust from: https://rustup.rs/")
        return
    
    print_info("Installing Rust-based tools...")
    
    if command_exists("rustscan"):
        print_success("rustscan is already installed")
    else:
        print_info("Installing rustscan...")
        success, _, stderr = run_command(["cargo", "install", "rustscan"])
        if success:
            print_success("rustscan installed")
        else:
            print_warning(f"Failed to install rustscan: {stderr}")

def verify_installations():
    """Verify that tools are installed."""
    print_info("Verifying installations...")
    print("")
    
    # Define all tools
    python_tools = ["sqlmap", "xsstrike", "paramspider", "arjun", "wfuzz", "wapiti", 
                    "theHarvester", "bloodhound-python", "crackmapexec", "scout", "rest-attacker"]
    go_tools = ["nuclei", "dalfox", "subfinder", "amass", "gobuster", "ffuf"]
    system_tools = ["nmap", "nikto", "hashcat", "john", "hydra"]
    rust_tools = ["rustscan"]
    
    all_tools = {
        "Python Tools": python_tools,
        "Go Tools": go_tools,
        "System Tools": system_tools,
        "Rust Tools": rust_tools,
    }
    
    installed_count = 0
    missing_count = 0
    
    for category, tools in all_tools.items():
        print(f"{category}:")
        for tool in tools:
            if command_exists(tool):
                print_success(f"  ✓ {tool}")
                installed_count += 1
            else:
                print_warning(f"  ✗ {tool} (not found)")
                missing_count += 1
        print("")
    
    print_info("Installation Summary:")
    print_success(f"{installed_count} tools installed")
    if missing_count > 0:
        print_warning(f"{missing_count} tools missing")
        print_info("Missing tools may need:")
        print_info("  - Manual installation")
        print_info("  - PATH configuration")
        print_info("  - Additional dependencies")

def main():
    """Main installation flow."""
    print("=" * 50)
    print("Red Team Agent - Tool Installation Script")
    print("=" * 50)
    print("")
    
    os_type, pkg_manager = detect_platform()
    print_info(f"Detected OS: {os_type}")
    print_info(f"Package Manager: {pkg_manager}")
    print("")
    
    # Step 1: Python packages
    print_info("Step 1/4: Installing Python packages...")
    install_python_packages()
    print("")
    
    # Step 2: System packages
    print_info("Step 2/4: Installing system packages...")
    install_system_packages(os_type, pkg_manager)
    print("")
    
    # Step 3: Go tools
    print_info("Step 3/4: Installing Go-based tools...")
    install_go_tools()
    print("")
    
    # Step 4: Rust tools
    print_info("Step 4/4: Installing Rust-based tools...")
    install_rust_tools()
    print("")
    
    # Verify
    verify_installations()
    
    print("")
    print_success("Installation complete!")
    print_info("Note: Some tools may require additional setup or PATH configuration.")
    print_info("Check the README.md for detailed installation instructions.")

if __name__ == "__main__":
    main()

