#!/bin/bash
# Red Team Agent - Complete Tool Installation Script
# This script installs all SOTA tools required for the red-team agent

# Don't exit on error - we want to continue installing other tools even if one fails
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if tool is installed
tool_installed() {
    command_exists "$1"
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PKG_MANAGER="brew"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            OS="linux"
            PKG_MANAGER="apt"
        elif command_exists yum; then
            OS="linux"
            PKG_MANAGER="yum"
        else
            OS="linux"
            PKG_MANAGER="unknown"
        fi
    else
        OS="unknown"
        PKG_MANAGER="unknown"
    fi
}

# Install system packages (only tools actually used by the agent)
install_system_packages() {
    print_info "Installing system packages (10s timeout per package)..."
    
    if [[ "$PKG_MANAGER" == "brew" ]]; then
        print_info "Using Homebrew (macOS)..."
        # Only install tools that the agent actually checks for
        brew_packages=("nmap" "nikto" "hashcat" "john-jumbo" "hydra" "masscan")
        
        for pkg in "${brew_packages[@]}"; do
            tool_name="${pkg/-jumbo/}"  # Check for 'john' not 'john-jumbo'
            if ! tool_installed "$tool_name"; then
                print_info "Installing $pkg (10s timeout)..."
                (brew install "$pkg" &) && sleep 10 && kill $! 2>/dev/null || print_warning "Failed to install $pkg (timeout or error)"
            else
                print_success "$tool_name is already installed"
            fi
        done
        
    elif [[ "$PKG_MANAGER" == "apt" ]]; then
        print_info "Using apt (Debian/Ubuntu)..."
        print_info "Updating package list..."
        timeout 30 sudo apt-get update || print_warning "Package list update timed out or failed"
        
        # Only tools actually checked by the agent
        apt_packages=("nmap" "masscan" "nikto" "hashcat" "john" "hydra" "metasploit-framework")
        
        for pkg in "${apt_packages[@]}"; do
            if ! tool_installed "$pkg"; then
                print_info "Installing $pkg (10s timeout)..."
                timeout 10 sudo apt-get install -y "$pkg" || print_warning "Failed to install $pkg (timeout or error)"
            else
                print_success "$pkg is already installed"
            fi
        done
        
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        print_info "Using yum (RHEL/CentOS)..."
        # Only tools actually checked by the agent
        yum_packages=("nmap" "nikto" "hashcat" "john" "hydra")
        
        for pkg in "${yum_packages[@]}"; do
            if ! tool_installed "$pkg"; then
                print_info "Installing $pkg (10s timeout)..."
                timeout 10 sudo yum install -y "$pkg" || print_warning "Failed to install $pkg (timeout or error)"
            else
                print_success "$pkg is already installed"
            fi
        done
        
    else
        print_warning "Unknown package manager. Please install system packages manually:"
        print_warning "  - nmap, masscan, nikto, hashcat, john, hydra, metasploit-framework"
    fi
}

# Install Python packages (only tools actually used by the agent)
install_python_packages() {
    print_info "Installing Python packages (10s timeout per package)..."
    
    if [[ -f "requirements.txt" ]]; then
        # Install core dependencies first (no timeout, these are required)
        print_info "Installing core dependencies..."
        pip install langchain langchain-openai langchain-anthropic langchain-community openai python-dotenv requests httpx beautifulsoup4 lxml
        
        # Install only tools that the agent actually checks for
        # Based on grep of _check_tool_available in tools/
        # Format: "package_name:check_name" where check_name is what agent looks for
        python_tools=(
            "sqlmap:sqlmap"
            "xsstrike:xsstrike"
            "arjun:arjun"
            "wapiti3:wapiti"
            "theHarvester:theHarvester"
            "bloodhound:bloodhound-python"
            "crackmapexec:crackmapexec"
            "scoutsuite:scout"
            "rest-attacker:rest_attacker"
        )
        
        for tool_entry in "${python_tools[@]}"; do
            pkg="${tool_entry%%:*}"
            check_name="${tool_entry##*:}"
            
            # Skip if already installed (check by trying to import or check command)
            if [[ "$check_name" == "rest_attacker" ]]; then
                # For Python modules, check import
                python3 -c "import rest_attacker" 2>/dev/null && {
                    print_success "$pkg is already installed"
                    continue
                }
            elif command_exists "$check_name"; then
                print_success "$check_name is already installed"
                continue
            fi
            
            print_info "Installing $pkg (10s timeout)..."
            timeout 10 pip install "$pkg" || print_warning "Failed to install $pkg (timeout or error)"
        done
        
        print_success "Python packages installation attempted"
    else
        print_error "requirements.txt not found!"
        exit 1
    fi
}

# Install Go tools (only tools actually used by the agent)
install_go_tools() {
    if ! command_exists go; then
        print_warning "Go is not installed. Skipping Go-based tools."
        print_warning "Install Go from: https://go.dev/dl/"
        return
    fi
    
    print_info "Installing Go-based tools (10s timeout per tool)..."
    
    # Ensure GOPATH/bin is in PATH
    export PATH="$PATH:$(go env GOPATH)/bin"
    
    # Only tools actually checked by the agent (from grep of _check_tool_available)
    go_tools=(
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest:nuclei"
        "github.com/hahwul/dalfox/v2@latest:dalfox"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest:subfinder"
        "github.com/owasp-amass/amass/v4/...@master:amass"
        "github.com/OJ/gobuster/v3@latest:gobuster"
        "github.com/ffuf/ffuf/v2@latest:ffuf"
    )
    
    for tool_entry in "${go_tools[@]}"; do
        tool_repo="${tool_entry%%:*}"
        tool_name="${tool_entry##*:}"
        if ! tool_installed "$tool_name"; then
            print_info "Installing $tool_name (10s timeout)..."
            timeout 10 go install -v "$tool_repo" || print_warning "Failed to install $tool_name (timeout or error)"
        else
            print_success "$tool_name is already installed"
        fi
    done
    
    print_info "Go tools installation attempted. Make sure $(go env GOPATH)/bin is in your PATH"
}

# Install Rust tools (only tools actually used by the agent)
install_rust_tools() {
    if ! command_exists cargo; then
        print_warning "Rust/Cargo is not installed. Skipping Rust-based tools."
        print_warning "Install Rust from: https://rustup.rs/"
        return
    fi
    
    print_info "Installing Rust-based tools (10s timeout)..."
    
    # Only rustscan is actually checked by the agent
    if ! tool_installed "rustscan"; then
        print_info "Installing rustscan (10s timeout)..."
        timeout 10 cargo install rustscan || print_warning "Failed to install rustscan (timeout or error - Rust installs can take longer)"
    else
        print_success "rustscan is already installed"
    fi
}

# Verify installations
verify_installations() {
    print_info "Verifying installations..."
    
    # Only tools actually checked by the agent (verified from codebase)
    python_tools=("sqlmap" "xsstrike" "arjun" "wapiti" "theHarvester" "bloodhound-python" "crackmapexec" "scout" "rest-attacker")
    
    # Go tools (only those checked by agent)
    go_tools=("nuclei" "dalfox" "subfinder" "amass" "gobuster" "ffuf")
    
    # System tools (only those checked by agent)
    system_tools=("nmap" "masscan" "nikto" "hashcat" "john" "hydra" "msfconsole")
    
    # Rust tools (only those checked by agent)
    rust_tools=("rustscan")
    
    all_tools=("${python_tools[@]}" "${go_tools[@]}" "${system_tools[@]}" "${rust_tools[@]}")
    
    installed=0
    missing=0
    
    for tool in "${all_tools[@]}"; do
        if tool_installed "$tool"; then
            print_success "✓ $tool"
            ((installed++))
        else
            print_warning "✗ $tool (not found)"
            ((missing++))
        fi
    done
    
    echo ""
    print_info "Installation Summary:"
    print_success "$installed tools installed"
    if [[ $missing -gt 0 ]]; then
        print_warning "$missing tools missing (may need manual installation or PATH configuration)"
    fi
}

# Main installation flow
main() {
    echo "=========================================="
    echo "Red Team Agent - Tool Installation Script"
    echo "=========================================="
    echo ""
    
    detect_os
    print_info "Detected OS: $OS"
    print_info "Package Manager: $PKG_MANAGER"
    echo ""
    
    # Step 1: Install Python packages
    print_info "Step 1/4: Installing Python packages..."
    install_python_packages
    echo ""
    
    # Step 2: Install system packages
    print_info "Step 2/4: Installing system packages..."
    install_system_packages
    echo ""
    
    # Step 3: Install Go tools
    print_info "Step 3/4: Installing Go-based tools..."
    install_go_tools
    echo ""
    
    # Step 4: Install Rust tools
    print_info "Step 4/4: Installing Rust-based tools..."
    install_rust_tools
    echo ""
    
    # Verify
    verify_installations
    
    echo ""
    print_success "Installation complete!"
    print_info "Note: Some tools may require additional setup or PATH configuration."
    print_info "Check the README.md for detailed installation instructions."
}

# Run main function
main

