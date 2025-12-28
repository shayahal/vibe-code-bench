#!/bin/bash
# Installation script for red team security tools
# This script installs wapiti3, nikto, and optionally nuclei

set -e

echo "🔧 Installing Red Team Security Tools..."
echo ""

# Check if running on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📦 Detected macOS - using Homebrew for system packages"
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew is not installed. Please install it first:"
        echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    
    # Install nikto via Homebrew
    echo "📥 Installing nikto..."
    if command -v nikto &> /dev/null; then
        echo "✅ nikto is already installed"
    else
        brew install nikto
        echo "✅ nikto installed successfully"
    fi
    
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "📦 Detected Linux - using apt-get for system packages"
    
    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then 
        echo "⚠️  Note: Some installations may require sudo privileges"
    fi
    
    # Install nikto via apt-get
    echo "📥 Installing nikto..."
    if command -v nikto &> /dev/null; then
        echo "✅ nikto is already installed"
    else
        sudo apt-get update
        sudo apt-get install -y nikto
        echo "✅ nikto installed successfully"
    fi
else
    echo "⚠️  Unsupported OS: $OSTYPE"
    echo "   Please install nikto manually for your system"
fi

# Install wapiti3 via pip (works on both macOS and Linux)
echo ""
echo "📥 Installing wapiti3..."
if command -v wapiti &> /dev/null; then
    echo "✅ wapiti3 is already installed (command: wapiti)"
else
    pip install wapiti3
    echo "✅ wapiti3 installed successfully"
fi

# Optional: Install nuclei (requires Go)
echo ""
echo "📥 Installing nuclei (optional, requires Go)..."
if command -v nuclei &> /dev/null; then
    echo "✅ nuclei is already installed"
elif command -v go &> /dev/null; then
    echo "   Installing nuclei via Go..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    
    # Check if Go bin is in PATH
    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo ""
        echo "⚠️  WARNING: Go bin directory may not be in your PATH"
        echo "   Add this to your ~/.zshrc or ~/.bashrc:"
        echo "   export PATH=\$PATH:\$HOME/go/bin"
        echo ""
        echo "   Or run: export PATH=\$PATH:\$HOME/go/bin"
    fi
    
    # Verify installation
    if command -v nuclei &> /dev/null || [ -f "$HOME/go/bin/nuclei" ]; then
        echo "✅ nuclei installed successfully"
    else
        echo "⚠️  nuclei installation may have succeeded but is not in PATH"
        echo "   Try: export PATH=\$PATH:\$HOME/go/bin"
    fi
else
    echo "⚠️  Go is not installed. Skipping nuclei installation."
    echo "   To install Go:"
    echo "   - macOS: brew install go"
    echo "   - Linux: sudo apt-get install golang-go"
    echo "   Then run this script again or manually install nuclei"
fi

# Optional: Install dalfox (requires Go)
echo ""
echo "📥 Installing dalfox (optional, requires Go)..."
if command -v dalfox &> /dev/null; then
    echo "✅ dalfox is already installed"
elif command -v go &> /dev/null; then
    echo "   Installing dalfox via Go..."
    go install github.com/hahwul/dalfox/v2@latest
    
    # Verify installation
    if command -v dalfox &> /dev/null || [ -f "$HOME/go/bin/dalfox" ]; then
        echo "✅ dalfox installed successfully"
    else
        echo "⚠️  dalfox installation may have succeeded but is not in PATH"
        echo "   Try: export PATH=\$PATH:\$HOME/go/bin"
    fi
else
    echo "⚠️  Go is not installed. Skipping dalfox installation."
fi

# Optional: Install sqlmap
echo ""
echo "📥 Installing sqlmap (optional)..."
if command -v sqlmap &> /dev/null; then
    echo "✅ sqlmap is already installed"
else
    pip install sqlmap
    echo "✅ sqlmap installed successfully"
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Installed tools status:"
echo ""

# Check and display status
tools=("nikto" "wapiti" "nuclei" "dalfox" "sqlmap")
for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "  ✅ $tool: installed ($(which $tool))"
    else
        echo "  ❌ $tool: not found in PATH"
    fi
done

echo ""
echo "💡 Note: If any Go-based tools (nuclei, dalfox) show as not found,"
echo "   make sure \$HOME/go/bin is in your PATH:"
echo "   export PATH=\$PATH:\$HOME/go/bin"
echo ""
echo "   Add this to your ~/.zshrc or ~/.bashrc to make it permanent."
