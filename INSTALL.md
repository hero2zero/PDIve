# PDIve Installation Guide

## System Requirements

- **Operating System**: Linux (Ubuntu/Debian recommended), macOS, or Windows with WSL2
- **Python**: Version 3.6 or higher
- **Memory**: Minimum 512MB RAM, 2GB+ recommended for large scans
- **Network**: Internet access for passive discovery, local network access for active scanning
- **Privileges**: Regular user account (sudo access required for masscan in active mode)

## Prerequisites

### Core Dependencies

#### 1. Python 3.6+
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv

# CentOS/RHEL/Fedora
sudo yum install python3 python3-pip python3-venv
# OR (newer versions)
sudo dnf install python3 python3-pip python3-venv

# macOS (with Homebrew)
brew install python3

# Verify installation
python3 --version
pip3 --version
```

#### 2. Git (for cloning repository)
```bash
# Ubuntu/Debian
sudo apt install git

# CentOS/RHEL/Fedora
sudo yum install git
# OR
sudo dnf install git

# macOS
git --version  # Should prompt to install Xcode command line tools

# Verify installation
git --version
```

### External Security Tools

#### 1. OWASP Amass (Required for both modes)

**Method 1: Package Manager (Recommended)**
```bash
# Ubuntu/Debian
sudo apt install amass

# Verify installation
amass --version
```

**Method 2: Manual Installation**
```bash
# Download latest release
wget https://github.com/OWASP/Amass/releases/latest/download/amass_linux_amd64.zip
unzip amass_linux_amd64.zip
sudo cp amass_linux_amd64/amass /usr/local/bin/
chmod +x /usr/local/bin/amass

# Verify installation
amass --version
```

**Method 3: Go Installation**
```bash
# Install Go first if not available
sudo apt install golang-go

# Install amass via go
go install -v github.com/OWASP/Amass/v4/...@master

# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

# Verify installation
amass --version
```

#### 2. Masscan (Required for active mode)

**Method 1: Package Manager**
```bash
# Ubuntu/Debian
sudo apt install masscan

# CentOS/RHEL (Enable EPEL first)
sudo yum install epel-release
sudo yum install masscan

# Verify installation
masscan --version
```

**Method 2: Manual Compilation**
```bash
# Install build dependencies
sudo apt install build-essential libpcap-dev

# Clone and build
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install

# Verify installation
masscan --version
```

#### 3. Nmap and Python-Nmap Module (Optional for enhanced service detection)

```bash
# Ubuntu/Debian/Kali - Install both nmap binary and python module
sudo apt install nmap python3-nmap

# CentOS/RHEL/Fedora
sudo yum install nmap python3-nmap
# OR
sudo dnf install nmap python3-nmap

# macOS
brew install nmap
pip3 install python-nmap

# Verify installation
nmap --version
python3 -c "import nmap; print('python-nmap module available')"
```

## Installation Methods

### Method 1: Quick Installation (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/PDIve.git
cd PDIve

# 2. Install system dependencies (Ubuntu/Debian/Kali)
sudo apt update
sudo apt install python3 python3-pip python3-venv amass masscan nmap python3-nmap

# 3. Create and activate virtual environment
python3 -m venv recon_env
source recon_env/bin/activate

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Test installation
python3 pdive.py --version
```

### Method 2: Manual Step-by-Step Installation

#### Step 1: System Preparation
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install base requirements
sudo apt install -y python3 python3-pip python3-venv git curl wget unzip
```

#### Step 2: Install Security Tools
```bash
# Install all security tools at once (including python3-nmap module)
sudo apt install -y amass masscan nmap python3-nmap

# OR install individually with verification
sudo apt install amass
amass --version

sudo apt install masscan
masscan --version

sudo apt install nmap python3-nmap
nmap --version
python3 -c "import nmap; print('python-nmap OK')"
```

#### Step 3: Download PDIve
```bash
# Option A: Clone from repository
git clone https://github.com/yourusername/PDIve.git
cd PDIve

# Option B: Download archive
wget https://github.com/yourusername/PDIve/archive/main.zip
unzip main.zip
cd PDIve-main
```

#### Step 4: Python Environment Setup
```bash
# Create isolated virtual environment
python3 -m venv recon_env

# Activate virtual environment
source recon_env/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install PDIve dependencies
pip install -r requirements.txt
```

#### Step 5: Verify Installation
```bash
# Check PDIve version
python3 pdive.py --version

# Test basic functionality
python3 pdive.py --help

# Quick test scan (requires confirmation)
# Note: Ping is disabled by default for stealth
echo "y" | python3 pdive.py -t 127.0.0.1 -T 5
```

### Method 3: Docker Installation (Alternative)

```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    amass \
    masscan \
    nmap \
    python3-nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app/

RUN python3 -m pip install -r requirements.txt

ENTRYPOINT ["python3", "pdive.py"]
EOF

# Build Docker image
docker build -t pdive:1.3 .

# Run PDIve in container
docker run -it --rm pdive:1.3 --help
```

## Post-Installation Configuration

### 1. Masscan Sudo Configuration

PDIve v1.3 requires sudo privileges for masscan. Choose one option:

**Option A: Run PDIve with sudo (Simplest)**
```bash
sudo python3 pdive.py -t target.com
```

**Option B: Configure passwordless sudo for masscan**
```bash
# Edit sudoers file (CAREFUL!)
sudo visudo

# Add this line (replace 'username' with your username):
username ALL=(ALL) NOPASSWD: /usr/bin/masscan

# Test configuration
sudo -n masscan --help
# Should run without password prompt
```

**Option C: Run without masscan (Automatic fallback)**
- PDIve will automatically detect sudo issues
- Falls back to built-in port scanner
- No configuration needed

### 2. Amass Configuration (Optional)

Create amass configuration for enhanced results:
```bash
# Create amass config directory
mkdir -p ~/.config/amass

# Create basic configuration
cat > ~/.config/amass/config.ini << 'EOF'
# https://github.com/OWASP/Amass/blob/master/examples/config.ini

[scope]
# domains = example1.com,example2.com

[graphdbs]
# Neo4j configuration (optional)
# [graphdbs.neo4j]
# url = "bolt://localhost:7687"
# username = ""
# password = ""

[data_sources]
# Enable/disable specific data sources
# [data_sources.AlienVault]
# apikey = ""

# [data_sources.Shodan]
# apikey = ""
EOF

# Test amass configuration
amass enum -d example.com -passive -v
```

### 3. Virtual Environment Activation Script

Create a convenient activation script:
```bash
# Create activation script
cat > activate_pdive.sh << 'EOF'
#!/bin/bash
echo "Activating PDIve environment..."
cd /path/to/PDIve
source recon_env/bin/activate
echo "PDIve v1.3 ready!"
echo "Usage: python3 pdive.py [options]"
EOF

chmod +x activate_pdive.sh

# Use the script
./activate_pdive.sh
```

## Verification and Testing

### 1. Component Verification
```bash
# Test all components
echo "Testing PDIve components..."

# Python environment
python3 --version
pip list | grep -E "(requests|colorama|urllib3|python-nmap)"
python3 -c "import nmap; print('python-nmap module: OK')"

# Security tools
echo "Amass version:"
amass --version

echo "Masscan version:"
masscan --version

echo "Nmap version:"
nmap --version

echo "PDIve version:"
python3 pdive.py --version
```

### 2. Functionality Tests
```bash
# Test passive mode (safe)
echo "y" | python3 pdive.py -t example.com -m passive -T 5

# Test active mode with localhost (safe, no ping by default)
echo "y" | python3 pdive.py -t 127.0.0.1 -T 5

# Test fast masscan-only mode (no service enumeration)
echo "y" | python3 pdive.py -t 127.0.0.1 -T 5 --masscan

# Test active mode with ping enabled
echo "y" | python3 pdive.py -t 127.0.0.1 -T 5 --ping

# Test sudo detection
python3 pdive.py --help | grep -A 5 "masscan"
```

### 3. Permission Tests
```bash
# Test masscan sudo access
sudo -n masscan --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Masscan sudo access configured"
else
    echo "⚠ Masscan will require sudo prompt or fallback to basic scan"
fi

# Test file permissions
touch test_output_dir/test_file.txt 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✓ Output directory writable"
    rm -f test_output_dir/test_file.txt
else
    echo "⚠ Check output directory permissions"
fi
```

## Troubleshooting Installation Issues

### Python Environment Issues
```bash
# "externally-managed-environment" error
# Solution 1: Use virtual environment (recommended)
python3 -m venv recon_env
source recon_env/bin/activate
pip install -r requirements.txt

# Solution 2: Use system package manager for python-nmap
sudo apt install python3-nmap
pip install --user requests colorama urllib3

# Permission denied for pip install
# Solution: Use --user flag or virtual environment
pip install --user -r requirements.txt
```

### Python-Nmap Module Issues
```bash
# Issue: "Note: nmap module not available, nmap scanning disabled"
# Solution: Install python3-nmap system package (Debian/Ubuntu/Kali)
sudo apt install python3-nmap

# Verify installation
python3 -c "import nmap; print('nmap module available')"

# For non-Debian systems or virtual environments
pip install python-nmap

# Note: The system package is named 'python3-nmap' but imports as 'nmap'
```

### Missing System Packages
```bash
# Amass not found
sudo apt update
sudo apt install amass
# OR download from GitHub releases

# Masscan not found
sudo apt install masscan
# OR compile from source

# Build tools missing (for compilation)
sudo apt install build-essential libpcap-dev
```

### Network and Firewall Issues
```bash
# Outbound connections blocked
# Check proxy settings
export https_proxy=http://proxy:port
export http_proxy=http://proxy:port

# Test connectivity
curl -I https://github.com
curl -I https://crt.sh

# DNS resolution issues
nslookup example.com
dig example.com
```

### Permission and Sudo Issues
```bash
# Cannot run as root warning
# Solution: Run as regular user, only use sudo for masscan

# Sudo timeout/password issues
# Solution: Configure passwordless sudo or run entire script with sudo

# File permission errors
# Solution: Check output directory permissions
chmod 755 output_directory
```

## Advanced Installation Options

### 1. Automated Installation Script
```bash
#!/bin/bash
# pdive_install.sh - Automated PDIve installation

set -e

echo "Starting PDIve v1.3 installation..."

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
else
    echo "Unsupported OS. Manual installation required."
    exit 1
fi

# Install system packages
if [ "$OS" = "debian" ]; then
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv git amass masscan nmap python3-nmap
elif [ "$OS" = "redhat" ]; then
    sudo yum install -y python3 python3-pip git epel-release
    sudo yum install -y amass masscan nmap python3-nmap
fi

# Clone repository
git clone https://github.com/yourusername/PDIve.git
cd PDIve

# Setup Python environment
python3 -m venv recon_env
source recon_env/bin/activate
pip install -r requirements.txt

# Test installation
python3 pdive.py --version

echo "PDIve v1.3 installation complete!"
echo "Activate with: source recon_env/bin/activate"
echo "Run with: python3 pdive.py [options]"
```

### 2. System-wide Installation
```bash
# Install PDIve system-wide (not recommended for most users)
sudo cp pdive.py /usr/local/bin/
sudo chmod +x /usr/local/bin/pdive.py

# Create symlink
sudo ln -s /usr/local/bin/pdive.py /usr/local/bin/pdive

# Install dependencies system-wide
sudo pip3 install -r requirements.txt

# Usage
pdive --help
```

### 3. Development Installation
```bash
# For development and customization
git clone https://github.com/yourusername/PDIve.git
cd PDIve

# Create development environment
python3 -m venv dev_env
source dev_env/bin/activate

# Install in development mode
pip install -e .
pip install -r requirements-dev.txt  # If available

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

## Uninstallation

### Remove Virtual Environment Installation
```bash
# Remove PDIve directory
rm -rf /path/to/PDIve

# Remove virtual environment
rm -rf recon_env

# System packages remain for other tools
```

### Remove System-wide Installation
```bash
# Remove PDIve script
sudo rm -f /usr/local/bin/pdive.py /usr/local/bin/pdive

# Remove Python packages (careful!)
pip3 uninstall requests colorama urllib3 python-nmap

# Remove security tools (if not needed)
sudo apt remove amass masscan nmap
```

## Next Steps

After successful installation:

1. **Read the Usage Guide**: See `USAGE.md` for comprehensive examples
2. **Review Security Guidelines**: Ensure you understand legal and ethical requirements
3. **Test with Safe Targets**: Start with localhost and domains you own
4. **Configure Sudo Access**: Set up masscan privileges if needed
5. **Explore Passive Mode**: Begin with passive discovery for minimal impact

For detailed usage instructions, see [USAGE.md](USAGE.md).
For troubleshooting, see the main [README.md](README.md).