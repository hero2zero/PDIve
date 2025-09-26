# PDIve (Python Edition)

**Dive deep into the network**

An automated penetration testing discovery tool designed for authorized security assessments and defensive testing, featuring both passive and active reconnaissance capabilities.

## ⚠️ Legal Notice

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is intended for legitimate security professionals, penetration testers, and system administrators who have explicit authorization to test networks and systems. Unauthorized scanning or testing of networks you do not own or have permission to test is illegal and unethical.

## Features

### Discovery Modes

PDIve now supports two distinct reconnaissance modes:

#### 🔍 **Passive Discovery Mode**
- **Amass Integration**: Passive subdomain enumeration using OWASP Amass only
- **OSINT-focused**: No active network scanning or probing
- **Stealth Operation**: Minimal network footprint for covert reconnaissance
- **Pure Passive**: Uses only amass for subdomain discovery

#### ⚡ **Active Discovery Mode** (Default)
- **Phase 1**: Passive subdomain discovery with Amass
- **Phase 2**: Host discovery and connectivity verification
- **Phase 3**: Fast port scanning with Masscan (1-65535)
- **Phase 4**: Detailed service enumeration with Nmap (on masscan results)
- **Comprehensive Analysis**: Full end-to-end reconnaissance workflow

### General Features
- **Comprehensive Reporting**: Specialized reports for each discovery mode
- **User-friendly CLI**: Color-coded output and progress indicators
- **Multi-target Support**: IP addresses, CIDR ranges, hostnames, and domain names
- **Flexible Output**: Multiple report formats (text, CSV)

## Prerequisites

### Required Tools
- **Python 3.6+**: Core runtime environment
- **Amass**: OWASP Amass for passive subdomain enumeration (required for both modes)
- **Masscan**: Fast port scanner (required for active mode)
- **Nmap**: Detailed service enumeration (optional for active mode)

### Installation

1. **Install System Dependencies**:

   **Ubuntu/Debian:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip amass masscan nmap
   ```

   **Manual Installation:**
   ```bash
   # Amass - https://github.com/OWASP/Amass
   # Masscan - https://github.com/robertdavidgraham/masscan
   # Nmap - https://nmap.org/download.html
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Passive Discovery Mode

Perfect for stealth reconnaissance and OSINT gathering:

```bash
# Basic passive discovery
python pdive.py -t example.com -m passive

# Passive discovery from file
python pdive.py -f domains.txt -m passive

# Multiple domains
python pdive.py -t "example.com,testsite.com" -m passive
```

### Active Discovery Mode

Traditional network scanning and analysis:

```bash
# Basic active scan
python pdive.py -t 192.168.1.0/24

# Active scan with nmap integration
python pdive.py -t 10.0.0.1 --nmap

# Multiple targets active scan
python pdive.py -t "192.168.1.1,example.com,10.0.0.0/24"
```

### Mixed Examples

```bash
# Scan from file with custom settings
python pdive.py -f targets.txt -o /tmp/scan_results -T 100

# Domain passive discovery with custom output
python pdive.py -t "*.company.com" -m passive -o /tmp/passive_recon
```

### Command Line Options

- `-t, --target`: Target IP address, hostname, CIDR range, or comma-separated list
- `-f, --file`: File containing targets (one per line)
- `-m, --mode`: Discovery mode - `active` (default) or `passive`
- `-o, --output`: Output directory (default: recon_output)
- `-T, --threads`: Number of threads (default: 50)
- `--nmap`: Enable detailed Nmap scanning (**Active mode only**)
- `--version`: Show version information

**Notes**:
- Either `-t` or `-f` is required, but not both
- `--nmap` flag cannot be used with passive mode
- Passive mode works best with domain names, not IP addresses

### Target File Format

When using the `-f` option, create a text file with one target per line:

```
# Comments start with #
# For passive mode, use domains:
example.com
testsite.org
company.net

# For active mode, use IPs/networks:
192.168.1.0/24
10.0.0.1
server.local
```

## Discovery Methods

### Passive Discovery Techniques

1. **Amass Enumeration**: Uses OWASP Amass for passive subdomain discovery
   - Sources: Certificate transparency, DNS aggregation, web archives
   - Command: `amass enum -d domain.com -passive`
   - Pure passive mode - no active network traffic to targets

### Active Discovery Process

1. **Authorization Check**: Prompts user to confirm scanning authorization
2. **Phase 1 - Amass Discovery**: Passive subdomain enumeration using amass
3. **Phase 2 - Host Discovery**: Ping sweep and port-based host detection on all discovered hosts
4. **Phase 3 - Masscan**: Fast port scanning (1-65535) on all live hosts
5. **Phase 4 - Nmap Enumeration**: Detailed service/version detection on masscan results
6. **Report Generation**: Creates comprehensive scan reports

## Output and Reports

### Passive Mode Reports

**Host List Report (`passive_discovery_TIMESTAMP.txt`)**:
```
PDIVE PASSIVE DISCOVERY REPORT
============================================================

DISCOVERY SUMMARY
--------------------
Targets: example.com
Discovery Mode: PASSIVE
Total Discovered Hosts: 45

DISCOVERED HOSTS
--------------------
  • accounts.example.com
  • api.example.com
  • mail.example.com
  • www.example.com
```

**CSV Host List (`passive_hosts_TIMESTAMP.csv`)**:
- Simple format: Host, Discovery_Method, Scan_Time
- Perfect for further analysis and integration

### Active Mode Reports

**Detailed Text Report (`recon_report_YYYYMMDD_HHMMSS.txt`)**:
- Complete scan summary with timestamps and statistics
- Detailed host information with port and service listings
- Professional format suitable for documentation

**CSV Report (`recon_results_YYYYMMDD_HHMMSS.csv`)**:
- Structured data: Host, Port, Protocol, State, Service, Scan_Time
- Compatible with Excel, databases, and analysis tools

### Tool Integration Details

**Masscan Integration (Active Mode - Phase 3)**:
- **Port Range**: Scans ports 1-65535 (complete coverage)
- **Speed**: Fast scanning with configurable rate limiting
- **Output**: Discovers all open ports quickly
- **Command**: `masscan -iL targets.txt -p1-65535 --rate 1000`

**Nmap Integration (Active Mode - Phase 4)**:
- **Targeted Scanning**: Only scans ports found by masscan
- **Service Detection**: Uses `-sV` for service version identification
- **High Intensity**: Uses `--version-intensity 7` for detailed detection
- **No Ping**: Uses `-Pn` to bypass ping filtering
- **Command**: `nmap -p <masscan_ports> -Pn -sV --version-intensity 7 <target>`

## Requirements

### Core Dependencies
- **Python 3.6+**
- **requests>=2.31.0** (Python library)
- **colorama>=0.4.6** (Python library)
- **urllib3>=2.0.4** (Python library)
- **python-nmap>=0.7.1** (Python library)

### Required External Tools
- **Amass**: OWASP Amass for passive subdomain enumeration
  - Required for both passive and active modes
  - Install from: https://github.com/OWASP/Amass
  - Ubuntu/Debian: `sudo apt install amass`

- **Masscan**: Fast port scanner
  - Required for active mode (fallback to basic scan if unavailable)
  - **Requires sudo privileges** for raw socket access
  - Install from: https://github.com/robertdavidgraham/masscan
  - Ubuntu/Debian: `sudo apt install masscan`
  - **Usage**: Run with `sudo python3 pdive.py` or configure passwordless sudo

- **Nmap**: Detailed service enumeration
  - Optional for active mode (enhanced service detection)
  - Install from: https://nmap.org/download.html
  - Ubuntu/Debian: `sudo apt install nmap`

## Use Cases

### Passive Mode - Perfect For:
- 🕵️ **OSINT Collection**: Gathering public information without direct contact
- 🔒 **Stealth Reconnaissance**: Minimal network footprint operations
- 📊 **Domain Analysis**: Understanding an organization's digital footprint
- 🛡️ **Defensive Assessment**: Identifying your own exposed assets
- 📋 **Compliance Auditing**: Asset discovery for security compliance

### Active Mode - Ideal For:
- 🎯 **Penetration Testing**: Authorized security assessments
- 🔍 **Vulnerability Assessment**: Identifying open services and versions
- 🖥️ **Network Discovery**: Mapping internal network topology
- 🛠️ **Infrastructure Analysis**: Detailed service enumeration
- 📈 **Security Monitoring**: Regular network security checks

## Troubleshooting

### Masscan Sudo Requirements

PDIve v1.3 includes intelligent masscan sudo handling. Masscan requires root privileges for raw socket access:

**Option 1: Run PDIve with sudo**
```bash
sudo python3 pdive.py -t target.com
```

**Option 2: Configure passwordless sudo for masscan**
```bash
# Add to /etc/sudoers (use visudo)
username ALL=(ALL) NOPASSWD: /usr/bin/masscan

# Test configuration
sudo -n masscan --help
```

**Option 3: Let PDIve fallback to basic port scanning**
- PDIve automatically detects sudo availability
- Falls back gracefully to built-in port scanner if masscan can't run
- Provides helpful error messages and suggestions

### Virtual Environment Setup

If you encounter "externally-managed-environment" errors:

```bash
# Create and activate virtual environment
python3 -m venv recon_env
source recon_env/bin/activate  # Linux/Mac
# OR
recon_env\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run PDIve
python pdive.py -t your_target
```

### Missing System Packages

On Debian/Ubuntu systems:

```bash
# Install all required packages
sudo apt update
sudo apt install python3-venv python3-pip amass masscan nmap

# Create virtual environment
python3 -m venv recon_env
source recon_env/bin/activate
pip install -r requirements.txt
```

### Amass Configuration Issues

If amass fails or times out:

```bash
# Test amass manually
amass enum -d example.com -passive

# Check amass installation
which amass
amass --help
```

### Common Issues

- **Passive mode with IPs**: Use domain names for passive discovery, not IP addresses
- **DNSDumpster blocking**: Rate limiting or bot detection may block requests
- **Amass timeout**: Large domains may take longer; tool has built-in timeout handling
- **Permission denied**: Ensure proper file permissions for output directory
- **Network timeouts**: Reduce thread count with `-T` option for slower networks

## Examples

### Comprehensive Passive Reconnaissance
```bash
# Discover all subdomains for multiple organizations
echo -e "example.com\ncompany.org\ntarget.net" > domains.txt
python pdive.py -f domains.txt -m passive -o passive_results

# Results show all discovered subdomains from multiple sources
```

### Active Network Assessment
```bash
# Full internal network scan with detailed analysis
python pdive.py -t 192.168.0.0/16 -m active --nmap -o internal_scan -T 200

# Results include live hosts, open ports, and service versions
```

### Hybrid Approach
```bash
# 1. Start with passive discovery
python pdive.py -t company.com -m passive -o recon_phase1

# 2. Use discovered hosts for targeted active scanning
python pdive.py -f discovered_hosts.txt -m active --nmap -o recon_phase2
```

## Security Considerations

- **Authorization**: Always obtain explicit written permission before scanning
- **Scope**: Stay within authorized target scope and timeframes
- **Rate Limiting**: Use appropriate thread counts to avoid overwhelming targets
- **Data Handling**: Secure storage and disposal of reconnaissance data
- **Legal Compliance**: Follow local laws and organizational policies
- **Ethical Use**: Use for legitimate security testing and defensive purposes only

## Version History

- **v1.3**: Enhanced masscan integration with intelligent sudo handling and improved error messages
- **v1.2**: Rebranded to PDIve with enhanced workflow: passive mode uses only amass, active mode uses amass → masscan → nmap
- **v1.1**: Added passive discovery mode with Amass, DNSDumpster, and crt.sh integration
- **v1.0**: Initial release as Roverly with active scanning capabilities

## License

This tool is provided for educational and authorized security testing purposes only.

## Disclaimer

The authors are not responsible for any misuse of this tool. Users are solely responsible for ensuring they have proper authorization before using this tool on any network or system. Passive reconnaissance should still be conducted within the bounds of authorized testing scope and applicable laws.
