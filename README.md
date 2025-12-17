# PDIve (Python Version)

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
- **Phase 2**: Host discovery via port-based detection (no ICMP by default)
- **Phase 3**: Fast port scanning with Masscan (1-65535)
- **Phase 4**: Service enumeration (always performed - basic or detailed with nmap)
- **Stealth by Default**: ICMP ping disabled by default; use `--ping` to enable
- **Speed Options**: Use `--masscan` for fast scans with basic service identification or `--nmap` for detailed analysis
- **Comprehensive Analysis**: Full end-to-end reconnaissance workflow with automatic service detection

### General Features
- **Comprehensive Reporting**: Specialized reports for each discovery mode
- **User-friendly CLI**: Color-coded output and real-time progress indicators
- **Multi-target Support**: IP addresses, CIDR ranges, hostnames, and domain names
- **Flexible Output**: Multiple report formats (text, CSV)
- **Visual Feedback**: Progress bars for masscan/nmap scans and spinners for long-running operations

## Prerequisites

### Required Tools
- **Python 3.6+**: Core runtime environment
- **Amass**: OWASP Amass for passive subdomain enumeration (required for both modes)
- **Masscan**: Fast port scanner (required for active mode)
- **Nmap**: Detailed service enumeration (optional for active mode)

### Installation

1. **Install System Dependencies**:

   **Ubuntu/Debian/Kali:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip amass masscan nmap python3-nmap
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
# Basic active scan (port-based discovery only, no ping)
python pdive.py -t 192.168.1.0/24

# Active scan with nmap integration (detailed service enumeration)
python pdive.py -t 10.0.0.1 --nmap

# Fast scan with masscan and basic service enumeration
python pdive.py -t 192.168.1.0/24 --masscan

# Active scan with ping enabled (less stealthy)
python pdive.py -t 192.168.1.0/24 --ping

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
- `-o, --output`: Output directory (default: pdive_output)
- `-T, --threads`: Number of threads for scan throttling (default: 5)
- `--nmap`: Enable detailed Nmap scanning after masscan (**Active mode only**)
- `--masscan`: Skip passive discovery and use fast port scanning with basic service enumeration (**Active mode only**)
- `--ping`: Enable ICMP ping for host discovery (**disabled by default for stealth**)
- `--version`: Show version information

**Notes**:
- Either `-t` or `-f` is required, but not both
- `--nmap` and `--masscan` flags cannot be used together (mutually exclusive)
- `--nmap` and `--masscan` flags cannot be used with passive mode
- `--ping` is disabled by default for stealth; port-based discovery is used instead
- Passive mode works best with domain names, not IP addresses
- Service enumeration is ALWAYS performed on all discovered open ports (basic or detailed with --nmap)

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
   - **No Timeout**: Amass runs until completion with visual progress indicator
   - **Progress Display**: Spinning indicator shows scan is active

### Active Discovery Process

1. **Authorization Check**: Prompts user to confirm scanning authorization
2. **Phase 1 - Amass Discovery**: Passive subdomain enumeration using amass (skipped with --masscan or --nmap flags)
3. **Phase 2 - Host Discovery**: Port-based host detection (optional ICMP ping with --ping flag)
4. **Phase 3 - Masscan**: Fast port scanning (1-65535) on all live hosts with real-time progress bar
5. **Phase 4 - Service Enumeration**: ALWAYS performed on all discovered open ports:
   - **Default**: Basic service identification via HTTP headers and port mapping
   - **--nmap flag**: Detailed service/version detection with Nmap (includes progress bar per host)
   - **--masscan flag**: Basic service identification (same as default but skips Phase 1)
6. **Report Generation**: Creates comprehensive scan reports with service information

**Note**: ICMP ping is disabled by default for stealth. PDIve uses port-based discovery (checks common ports like 80, 443, 22) to detect live hosts without generating ICMP traffic.

**Speed vs Detail Trade-off**:
- **Fastest**: Use `--masscan` to skip passive discovery and use basic service identification
- **Balanced**: Default behavior with amass discovery + basic service identification
- **Most Detailed**: Use `--nmap` for comprehensive service/version enumeration with detailed Nmap scans

## Output and Reports

### Passive Mode Reports

**Host List Report (`pdive_passive_TIMESTAMP.txt`)**:
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

**CSV Host List (`pdive_hosts_TIMESTAMP.csv`)**:
- Simple format: Host, Discovery_Method, Scan_Time
- Perfect for further analysis and integration

### Active Mode Reports

**Detailed Text Report (`pdive_report_YYYYMMDD_HHMMSS.txt`)**:
- Complete scan summary with timestamps and statistics
- Detailed host information with port and service listings
- Professional format suitable for documentation

**CSV Report (`pdive_results_YYYYMMDD_HHMMSS.csv`)**:
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

- **Nmap and Python-Nmap Module**: Detailed service enumeration
  - Optional for active mode (enhanced service detection)
  - Install from: https://nmap.org/download.html
  - Ubuntu/Debian/Kali: `sudo apt install nmap python3-nmap`
  - **Note**: Use system package `python3-nmap` to avoid "externally-managed-environment" errors

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

On Debian/Ubuntu/Kali systems:

```bash
# Install all required packages (including python3-nmap)
sudo apt update
sudo apt install python3-venv python3-pip amass masscan nmap python3-nmap

# Create virtual environment
python3 -m venv recon_env
source recon_env/bin/activate
pip install -r requirements.txt

# Verify nmap module is available
python3 -c "import nmap; print('nmap module available')"
```

### Nmap Module Not Available

If you see "Note: nmap module not available, nmap scanning disabled":

```bash
# Install python3-nmap system package (recommended for Kali/Debian/Ubuntu)
sudo apt install python3-nmap

# Verify installation
python3 -c "import nmap; print('nmap module available')"

# Alternative: Install via pip in virtual environment
python3 -m venv recon_env
source recon_env/bin/activate
pip install python-nmap
```

### Amass Configuration Issues

If amass fails:

```bash
# Test amass manually
amass enum -d example.com

# Check amass installation
which amass
amass --help
```

**Note**: As of v1.3.3, amass runs without timeout and displays a progress indicator during execution. Large domain scans may take considerable time to complete.

### Common Issues

- **Passive mode with IPs**: Use domain names for passive discovery, not IP addresses
- **DNSDumpster blocking**: Rate limiting or bot detection may block requests
- **Amass long runtime**: Large domains may take considerable time; watch progress indicator to confirm scan is active
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
# Fast port scan for quick network mapping (with basic service enumeration)
python pdive.py -t 192.168.0.0/16 --masscan -o quick_scan -T 200

# Balanced scan with amass discovery and basic service identification (default)
python pdive.py -t 192.168.0.0/16 -o balanced_scan -T 200

# Full internal network scan with detailed nmap service analysis
python pdive.py -t 192.168.0.0/16 -m active --nmap -o internal_scan -T 200

# Results include live hosts, open ports, and service information (always)
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

### Python Version

- **v1.3.4** (Current):
  - **Progress Bars**: Added visual progress bars for masscan and nmap scans
  - **Always-On Service Scanning**: Service enumeration now ALWAYS performed on all discovered open ports
  - **Enhanced User Experience**: Real-time progress indicators show scan status with elapsed time
  - **Improved Workflow**: Removed option to skip service enumeration - all scans now provide service information
  - **Better Visibility**: Progress bars display for long-running masscan and per-host nmap scans

- **v1.3.3**:
  - Removed amass timeout - scans now run until completion
  - Added real-time progress indicator for amass operations
  - Enhanced user experience with visual feedback during long scans
  - Improved reliability for large domain enumeration tasks

- **v1.3.2**:
  - Modified default thread count from 50 to 5 for better scan throttling control
  - Improved conservative scanning approach by default
  - Updated help text and examples to clarify thread throttling
  - Users can increase threads with `-T` flag (e.g., `-T 100` for faster scans)

- **v1.3.1**:
  - Disabled ICMP ping by default for stealth operations
  - Added `--ping` flag for optional ICMP discovery

- **v1.3**:
  - Enhanced masscan integration with intelligent sudo handling
  - Improved error messages and fallback handling

- **v1.2**:
  - Rebranded to PDIve with enhanced workflow
  - Passive mode uses only amass
  - Active mode uses amass → masscan → nmap pipeline

- **v1.1**:
  - Added passive discovery mode
  - Integrated Amass, DNSDumpster, and crt.sh

- **v1.0**:
  - Initial release as Roverly with active scanning capabilities

## License

This tool is provided for educational and authorized security testing purposes only.

## Disclaimer

The authors are not responsible for any misuse of this tool. Users are solely responsible for ensuring they have proper authorization before using this tool on any network or system. Passive reconnaissance should still be conducted within the bounds of authorized testing scope and applicable laws.