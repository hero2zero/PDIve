# PDIve Usage Guide

## Table of Contents
- [Quick Start](#quick-start)
- [Discovery Modes](#discovery-modes)
- [Command Line Options](#command-line-options)
- [Target Formats](#target-formats)
- [Passive Discovery Examples](#passive-discovery-examples)
- [Active Discovery Examples](#active-discovery-examples)
- [Advanced Usage](#advanced-usage)
- [Output and Reports](#output-and-reports)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites Check
```bash
# Verify PDIve installation
python3 pdive.py --version

# Check required tools
which amass masscan nmap
```

### Basic Commands
```bash
# Passive discovery (minimal network footprint)
python3 pdive.py -t example.com -m passive

# Active discovery (comprehensive scanning)
python3 pdive.py -t 192.168.1.0/24

# Active discovery with detailed service detection
python3 pdive.py -t 10.0.0.1 --nmap
```

## Discovery Modes

### Passive Mode (`-m passive`)

**Purpose**: Stealth reconnaissance using only public sources
**Network Impact**: Zero direct contact with target
**Duration**: 30-120 seconds per domain

**Workflow**:
1. OWASP Amass passive subdomain enumeration
2. DNS and certificate transparency log analysis
3. No active network scanning or probing

**Best For**:
- Initial reconnaissance
- OSINT collection
- Compliance-sensitive environments
- Stealth operations

### Active Mode (`-m active`) - Default

**Purpose**: Comprehensive network reconnaissance and enumeration
**Network Impact**: Direct network scanning and probing
**Duration**: 2-30 minutes depending on scope

**Workflow**:
1. **Phase 1**: Amass passive subdomain discovery
2. **Phase 2**: Host discovery (ping + port-based detection)
3. **Phase 3**: Fast port scanning with Masscan (1-65535)
4. **Phase 4**: Service enumeration (basic or Nmap if enabled)

**Best For**:
- Authorized penetration testing
- Network discovery
- Vulnerability assessments
- Infrastructure analysis

## Command Line Options

### Required Arguments (Mutually Exclusive)
```bash
-t, --target    # Single target or comma-separated list
-f, --file      # File containing targets (one per line)
```

### Optional Arguments
```bash
-m, --mode      # Discovery mode: active (default) or passive
-o, --output    # Output directory (default: pdive_output)
-T, --threads   # Number of threads (default: 50)
--nmap          # Enable detailed Nmap scanning (active mode only)
--version       # Show version information
```

### Argument Combinations
```bash
# Valid combinations
python3 pdive.py -t target.com
python3 pdive.py -f targets.txt
python3 pdive.py -t "ip1,ip2,domain" -m active --nmap
python3 pdive.py -f domains.txt -m passive -o results

# Invalid combinations
python3 pdive.py -t target.com -f targets.txt  # Cannot use both -t and -f
python3 pdive.py -t target.com -m passive --nmap  # Cannot use --nmap with passive mode
```

## Target Formats

### Single Targets
```bash
# IP address
python3 pdive.py -t 192.168.1.100

# Domain name
python3 pdive.py -t example.com

# Subdomain
python3 pdive.py -t api.example.com

# CIDR network
python3 pdive.py -t 10.0.0.0/24
```

### Multiple Targets (Comma-separated)
```bash
# Mixed targets
python3 pdive.py -t "192.168.1.1,example.com,10.0.0.0/28"

# Multiple domains (passive mode)
python3 pdive.py -t "domain1.com,domain2.org,target.net" -m passive

# Multiple IP ranges
python3 pdive.py -t "192.168.1.0/24,10.0.0.0/24,172.16.0.0/28"
```

### Target Files (`-f` option)
```bash
# Create target file
cat > targets.txt << EOF
# Passive mode targets (domains)
example.com
testsite.org
company.net

# Active mode targets (IPs/networks)
192.168.1.0/24
10.0.0.1
server.local
EOF

# Use target file
python3 pdive.py -f targets.txt
```

## Passive Discovery Examples

### Basic Passive Discovery
```bash
# Single domain
python3 pdive.py -t example.com -m passive

# Multiple domains
python3 pdive.py -t "example.com,target.org" -m passive

# From file with custom output
python3 pdive.py -f domains.txt -m passive -o passive_results
```

### Expected Output - Passive Mode
```
[+] Starting Passive Discovery (amass only)...
[*] Running amass on example.com...
[+] Amass discovered: mail.example.com
[+] Amass discovered: www.example.com
[+] Amass discovered: api.example.com
[+] Amass discovered: blog.example.com

[*] Passive discovery completed. Found 4 hosts.

[+] PASSIVE DISCOVERY RESULTS
==================================================
Total hosts discovered: 4

Discovered hosts:
api.example.com
blog.example.com
mail.example.com
www.example.com
```

### Corporate Domain Reconnaissance
```bash
# Comprehensive passive discovery for large organization
echo -e "company.com\ncompany.org\ncompany.net" > corp_domains.txt
python3 pdive.py -f corp_domains.txt -m passive -o corporate_recon

# Expected to discover:
# - Subdomains across all TLDs
# - Development/staging environments
# - Regional offices (us.company.com, eu.company.com)
# - Service-specific subdomains (mail, vpn, ftp, etc.)
```

## Active Discovery Examples

### Basic Active Discovery
```bash
# Local network scan
python3 pdive.py -t 192.168.1.0/24

# Single host comprehensive scan
python3 pdive.py -t 10.0.0.1 --nmap

# Mixed targets
python3 pdive.py -t "192.168.1.1,example.com,server.local"
```

### Expected Output - Active Mode
```
[+] Starting Active Discovery Mode
[*] Phase 1: Passive subdomain discovery with amass
[*] Phase 2: Host discovery and connectivity check

[+] Starting Host Discovery...
[*] Processing target: 192.168.1.0/24
[*] Phase 1: Ping discovery...
[+] Host discovered (ping): 192.168.1.1
[+] Host discovered (ping): 192.168.1.100

[*] Phase 3: Fast port scanning with masscan
[*] Running masscan on 2 hosts...
[+] Masscan found: 192.168.1.1:80
[+] Masscan found: 192.168.1.1:443
[+] Masscan found: 192.168.1.100:22

[*] Phase 4: Basic service identification
[+] Service identified: 192.168.1.1:80 -> http (nginx/1.18)
[+] Service identified: 192.168.1.1:443 -> https (nginx/1.18)
[+] Service identified: 192.168.1.100:22 -> ssh
```

### Network Segment Discovery
```bash
# Scan multiple network segments
python3 pdive.py -t "10.0.1.0/24,10.0.2.0/24,10.0.3.0/24" -T 100

# DMZ network scan with detailed enumeration
sudo python3 pdive.py -t 172.16.0.0/24 --nmap -o dmz_scan

# Internal infrastructure discovery
python3 pdive.py -t "192.168.0.0/16" -T 200 -o internal_recon
```

### Domain-to-IP Active Scanning
```bash
# Two-phase approach: passive discovery then active scanning
# Phase 1: Passive discovery
python3 pdive.py -t company.com -m passive -o phase1

# Phase 2: Extract discovered hosts and scan actively
# (Manual step: extract hosts from phase1 results)
python3 pdive.py -f discovered_hosts.txt -o phase2 --nmap
```

## Advanced Usage

### Performance Optimization
```bash
# High-speed scanning (requires powerful system)
sudo python3 pdive.py -t 10.0.0.0/16 -T 500

# Conservative scanning (slower networks/systems)
python3 pdive.py -t target.com -T 10

# Memory-efficient large network scan
python3 pdive.py -t 172.16.0.0/12 -T 50 -o large_scan
```

### Stealth and Rate Limiting
```bash
# Minimal thread count for stealth
python3 pdive.py -t target.com -T 5

# Passive-only reconnaissance
python3 pdive.py -t "target1.com,target2.org,target3.net" -m passive

# Active scan without masscan (slower but more controlled)
# PDIve automatically falls back if masscan sudo access unavailable
python3 pdive.py -t 192.168.1.0/24 -T 20
```

### Comprehensive Assessment Workflow
```bash
# Step 1: Passive reconnaissance
python3 pdive.py -t target.com -m passive -o step1_passive

# Step 2: Active host discovery
python3 pdive.py -t target.com -o step2_active

# Step 3: Detailed service enumeration
sudo python3 pdive.py -t target.com --nmap -o step3_detailed

# Step 4: Infrastructure mapping
python3 pdive.py -t "target.com,target.org,target.net" --nmap -o step4_infrastructure
```

### Custom Output Management
```bash
# Organized output by date
DATE=$(date +%Y%m%d)
python3 pdive.py -t target.com -o "scans/${DATE}/target_com"

# Separate passive and active results
python3 pdive.py -t company.com -m passive -o "results/passive/company"
python3 pdive.py -t company.com -o "results/active/company" --nmap

# Project-based organization
python3 pdive.py -t client.com -o "projects/client_pentest/recon"
```

## Output and Reports

### Report Types Generated

#### Passive Mode Reports
1. **Host List Report** (`pdive_passive_TIMESTAMP.txt`)
   - Summary statistics
   - Discovered hosts list
   - DNS resolution information

2. **CSV Host List** (`pdive_hosts_TIMESTAMP.csv`)
   - Host,IP_Address,Reverse_DNS,Discovery_Method,Scan_Time
   - Suitable for spreadsheet analysis

#### Active Mode Reports
1. **Detailed Text Report** (`pdive_report_TIMESTAMP.txt`)
   - Scan summary with statistics
   - Host-by-host analysis
   - Port and service details

2. **CSV Results** (`pdive_results_TIMESTAMP.csv`)
   - Host,IP_Address,Reverse_DNS,Port,Protocol,State,Service,Scan_Time
   - Database-ready format

### Report Analysis Examples

#### Passive Mode Analysis
```bash
# Extract all discovered subdomains
grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' pdive_passive_*.txt

# Count discoveries by domain
cat pdive_hosts_*.csv | cut -d',' -f1 | sort | uniq -c | sort -nr

# Find interesting subdomains
grep -E '(api|admin|test|dev|staging|vpn|mail)' pdive_passive_*.txt
```

#### Active Mode Analysis
```bash
# Extract all open ports
grep "Open Ports:" -A 10 pdive_report_*.txt

# Find web services
grep -E "(80|443|8080|8443)" pdive_results_*.csv

# Identify SSH services
grep ":22/tcp" pdive_report_*.txt

# Count services by type
cut -d',' -f7 pdive_results_*.csv | sort | uniq -c | sort -nr
```

### Integration with Other Tools

#### Nmap Integration
```bash
# Extract hosts with open ports for detailed nmap scan
grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" pdive_results_*.csv | \
    cut -d',' -f1 | sort -u > live_hosts.txt

# Run custom nmap scan on discovered hosts
nmap -sV -sC -iL live_hosts.txt -oA detailed_scan
```

#### Masscan Integration
```bash
# Extract IP ranges for custom masscan
grep -E "^[0-9]+\.[0-9]+\.[0-9]+\." pdive_hosts_*.csv | \
    cut -d',' -f2 | sort -u > target_ips.txt

# Custom masscan with specific ports
sudo masscan -iL target_ips.txt -p80,443,22,21,25 --rate 1000
```

## Best Practices

### Legal and Ethical Guidelines

#### Before Scanning
```bash
# 1. Obtain written authorization
# 2. Define scope clearly
# 3. Set time boundaries
# 4. Understand legal implications

# Example: Safe testing targets
python3 pdive.py -t 127.0.0.1  # Always safe
python3 pdive.py -t your-own-domain.com -m passive  # Your domains only
```

#### Authorization Confirmation
PDIve always prompts for authorization:
```
WARNING: This tool is for authorized security testing only!
Ensure you have proper permission before scanning any network.

Targets to scan: example.com
Do you have authorization to scan these targets? (y/N):
```

### Operational Best Practices

#### Start Small and Scale
```bash
# 1. Test with single host
python3 pdive.py -t single-host.com -T 5

# 2. Small network segment
python3 pdive.py -t 192.168.1.0/28 -T 10

# 3. Full network (if authorized)
python3 pdive.py -t 192.168.0.0/16 -T 50
```

#### Progressive Disclosure
```bash
# Phase 1: Passive reconnaissance (minimal impact)
python3 pdive.py -t target.com -m passive

# Phase 2: Host discovery (low impact)
python3 pdive.py -t target.com -T 10

# Phase 3: Service enumeration (medium impact)
python3 pdive.py -t target.com --nmap -T 20
```

#### Resource Management
```bash
# Monitor system resources during large scans
htop  # Monitor CPU/memory usage
netstat -i  # Monitor network interface utilization

# Adjust threading based on system capacity
# Low-end system: -T 10-20
# Medium system: -T 50-100
# High-end system: -T 100-500
```

### Network Considerations

#### Firewall and IDS Awareness
```bash
# Slower scanning to avoid detection
python3 pdive.py -t target.com -T 5

# Passive-only to avoid network signatures
python3 pdive.py -t target.com -m passive

# Distributed scanning (manual process)
# Split large networks across multiple systems/times
```

#### Network Bandwidth Management
```bash
# Internal network: Higher thread counts acceptable
python3 pdive.py -t 192.168.0.0/16 -T 200

# Internet targets: Conservative approach
python3 pdive.py -t internet-target.com -T 20

# Shared/limited bandwidth: Minimal impact
python3 pdive.py -t target.com -T 5
```

## Troubleshooting

### Common Issues and Solutions

#### Masscan Sudo Issues
```bash
# Issue: "permission denied" or "sudo password required"
# Solution 1: Run entire script with sudo
sudo python3 pdive.py -t target.com

# Solution 2: Configure passwordless sudo for masscan
sudo visudo
# Add: username ALL=(ALL) NOPASSWD: /usr/bin/masscan

# Solution 3: Accept automatic fallback to basic scan
# PDIve automatically handles this in v1.3
```

#### Amass Configuration Issues
```bash
# Issue: Amass timeout or no results
# Debug: Test amass manually
amass enum -d example.com -passive -v

# Issue: Amass not found
which amass
sudo apt install amass  # Or manual installation

# Issue: Amass configuration errors
rm -rf ~/.config/amass  # Reset configuration
```

#### Performance Issues
```bash
# Issue: High CPU usage
# Solution: Reduce thread count
python3 pdive.py -t target.com -T 10

# Issue: Memory exhaustion
# Solution: Scan smaller networks or reduce threads
python3 pdive.py -t 192.168.1.0/25 -T 20  # Instead of /24

# Issue: Network timeouts
# Solution: Conservative threading
python3 pdive.py -t target.com -T 5
```

#### Output and Permission Issues
```bash
# Issue: Cannot write to output directory
# Solution: Check permissions
mkdir -p custom_output
chmod 755 custom_output
python3 pdive.py -t target.com -o custom_output

# Issue: Reports not generated
# Solution: Check disk space and permissions
df -h  # Check available space
ls -la output_directory/  # Check permissions
```

### Debugging and Verbose Output

#### Enable Debug Information
```bash
# Add debug prints (modify pdive.py temporarily)
# Or run with Python verbose mode
python3 -v pdive.py -t target.com

# Monitor network activity
sudo tcpdump -i any host target.com

# Check DNS resolution
nslookup target.com
dig target.com
```

#### Validate Tool Dependencies
```bash
# Check all required tools
echo "Checking dependencies..."
python3 --version
amass --version
masscan --version
nmap --version

# Check Python modules
python3 -c "import requests, colorama, urllib3; print('Python modules OK')"
python3 -c "import nmap; print('python-nmap module OK')"

# Check network connectivity
ping -c 1 8.8.8.8
curl -I https://crt.sh
```

### Performance Tuning

#### System-Specific Optimization
```bash
# For high-performance systems
sudo python3 pdive.py -t large-network.com -T 300

# For resource-constrained systems
python3 pdive.py -t target.com -T 5

# For network-limited environments
python3 pdive.py -t target.com -T 10 -m passive
```

#### Monitoring and Optimization
```bash
# Monitor PDIve performance
top -p $(pgrep -f pdive.py)

# Monitor network utilization
iftop -i eth0

# Monitor DNS queries
sudo tcpdump -i any port 53

# Adjust based on observations:
# - High CPU: Reduce threads
# - Network saturation: Reduce threads or use passive mode
# - Memory issues: Scan smaller segments
```

## Example Workflows

### Penetration Testing Workflow
```bash
# 1. Passive reconnaissance
python3 pdive.py -t client.com -m passive -o "pentest/01-passive"

# 2. Active host discovery
python3 pdive.py -t client.com -o "pentest/02-discovery" -T 50

# 3. Detailed enumeration
sudo python3 pdive.py -t client.com --nmap -o "pentest/03-detailed" -T 100

# 4. Infrastructure mapping
python3 pdive.py -t "client.com,client.org,client.net" --nmap -o "pentest/04-infrastructure"

# 5. Analysis and reporting
grep -r "ssh\|rdp\|ftp" pentest/*/
```

### Security Monitoring Workflow
```bash
# Weekly passive monitoring
DATE=$(date +%Y%m%d)
python3 pdive.py -t company.com -m passive -o "monitoring/passive/${DATE}"

# Monthly active assessment
python3 pdive.py -t "company.com,company.org" -o "monitoring/active/${DATE}"

# Compare results over time
diff monitoring/passive/20231201/pdive_hosts_*.csv \
     monitoring/passive/20231215/pdive_hosts_*.csv
```

### Red Team Reconnaissance
```bash
# Phase 1: Stealth passive collection
python3 pdive.py -t target.com -m passive -T 5 -o "redteam/phase1"

# Phase 2: Minimal-impact active probing
python3 pdive.py -t target.com -T 5 -o "redteam/phase2"

# Phase 3: Targeted enumeration (high-value targets only)
python3 pdive.py -t high-value-hosts.txt --nmap -T 10 -o "redteam/phase3"
```

This comprehensive usage guide should help users effectively utilize PDIve v1.3 for their authorized security testing and reconnaissance needs.