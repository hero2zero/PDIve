#!/usr/bin/env python3
"""
PDIve - Automated Penetration Testing Discovery Tool
Dive deep into the network - A defensive security tool for authorized network reconnaissance and vulnerability assessment.
"""

import argparse
import csv
import ipaddress
import os
import socket
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    from colorama import init, Fore, Back, Style
    import requests
    import urllib3
    # Suppress SSL warnings for reconnaissance purposes
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class MockColor:
        CYAN = YELLOW = GREEN = RED = ""
        RESET_ALL = ""
    Fore = Style = MockColor()

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    print("Note: nmap module not available, nmap scanning disabled")

if HAS_COLORAMA:
    init(autoreset=True)


class PDIve:
    def __init__(self, targets, output_dir="pdive_output", threads=50, discovery_mode="active", enable_ping=False):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.output_dir = output_dir
        self.threads = threads
        self.discovery_mode = discovery_mode
        self.enable_ping = enable_ping
        self.results = {
            "scan_info": {
                "targets": self.targets,
                "start_time": datetime.now().isoformat(),
                "scanner": "PDIve v1.3",
                "discovery_mode": self.discovery_mode
            },
            "hosts": {},
            "services": {},
            "summary": {},
            "unresponsive_hosts": 0
        }

        os.makedirs(output_dir, exist_ok=True)

    def print_banner(self):
        targets_display = ', '.join(self.targets[:3])
        if len(self.targets) > 3:
            targets_display += f" ... (+{len(self.targets) - 3} more)"

        banner = f"""
{Fore.CYAN}
██████╗ ██████╗ ██╗██╗   ██╗███████╗
██╔══██╗██╔══██╗██║██║   ██║██╔════╝
██████╔╝██║  ██║██║██║   ██║█████╗
██╔═══╝ ██║  ██║██║╚██╗ ██╔╝██╔══╝
██║     ██████╔╝██║ ╚████╔╝ ███████╗
╚═╝     ╚═════╝ ╚═╝  ╚═══╝  ╚══════╝
{Style.RESET_ALL}
{Fore.YELLOW}Dive deep into the network{Style.RESET_ALL}
{Fore.RED}For authorized security testing only!{Style.RESET_ALL}

Targets ({len(self.targets)}): {Fore.GREEN}{targets_display}{Style.RESET_ALL}
Output Directory: {Fore.GREEN}{self.output_dir}{Style.RESET_ALL}
Threads: {Fore.GREEN}{self.threads}{Style.RESET_ALL}
Discovery Mode: {Fore.GREEN}{self.discovery_mode.upper()}{Style.RESET_ALL}
Ping Enabled: {Fore.GREEN}{'YES' if self.enable_ping else 'NO'}{Style.RESET_ALL}
"""
        print(banner)

    def validate_targets(self):
        """Validate if all targets are valid IP addresses, network ranges, or hostnames"""
        valid_targets = []
        invalid_targets = []

        for target in self.targets:
            try:
                ipaddress.ip_network(target, strict=False)
                valid_targets.append(target)
            except ValueError:
                try:
                    socket.gethostbyname(target)
                    valid_targets.append(target)
                except socket.gaierror:
                    invalid_targets.append(target)

        if invalid_targets:
            print(f"{Fore.RED}[-] Invalid targets: {', '.join(invalid_targets)}{Style.RESET_ALL}")

        self.targets = valid_targets
        return len(valid_targets) > 0

    def host_discovery(self):
        """Perform host discovery using optional ping and port-based detection"""
        print(f"\n{Fore.YELLOW}[+] Starting Host Discovery...{Style.RESET_ALL}")

        all_hosts = []

        for target in self.targets:
            print(f"{Fore.CYAN}[*] Processing target: {target}{Style.RESET_ALL}")

            try:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
            except ValueError:
                hosts = [target]

            all_hosts.extend([str(host) for host in hosts])

        all_hosts = list(set(all_hosts))
        live_hosts = set()
        ping_responsive = set()

        # Common ports for host discovery fallback
        discovery_ports = [80, 443, 22, 21, 25, 53, 135, 139, 445]

        def ping_host(host):
            try:
                response = os.system(f"ping -c 1 -W 2 {host} > /dev/null 2>&1")
                if response == 0:
                    return str(host)
            except:
                pass
            return None

        def port_discovery(host):
            """Try to connect to common ports to detect live hosts"""
            for port in discovery_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    if result == 0:
                        return str(host)
                except:
                    continue
            return None

        # Phase 1: Ping discovery (only if enabled)
        if self.enable_ping:
            print(f"{Fore.CYAN}[*] Phase 1: Ping discovery...{Style.RESET_ALL}")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(ping_host, host) for host in all_hosts]

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.add(result)
                        ping_responsive.add(result)
                        print(f"{Fore.GREEN}[+] Host discovered (ping): {result}{Style.RESET_ALL}")

            # For hosts that didn't respond to ping, try port-based discovery
            non_ping_hosts = [host for host in all_hosts if host not in ping_responsive]
        else:
            print(f"{Fore.CYAN}[*] Ping discovery disabled (use --ping to enable){Style.RESET_ALL}")
            # All hosts will be checked via port-based discovery
            non_ping_hosts = all_hosts

        # Phase 2: Port-based discovery
        if non_ping_hosts:
            phase_num = 2 if self.enable_ping else 1
            print(f"{Fore.CYAN}[*] Phase {phase_num}: Port-based discovery for {len(non_ping_hosts)} hosts...{Style.RESET_ALL}")
            with ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
                futures = [executor.submit(port_discovery, host) for host in non_ping_hosts]

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.add(result)
                        print(f"{Fore.GREEN}[+] Host discovered (port): {result}{Style.RESET_ALL}")

        live_hosts_list = list(live_hosts)
        unresponsive_count = len(all_hosts) - len(live_hosts_list)

        self.results["hosts"] = {host: {"status": "up", "ports": {}} for host in live_hosts_list}
        self.results["unresponsive_hosts"] = unresponsive_count
        print(f"\n{Fore.CYAN}[*] Host discovery completed. Found {len(live_hosts_list)} live hosts from {len(all_hosts)} total hosts.{Style.RESET_ALL}")
        if self.enable_ping:
            print(f"{Fore.CYAN}[*] Ping responsive: {len(ping_responsive)}, Port responsive: {len(live_hosts_list) - len(ping_responsive)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[*] All hosts discovered via port-based detection (ping disabled){Style.RESET_ALL}")

        return live_hosts_list

    def port_scan(self, hosts):
        """Perform port scanning on discovered hosts"""
        print(f"\n{Fore.YELLOW}[+] Starting Port Scanning...{Style.RESET_ALL}")

        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]

        def scan_port(host, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)  # Increased timeout for better detection
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    return port
            except:
                pass
            return None

        for host in hosts:
            print(f"\n{Fore.CYAN}[*] Scanning {host}...{Style.RESET_ALL}")
            open_ports = []

            # Ensure host is initialized in results
            if host not in self.results["hosts"]:
                self.results["hosts"][host] = {"status": "up", "ports": {}}

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(scan_port, host, port) for port in common_ports]

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        print(f"{Fore.GREEN}[+] Open port found: {host}:{result}{Style.RESET_ALL}")

            self.results["hosts"][host]["ports"] = {str(port): {"state": "open", "service": ""} for port in open_ports}

    def service_enumeration(self, hosts):
        """Perform service enumeration on open ports"""
        print(f"\n{Fore.YELLOW}[+] Starting Service Enumeration...{Style.RESET_ALL}")

        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "rpc", 139: "netbios", 143: "imap",
            443: "https", 993: "imaps", 995: "pop3s", 1723: "pptp",
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
            8080: "http-alt", 8443: "https-alt"
        }

        def enumerate_service(host, port):
            try:
                service = service_map.get(int(port), "unknown")

                if service in ["http", "https", "http-alt", "https-alt"]:
                    protocol = "https" if service in ["https", "https-alt"] else "http"
                    port_num = port if port not in ["80", "443"] else ""
                    url = f"{protocol}://{host}:{port_num}" if port_num else f"{protocol}://{host}"

                    try:
                        # Suppress SSL warnings and disable SSL verification for reconnaissance
                        response = requests.get(url, timeout=5, verify=False,
                                              headers={'User-Agent': 'PDIve/1.3'})
                        server_header = response.headers.get('Server', 'Unknown')
                        service_info = f"{service} ({server_header})"
                    except:
                        service_info = service
                else:
                    service_info = service

                return service_info
            except:
                return "unknown"

        for host in hosts:
            if host in self.results["hosts"]:
                for port in self.results["hosts"][host]["ports"]:
                    service_info = enumerate_service(host, port)
                    self.results["hosts"][host]["ports"][port]["service"] = service_info
                    print(f"{Fore.GREEN}[+] Service identified: {host}:{port} -> {service_info}{Style.RESET_ALL}")

    def passive_discovery(self):
        """Perform passive discovery using amass only"""
        print(f"\n{Fore.YELLOW}[+] Starting Passive Discovery (amass only)...{Style.RESET_ALL}")

        discovered_hosts = set()

        for target in self.targets:
            # Extract domain from target
            domain = self.extract_domain(target)
            if not domain:
                continue

            print(f"{Fore.CYAN}[*] Performing passive discovery on domain: {domain}{Style.RESET_ALL}")

            # Use amass for passive discovery
            amass_hosts = self.amass_discovery(domain)
            discovered_hosts.update(amass_hosts)

        discovered_hosts_list = list(discovered_hosts)

        # Add discovered hosts to results
        self.results["hosts"] = {host: {"status": "discovered", "ports": {}} for host in discovered_hosts_list}

        print(f"\n{Fore.CYAN}[*] Passive discovery completed. Found {len(discovered_hosts_list)} hosts.{Style.RESET_ALL}")

        return discovered_hosts_list

    def extract_domain(self, target):
        """Extract domain name from target"""
        try:
            # If it's an IP or CIDR, skip
            ipaddress.ip_network(target, strict=False)
            return None
        except ValueError:
            # It's likely a domain name
            return target.lower().strip()

    def amass_discovery(self, domain):
        """Use amass for passive subdomain enumeration"""
        discovered_hosts = set()

        try:
            print(f"{Fore.CYAN}[*] Running amass on {domain}...{Style.RESET_ALL}")

            # Check if amass is available - try multiple methods
            import subprocess
            import shutil

            # Try using shutil.which first (more reliable)
            amass_path = shutil.which('amass')
            if not amass_path:
                # Fallback to 'which' command
                try:
                    result = subprocess.run(['which', 'amass'], capture_output=True, text=True)
                    if result.returncode != 0:
                        print(f"{Fore.RED}[-] Amass not found in PATH, skipping amass discovery{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}[*] Install amass from: https://github.com/OWASP/Amass{Style.RESET_ALL}")
                        return discovered_hosts
                except FileNotFoundError:
                    print(f"{Fore.RED}[-] Amass not found, skipping amass discovery{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Install amass from: https://github.com/OWASP/Amass{Style.RESET_ALL}")
                    return discovered_hosts

            # Run amass with specified options (passive mode only)
            cmd = ['amass', 'enum', '-d', domain, '-passive']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                output_lines = result.stdout.strip().split('\n')
                if output_lines and any(line.strip() for line in output_lines):
                    for line in output_lines:
                        if line.strip():
                            discovered_hosts.add(line.strip())
                            print(f"{Fore.GREEN}[+] Amass discovered: {line.strip()}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[*] Amass completed but found no subdomains for {domain}{Style.RESET_ALL}")
            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                print(f"{Fore.RED}[-] Amass failed (exit code {result.returncode}): {error_msg}{Style.RESET_ALL}")

                # If amass fails, provide helpful debugging info
                if "config" in error_msg.lower() or "permission" in error_msg.lower():
                    print(f"{Fore.YELLOW}[*] Amass may need configuration. Try running 'amass enum -d {domain} -passive' manually{Style.RESET_ALL}")
                elif not error_msg:
                    print(f"{Fore.YELLOW}[*] Amass failed silently. This may be due to missing configuration or network issues{Style.RESET_ALL}")

                print(f"{Fore.YELLOW}[*] Continuing with other passive discovery methods...{Style.RESET_ALL}")

        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Amass timeout for domain {domain}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Amass error for {domain}: {e}{Style.RESET_ALL}")

        return discovered_hosts

    def dnsdumpster_discovery(self, domain):
        """Use dnsdumpster.com API for passive DNS discovery"""
        discovered_hosts = set()

        try:
            print(f"{Fore.CYAN}[*] Querying dnsdumpster for {domain}...{Style.RESET_ALL}")

            import re

            # DNSDumpster requires a session and CSRF token
            session = requests.Session()

            # Set realistic headers to avoid blocking
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }

            # Get the page to extract CSRF token
            url = 'https://dnsdumpster.com/'
            page = session.get(url, headers=headers, timeout=15)

            if page.status_code != 200:
                print(f"{Fore.RED}[-] Failed to access dnsdumpster.com (status: {page.status_code}){Style.RESET_ALL}")
                return discovered_hosts

            # Try multiple CSRF token patterns
            csrf_patterns = [
                r'name="csrfmiddlewaretoken" value="([^"]+)"',
                r'csrfmiddlewaretoken["\s]*:["\s]*([^"]+)',
                r'csrf_token["\s]*:["\s]*([^"]+)',
                r'<input[^>]*name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']'
            ]

            csrf_token = None
            for pattern in csrf_patterns:
                matches = re.findall(pattern, page.text)
                if matches:
                    csrf_token = matches[0]
                    break

            if not csrf_token:
                print(f"{Fore.RED}[-] Could not extract CSRF token from dnsdumpster{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] This may be due to rate limiting or site changes{Style.RESET_ALL}")
                return discovered_hosts

            # Submit the form
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': domain,
                'user': 'free'
            }

            # Update headers for POST request
            headers.update({
                'Referer': url,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'https://dnsdumpster.com'
            })

            response = session.post(url, data=data, headers=headers, timeout=30)

            if response.status_code == 200:
                # Parse the response for subdomains
                subdomain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*' + re.escape(domain)
                matches = re.findall(subdomain_pattern, response.text)

                for match in matches:
                    if isinstance(match, tuple):
                        subdomain = match[0] + domain if match[0] else domain
                    else:
                        subdomain = match

                    if subdomain and subdomain != domain:
                        discovered_hosts.add(subdomain)
                        print(f"{Fore.GREEN}[+] DNSDumpster discovered: {subdomain}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] DNSDumpster request failed with status {response.status_code}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] DNSDumpster error for {domain}: {e}{Style.RESET_ALL}")

        return discovered_hosts

    def crtsh_discovery(self, domain):
        """Use crt.sh certificate transparency logs for subdomain discovery"""
        discovered_hosts = set()

        try:
            print(f"{Fore.CYAN}[*] Querying crt.sh for {domain}...{Style.RESET_ALL}")

            import json

            # Query crt.sh API
            url = f'https://crt.sh/?q=%.{domain}&output=json'
            response = requests.get(url, timeout=30, headers={'User-Agent': 'PDIve/1.3'})

            if response.status_code == 200:
                try:
                    data = response.json()

                    for cert in data:
                        if 'name_value' in cert:
                            # Certificate can contain multiple domains
                            names = cert['name_value'].split('\n')

                            for name in names:
                                name = name.strip().lower()

                                # Filter out wildcards and invalid entries
                                if name and not name.startswith('*') and domain in name:
                                    discovered_hosts.add(name)
                                    print(f"{Fore.GREEN}[+] crt.sh discovered: {name}{Style.RESET_ALL}")

                except json.JSONDecodeError:
                    print(f"{Fore.RED}[-] Failed to parse crt.sh JSON response{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] crt.sh request failed with status {response.status_code}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] crt.sh error for {domain}: {e}{Style.RESET_ALL}")

        return discovered_hosts

    def masscan_scan(self, hosts):
        """Perform fast port scanning using masscan"""
        print(f"\n{Fore.YELLOW}[+] Starting Fast Port Scan (masscan)...{Style.RESET_ALL}")

        if not hosts:
            print(f"{Fore.RED}[-] No hosts provided for masscan{Style.RESET_ALL}")
            return {}

        import subprocess
        import shutil
        import json

        # Check if masscan is available
        masscan_path = shutil.which('masscan')
        if not masscan_path:
            print(f"{Fore.RED}[-] Masscan not found in PATH, falling back to basic port scan{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Install masscan from: https://github.com/robertdavidgraham/masscan{Style.RESET_ALL}")
            # Fallback to the original port_scan method
            self.port_scan(hosts)
            return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}

        # Check if we can run masscan with sudo (test sudo access)
        try:
            print(f"{Fore.CYAN}[*] Checking sudo access for masscan...{Style.RESET_ALL}")
            # Try to run masscan with --help to test sudo access without actually scanning
            test_cmd = ['sudo', '-n', 'masscan', '--help']
            test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=10)

            if test_result.returncode != 0:
                print(f"{Fore.YELLOW}[!] Masscan requires sudo privileges but no passwordless sudo access detected{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Run with 'sudo python3 pdive.py' or configure passwordless sudo for masscan{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
                self.port_scan(hosts)
                return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}
            else:
                print(f"{Fore.GREEN}[+] Sudo access confirmed for masscan{Style.RESET_ALL}")

        except (subprocess.TimeoutExpired, Exception) as e:
            print(f"{Fore.YELLOW}[!] Could not verify sudo access for masscan: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
            self.port_scan(hosts)
            return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}

        masscan_results = {}

        # Common ports to scan quickly
        port_range = "1-65535"

        try:
            # Create a temporary target file for masscan
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as target_file:
                for host in hosts:
                    target_file.write(f"{host}\n")
                target_file_path = target_file.name

            print(f"{Fore.CYAN}[*] Running masscan on {len(hosts)} hosts...{Style.RESET_ALL}")

            # Run masscan with output in list format (requires sudo for raw sockets)
            cmd = [
                'sudo', 'masscan',
                '-iL', target_file_path,
                '-p', port_range,
                '--rate', '1000',
                '--output-format', 'list',
                '--output-filename', '-'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Clean up temp file
            os.unlink(target_file_path)

            if result.returncode == 0:
                # Parse masscan output
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and not line.startswith('#'):
                        # Masscan list format: "open tcp 80 1.2.3.4 1234567890"
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == 'open' and parts[1] == 'tcp':
                            port = parts[2]
                            host = parts[3]

                            if host not in masscan_results:
                                masscan_results[host] = {}
                            masscan_results[host][port] = {"state": "open", "service": ""}

                            print(f"{Fore.GREEN}[+] Masscan found: {host}:{port}{Style.RESET_ALL}")

                print(f"\n{Fore.CYAN}[*] Masscan completed. Found ports on {len(masscan_results)} hosts.{Style.RESET_ALL}")

                # Update results with masscan findings
                for host in hosts:
                    if host not in self.results["hosts"]:
                        self.results["hosts"][host] = {"status": "up", "ports": {}}

                    if host in masscan_results:
                        self.results["hosts"][host]["ports"].update(masscan_results[host])

            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                print(f"{Fore.RED}[-] Masscan failed (exit code {result.returncode}): {error_msg}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
                self.port_scan(hosts)
                return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}

        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[-] Masscan timeout{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
            self.port_scan(hosts)
            return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}
        except Exception as e:
            print(f"{Fore.RED}[-] Masscan error: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Falling back to basic port scan...{Style.RESET_ALL}")
            self.port_scan(hosts)
            return {host: self.results["hosts"][host]["ports"] for host in hosts if host in self.results["hosts"]}

        return masscan_results

    def nmap_scan(self, masscan_results):
        """Perform detailed Nmap scan on masscan results for service enumeration"""
        if not HAS_NMAP:
            print(f"\n{Fore.RED}[-] Nmap module not available, skipping detailed service enumeration{Style.RESET_ALL}")
            return

        if not masscan_results:
            print(f"\n{Fore.YELLOW}[*] No masscan results to enumerate with nmap{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}[+] Starting Detailed Service Enumeration (Nmap)...{Style.RESET_ALL}")

        nm = nmap.PortScanner()

        for host, ports in masscan_results.items():
            if not ports:
                continue

            try:
                # Create port list from masscan results
                port_list = ','.join(ports.keys())
                print(f"{Fore.CYAN}[*] Nmap service scan on {host} ports: {port_list}{Style.RESET_ALL}")

                # Run nmap only on the ports that masscan found
                nm.scan(hosts=host, ports=port_list, arguments="-Pn -sV --version-intensity 7")

                for scanned_host in nm.all_hosts():
                    if scanned_host not in self.results["hosts"]:
                        self.results["hosts"][scanned_host] = {"status": "up", "ports": {}}

                    # Add OS detection results if available
                    if nm[scanned_host].get('osmatch'):
                        self.results["hosts"][scanned_host]["os"] = nm[scanned_host]['osmatch']

                    for protocol in nm[scanned_host].all_protocols():
                        nmap_ports = nm[scanned_host][protocol].keys()
                        for port in nmap_ports:
                            port_info = nm[scanned_host][protocol][port]
                            service_name = port_info.get('name', 'unknown')
                            service_version = port_info.get('version', '')
                            service_product = port_info.get('product', '')

                            # Build comprehensive service info
                            service_details = service_name
                            if service_product:
                                service_details += f" ({service_product}"
                                if service_version:
                                    service_details += f" {service_version}"
                                service_details += ")"
                            elif service_version:
                                service_details += f" {service_version}"

                            # Update the existing port info from masscan with detailed nmap results
                            if str(port) in self.results["hosts"][scanned_host]["ports"]:
                                self.results["hosts"][scanned_host]["ports"][str(port)]["service"] = service_details
                                self.results["hosts"][scanned_host]["ports"][str(port)]["state"] = port_info['state']
                            else:
                                # This shouldn't happen if masscan worked correctly, but add it anyway
                                self.results["hosts"][scanned_host]["ports"][str(port)] = {
                                    "state": port_info['state'],
                                    "service": service_details
                                }

                            print(f"{Fore.GREEN}[+] Nmap service: {scanned_host}:{port} -> {service_details}{Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.RED}[-] Nmap scan failed for {host}: {e}{Style.RESET_ALL}")

    def enumerate_basic_service(self, host, port):
        """Perform basic service enumeration without nmap"""
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "rpc", 139: "netbios", 143: "imap",
            443: "https", 993: "imaps", 995: "pop3s", 1723: "pptp",
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
            8080: "http-alt", 8443: "https-alt"
        }

        try:
            service = service_map.get(int(port), "unknown")

            if service in ["http", "https", "http-alt", "https-alt"]:
                protocol = "https" if service in ["https", "https-alt"] else "http"
                port_num = port if port not in ["80", "443"] else ""
                url = f"{protocol}://{host}:{port_num}" if port_num else f"{protocol}://{host}"

                try:
                    response = requests.get(url, timeout=5, verify=False,
                                          headers={'User-Agent': 'PDIve/1.3'})
                    server_header = response.headers.get('Server', 'Unknown')
                    service_info = f"{service} ({server_header})"
                except:
                    service_info = service
            else:
                service_info = service

            return service_info
        except:
            return "unknown"

    def resolve_domain_to_ip(self, hostname):
        """Resolve domain name to IP address"""
        try:
            # Check if the hostname is already an IP address
            ipaddress.ip_address(hostname)
            return hostname  # Already an IP address
        except ValueError:
            # It's a hostname, try to resolve it
            try:
                ip_address = socket.gethostbyname(hostname)
                return ip_address
            except socket.gaierror:
                return "N/A"  # Resolution failed

    def reverse_dns_lookup(self, ip_address):
        """Perform reverse DNS lookup on IP address"""
        try:
            # Validate that it's actually an IP address
            ipaddress.ip_address(ip_address)

            # Perform reverse DNS lookup
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.herror, socket.gaierror, ValueError):
            return "N/A"  # Reverse lookup failed or invalid IP

    def generate_report(self):
        """Generate comprehensive scan reports in text and CSV format"""
        print(f"\n{Fore.YELLOW}[+] Generating Reports...{Style.RESET_ALL}")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        end_time = datetime.now().isoformat()

        total_hosts = len(self.results["hosts"])
        total_ports = sum(len(host_data["ports"]) for host_data in self.results["hosts"].values())

        # Extract the directory name to use as prefix
        dir_name = os.path.basename(self.output_dir)

        # Generate detailed text report
        txt_file = os.path.join(self.output_dir, f"{dir_name}_report_{timestamp}.txt")
        with open(txt_file, 'w') as f:
            f.write("PDIVE DETAILED SCAN REPORT\n")
            f.write("=" * 60 + "\n\n")

            # Summary section
            f.write("SCAN SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write("Targets:\n")
            for target in self.targets:
                f.write(f"  {target}\n")
            f.write(f"\nScan Start Time: {self.results['scan_info']['start_time']}\n")
            f.write(f"Scan End Time: {end_time}\n")
            f.write(f"Scanner Version: {self.results['scan_info']['scanner']}\n")
            f.write(f"Total Live Hosts: {total_hosts}\n")
            f.write(f"Total Open Ports: {total_ports}\n")
            f.write(f"Unresponsive Hosts: {self.results['unresponsive_hosts']}\n\n")

            # Detailed results section
            f.write("DETAILED RESULTS\n")
            f.write("-" * 20 + "\n")
            if self.results["hosts"]:
                for host, data in self.results["hosts"].items():
                    # Resolve domain to IP address
                    ip_address = self.resolve_domain_to_ip(host)

                    # Perform reverse DNS lookup on the IP address
                    reverse_dns = self.reverse_dns_lookup(ip_address) if ip_address != "N/A" else "N/A"

                    f.write(f"\nHost: {host}")
                    if ip_address != host and ip_address != "N/A":
                        f.write(f" ({ip_address})")
                    f.write("\n")

                    # Add reverse DNS information if available and different from host
                    if reverse_dns != "N/A" and reverse_dns != host:
                        f.write(f"Reverse DNS: {reverse_dns}\n")

                    f.write("=" * (len(host) + 6 + (len(ip_address) + 3 if ip_address != host and ip_address != "N/A" else 0)) + "\n")

                    if data["ports"]:
                        f.write("Open Ports:\n")
                        for port, port_data in data["ports"].items():
                            service = port_data.get('service', 'unknown')
                            f.write(f"  {port:>5}/tcp  {service}\n")
                    else:
                        f.write("  No open ports detected\n")
            else:
                f.write("No live hosts discovered\n")

        # Generate CSV report
        csv_file = os.path.join(self.output_dir, f"{dir_name}_results_{timestamp}.csv")
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)

            # CSV Headers
            writer.writerow(['Host', 'IP_Address', 'Reverse_DNS', 'Port', 'Protocol', 'State', 'Service', 'Scan_Time'])

            # CSV Data
            scan_time = self.results['scan_info']['start_time']
            if self.results["hosts"]:
                for host, data in self.results["hosts"].items():
                    # Resolve domain to IP address
                    ip_address = self.resolve_domain_to_ip(host)

                    # Perform reverse DNS lookup on the IP address
                    reverse_dns = self.reverse_dns_lookup(ip_address) if ip_address != "N/A" else "N/A"

                    if data["ports"]:
                        for port, port_data in data["ports"].items():
                            writer.writerow([
                                host,
                                ip_address,
                                reverse_dns,
                                port,
                                'tcp',
                                port_data.get('state', 'open'),
                                port_data.get('service', 'unknown'),
                                scan_time
                            ])
                    else:
                        # Host is up but no ports detected
                        writer.writerow([host, ip_address, reverse_dns, '', '', 'host_up', 'no_open_ports', scan_time])

        print(f"{Fore.GREEN}[+] Reports saved to:{Style.RESET_ALL}")
        print(f"  - Detailed Report: {txt_file}")
        print(f"  - CSV Data: {csv_file}")

    def generate_passive_report(self):
        """Generate simple report for passive discovery mode"""
        print(f"\n{Fore.YELLOW}[+] Generating Passive Discovery Report...{Style.RESET_ALL}")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        end_time = datetime.now().isoformat()

        total_hosts = len(self.results["hosts"])

        # Extract the directory name to use as prefix
        dir_name = os.path.basename(self.output_dir)

        # Generate simple text report for passive mode
        txt_file = os.path.join(self.output_dir, f"{dir_name}_passive_{timestamp}.txt")
        with open(txt_file, 'w') as f:
            f.write("PDIVE PASSIVE DISCOVERY REPORT\n")
            f.write("=" * 60 + "\n\n")

            # Summary section
            f.write("DISCOVERY SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write("Targets:\n")
            for target in self.targets:
                f.write(f"  {target}\n")
            f.write(f"\nScan Start Time: {self.results['scan_info']['start_time']}\n")
            f.write(f"Scan End Time: {end_time}\n")
            f.write(f"Scanner Version: {self.results['scan_info']['scanner']}\n")
            f.write(f"Discovery Mode: {self.results['scan_info']['discovery_mode'].upper()}\n")
            f.write(f"Total Discovered Hosts: {total_hosts}\n\n")

            # Host list section
            f.write("DISCOVERED HOSTS\n")
            f.write("-" * 20 + "\n")
            if self.results["hosts"]:
                for host in sorted(self.results["hosts"].keys()):
                    # Resolve domain to IP address
                    ip_address = self.resolve_domain_to_ip(host)

                    # Perform reverse DNS lookup on the IP address
                    reverse_dns = self.reverse_dns_lookup(ip_address) if ip_address != "N/A" else "N/A"

                    if ip_address != host and ip_address != "N/A":
                        if reverse_dns != "N/A" and reverse_dns != host and reverse_dns != ip_address:
                            f.write(f"{host} ({ip_address}) [rDNS: {reverse_dns}]\n")
                        else:
                            f.write(f"{host} ({ip_address})\n")
                    else:
                        f.write(f"{host}\n")
            else:
                f.write("No hosts discovered\n")

        # Generate simple CSV with just hostnames
        csv_file = os.path.join(self.output_dir, f"{dir_name}_hosts_{timestamp}.csv")
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)

            # CSV Headers
            writer.writerow(['Host', 'IP_Address', 'Reverse_DNS', 'Discovery_Method', 'Scan_Time'])

            # CSV Data
            scan_time = self.results['scan_info']['start_time']
            if self.results["hosts"]:
                for host, data in self.results["hosts"].items():
                    # Resolve domain to IP address
                    ip_address = self.resolve_domain_to_ip(host)

                    # Perform reverse DNS lookup on the IP address
                    reverse_dns = self.reverse_dns_lookup(ip_address) if ip_address != "N/A" else "N/A"

                    discovery_method = data.get('discovery_method', 'passive')
                    writer.writerow([host, ip_address, reverse_dns, discovery_method, scan_time])

        print(f"{Fore.GREEN}[+] Passive discovery reports saved to:{Style.RESET_ALL}")
        print(f"  - Host List Report: {txt_file}")
        print(f"  - CSV Host List: {csv_file}")

    def run_scan(self, enable_nmap=False):
        """Execute complete reconnaissance scan"""
        if not self.validate_targets():
            print(f"{Fore.RED}[-] No valid targets found{Style.RESET_ALL}")
            return

        self.print_banner()

        # Inform user about ping setting
        if not self.enable_ping and self.discovery_mode == "active":
            print(f"{Fore.YELLOW}[!] Ping is disabled by default. Use --ping to enable ICMP ping discovery.{Style.RESET_ALL}")

        if self.discovery_mode == "passive":
            # Passive discovery mode - use passive techniques only
            discovered_hosts = self.passive_discovery()
            if not discovered_hosts:
                print(f"{Fore.RED}[-] No hosts discovered through passive methods.{Style.RESET_ALL}")
                return

            # In passive mode, only return the list of discovered hosts
            print(f"\n{Fore.YELLOW}[+] PASSIVE DISCOVERY RESULTS{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Total hosts discovered: {len(discovered_hosts)}{Style.RESET_ALL}\n")

            print(f"{Fore.GREEN}Discovered hosts:{Style.RESET_ALL}")
            for host in sorted(discovered_hosts):
                print(f"{host}")

            # Generate simple report for passive mode
            self.generate_passive_report()

        else:
            # Active discovery mode - amass -> host discovery -> masscan -> nmap
            print(f"\n{Fore.YELLOW}[+] Starting Active Discovery Mode{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Phase 1: Passive subdomain discovery with amass{Style.RESET_ALL}")

            # First, run amass to discover subdomains
            amass_hosts = self.passive_discovery()

            # Then do traditional host discovery
            print(f"\n{Fore.CYAN}[*] Phase 2: Host discovery and connectivity check{Style.RESET_ALL}")
            live_hosts = self.host_discovery()

            # Combine amass results with live host discovery
            all_discovered_hosts = set(amass_hosts + live_hosts)

            if not all_discovered_hosts:
                print(f"{Fore.RED}[-] No live hosts discovered.{Style.RESET_ALL}")
                return

            # Ensure all discovered hosts are initialized in results before proceeding
            for host in all_discovered_hosts:
                if host not in self.results["hosts"]:
                    self.results["hosts"][host] = {"status": "up", "ports": {}}

            print(f"\n{Fore.CYAN}[*] Phase 3: Fast port scanning with masscan{Style.RESET_ALL}")
            # Use masscan for fast port discovery
            masscan_results = self.masscan_scan(list(all_discovered_hosts))

            if enable_nmap and masscan_results:
                print(f"\n{Fore.CYAN}[*] Phase 4: Detailed service enumeration with nmap{Style.RESET_ALL}")
                self.nmap_scan(masscan_results)
            elif masscan_results:
                # If nmap is not enabled, do basic service enumeration on masscan results
                print(f"\n{Fore.CYAN}[*] Phase 4: Basic service identification{Style.RESET_ALL}")
                for host in all_discovered_hosts:
                    if host in self.results["hosts"]:
                        for port in self.results["hosts"][host]["ports"]:
                            service_info = self.enumerate_basic_service(host, port)
                            self.results["hosts"][host]["ports"][port]["service"] = service_info
                            print(f"{Fore.GREEN}[+] Service identified: {host}:{port} -> {service_info}{Style.RESET_ALL}")

            # Generate full report for active mode
            self.generate_report()

        print(f"\n{Fore.GREEN}[+] Reconnaissance scan completed!{Style.RESET_ALL}")


def load_targets_from_file(file_path):
    """Load targets from a text file, one per line"""
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                target = line.strip()
                if target and not target.startswith('#'):
                    targets.append(target)
        return targets
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Target file not found: {file_path}{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[-] Error reading target file: {e}{Style.RESET_ALL}")
        return []


def main():
    parser = argparse.ArgumentParser(
        description="PDIve - Automated Penetration Testing Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pdive.py -t 192.168.1.0/24
  python pdive.py -t 10.0.0.1 --nmap
  python pdive.py -t 192.168.1.0/24 --ping
  python pdive.py -f targets.txt -o /tmp/scan_results -T 100
  python pdive.py -t "192.168.1.1,example.com,10.0.0.0/24"
  python pdive.py -t example.com -m passive
  python pdive.py -t testphp.vulnweb.com -m active --nmap --ping
        """
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target',
                             help='Target IP address, hostname, CIDR range, or comma-separated list')
    target_group.add_argument('-f', '--file',
                             help='File containing targets (one per line)')

    parser.add_argument('-o', '--output', default='pdive_output',
                       help='Output directory (default: pdive_output)')
    parser.add_argument('-T', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('-m', '--mode', choices=['active', 'passive'], default='active',
                       help='Discovery mode: active (default) or passive')
    parser.add_argument('--nmap', action='store_true',
                       help='Enable detailed Nmap scanning (Active mode only)')
    parser.add_argument('--ping', action='store_true',
                       help='Enable ICMP ping for host discovery (disabled by default for stealth)')
    parser.add_argument('--version', action='version', version='PDIve 1.3')

    args = parser.parse_args()

    # Validate mode and nmap combination
    if args.mode == 'passive' and args.nmap:
        print(f"{Fore.RED}[-] Error: --nmap flag is not compatible with passive mode{Style.RESET_ALL}")
        sys.exit(1)

    if args.file:
        targets = load_targets_from_file(args.file)
        if not targets:
            print(f"{Fore.RED}[-] No valid targets found in file{Style.RESET_ALL}")
            sys.exit(1)
    else:
        if ',' in args.target:
            targets = [t.strip() for t in args.target.split(',') if t.strip()]
        else:
            targets = [args.target]

    print(f"{Fore.RED}WARNING: This tool is for authorized security testing only!{Style.RESET_ALL}")
    print(f"{Fore.RED}Ensure you have proper permission before scanning any network.{Style.RESET_ALL}\n")

    targets_display = ', '.join(targets[:3])
    if len(targets) > 3:
        targets_display += f" ... (+{len(targets) - 3} more)"

    print(f"Targets to scan: {targets_display}")
    response = input("Do you have authorization to scan these targets? (y/N): ")
    if response.lower() != 'y':
        print("Scan aborted.")
        sys.exit(1)

    pdive = PDIve(targets, args.output, args.threads, args.mode, enable_ping=args.ping)
    pdive.run_scan(enable_nmap=args.nmap)


if __name__ == "__main__":
    main()