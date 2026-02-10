# PDIve Usage

`pdive.py` is a CLI tool for authorized network reconnaissance.

## Basic Syntax

```bash
python pdive.py -t <target> [options]
python pdive.py -f <targets_file> [options]
```

## Targets

- Single host: `-t 10.0.0.5`
- CIDR range: `-t 192.168.1.0/24`
- Domain: `-t example.com`
- Multiple targets: `-t "192.168.1.10,example.com,10.0.0.0/24"`
- File input: `-f targets.txt` (one target per line, `#` for comments)

## Common Options

- `-o, --output <dir>`: Output directory (default: `pdive_output`)
- `-T, --threads <n>`: Thread count, `1-1000` (default: `50`)
- `-m, --mode <active|passive>`: Discovery mode (default: `active`)
- `--ping`: Enable ICMP ping discovery (disabled by default)
- `--masscan`: Active mode only; skip passive discovery and run fast port scan + basic service detection
- `--nmap`: Active mode only; run detailed nmap service enumeration after masscan
- `--amass-timeout <seconds>`: Timeout for amass (range: `1-3600`)
- `--version`: Show version

## Mode Behavior

### Active Mode (`-m active`)

Pipeline:
1. Optional amass passive subdomain discovery
2. Host discovery (ping if enabled, otherwise port-based)
3. Masscan fast port scan (fallback to built-in port scan if unavailable)
4. Service identification (basic, or detailed with `--nmap`)
5. Full report generation (TXT + CSV)

### Passive Mode (`-m passive`)

Pipeline:
1. Passive host discovery via amass
2. Host list output
3. Passive report generation (TXT + CSV)

## Example Commands

### Active scans

```bash
python pdive.py -t 192.168.1.0/24
python pdive.py -t 10.0.0.1 --ping
python pdive.py -t 10.0.0.1 --nmap
python pdive.py -t 192.168.1.0/24 --masscan
python pdive.py -t testphp.vulnweb.com -m active --nmap --ping -T 50
```

### Passive scans

```bash
python pdive.py -t example.com -m passive
python pdive.py -t example.com -m passive --amass-timeout 300
```

### Target file + custom output

```bash
python pdive.py -f targets.txt -o ./scan_results -T 100
```

## Incompatible Flag Combinations

- `--nmap` cannot be used with `-m passive`
- `--masscan` cannot be used with `-m passive`
- `--nmap` and `--masscan` cannot be used together

## Output Files

### Active mode

- `<output_dir>/<dirname>_report_<timestamp>.txt`
- `<output_dir>/<dirname>_results_<timestamp>.csv`

### Passive mode

- `<output_dir>/<dirname>_passive_<timestamp>.txt`
- `<output_dir>/<dirname>_hosts_<timestamp>.csv`

## Notes

- The tool prompts for authorization before scanning.
- Some features depend on external binaries/modules (`amass`, `masscan`, `python-nmap`, `python-whois`, `requests`, `colorama`).
- Run only against assets you are explicitly authorized to test.
