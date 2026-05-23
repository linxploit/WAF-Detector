<div align="center">

```
██╗    ██╗ █████╗ ███████╗      ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗
██║    ██║██╔══██╗██╔════╝      ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
██║ █╗ ██║███████║█████╗        ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝
██║███╗██║██╔══██║██╔══╝        ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
╚███╔███╔╝██║  ██║██║           ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝           ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

# 🛡️ WAF Detector

**Advanced Web Application Firewall & Network Protection Fingerprinting Tool**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Rich](https://img.shields.io/badge/UI-Rich%20TUI-red?style=flat-square)](https://github.com/Textualize/rich)
[![Async](https://img.shields.io/badge/Execution-Concurrent%20Threads-orange?style=flat-square)]()
[![WAFs](https://img.shields.io/badge/WAF%20Signatures-15%2B-purple?style=flat-square)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()

*Identify, fingerprint, and analyze Web Application Firewalls and network-layer protections with surgical precision.*

---

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Output](#-output-modes) · [WAF Coverage](#-waf-coverage) · [Ethics](#-ethical-use)

</div>

---

## 🔍 Overview

**WAF Detector** is a production-grade CLI tool built for penetration testers, security researchers, and red team operators who need fast, reliable WAF fingerprinting during reconnaissance. It fires concurrent multi-vector HTTP probes — manipulating headers, injecting payloads, and varying user agents — then cross-references every response against a curated signature database covering **15+ WAF and CDN products**.

Results are rendered in a clean, color-coded terminal interface powered by `rich`, and can be exported as structured JSON for downstream tooling or reporting pipelines.

---

## ✨ Features

| Capability | Detail |
|---|---|
| **Multi-vector Probing** | Sends 12+ concurrent HTTP probes: payload injection, header manipulation, user-agent rotation |
| **Signature Detection** | Matches headers, cookies, server strings, response bodies, and HTTP status codes |
| **Confidence Scoring** | Rates each detection as `LOW` → `MEDIUM` → `HIGH` → `VERY HIGH` based on evidence count |
| **Port Scanning** | Probes 9 known firewall-indicative ports with configurable timeout |
| **Concurrent Execution** | `ThreadPoolExecutor`-powered — all probes and port checks run in parallel |
| **Rich TUI** | Live progress bar, color-coded tables, panel layouts — no raw print statements |
| **JSON Export** | Machine-readable structured report for SIEM, reporting, or pipeline integration |
| **Quiet Mode** | Emits raw JSON only — pipe-safe for `jq`, `grep`, `tee`, or custom parsers |
| **Defensive Validation** | Input sanitized against control characters, RFC hostname rules, and path traversal |
| **POSIX Exit Codes** | `0` success · `1` runtime error · `2` CLI/validation error |

---

## 🖥️ Installation

### Prerequisites

- Python **3.9** or higher
- `pip` package manager

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/linxploit/waf-detector.git
cd waf-detector

# 2. (Recommended) Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python main.py https://example.com
```

### Dependencies

```
requests>=2.31.0
urllib3>=2.0.0
rich>=13.7.0
```

---

## 🚀 Usage

### Basic Scan

```bash
python main.py https://target.com
```

### Full Argument Reference

```
usage: waf-detector [-h] [-o FILE] [--timeout SECONDS] [--workers N]
                    [--no-port-scan] [--port-timeout SECONDS] [-v] [-q]
                    [URL]

positional arguments:
  URL                   Target URL to scan (e.g. https://example.com)

options:
  -h, --help            Show this help message and exit
  -o, --output FILE     Export JSON report to FILE
  --timeout SECONDS     Per-request timeout in seconds (default: 10)
  --workers N           Concurrent worker threads (default: 8)
  --no-port-scan        Skip firewall port scanning
  --port-timeout SECS   Per-port connect timeout (default: 1.0)
  -v, --verbose         Enable debug logging
  -q, --quiet           Suppress all output — emit raw JSON only
```

### Usage Examples

```bash
# Interactive mode (no arguments — prompts for target)
python main.py

# Standard scan with JSON export
python main.py https://example.com -o report.json

# High-speed scan — 16 workers, short timeouts
python main.py https://example.com --timeout 5 --workers 16

# Skip port scan for stealth / speed
python main.py https://example.com --no-port-scan

# Debug mode — see every probe logged
python main.py https://example.com -v

# Pipe-safe quiet mode — raw JSON to stdout
python main.py https://example.com -q | jq '.detected_wafs'

# Quiet mode + save to file simultaneously
python main.py https://example.com -q -o scan_$(date +%s).json
```

---

## 📊 Output Modes

### Standard TUI Output

```
╭─────────────────────────────────────────────╮
│  WAF / FIREWALL DETECTOR                    │
│  Target : https://example.com              │
│  Domain : example.com                      │
│  Scan ID: 20250115_142301                  │
╰─────────────────────────────────────────────╯

  Probing sending requests… ████████████ 14/14  [0:00:03]

╭─ WAF / Firewall Detection Results ──────────────────────────────╮
│ WAF / Product     │ Confidence │ Evidence             │ Sources  │
│ Cloudflare        │  VERY HIGH │ • Header: cf-ray: …  │ header,  │
│                   │            │ • Cookie: __cfruid   │ cookie,  │
│                   │            │ • Server: cloudflare │ server   │
╰──────────────────────────────────────────────────────────────────╯

── Recommendations ───────────────────────────────────────────────
[✓] Cloudflare — verify WAF rules are set to an appropriate level.
[Pentest Notes] IP rotation, payload obfuscation, rate-limit evasion

Scan ID: 20250115_142301  Duration: 3.41s  Probes sent: 14  WAFs found: 1
```

### Quiet Mode JSON Output

```json
{
  "scan_id": "20250115_142301",
  "target": "https://example.com",
  "domain": "example.com",
  "timestamp": "2025-01-15T14:23:01.442310",
  "duration_seconds": 3.412,
  "detected_wafs": [
    {
      "waf": "Cloudflare",
      "evidence": ["Header: cf-ray: ...", "Cookie: __cfruid", "Server: cloudflare"],
      "confidence": "VERY HIGH",
      "sources": ["header", "cookie", "server"]
    }
  ],
  "open_firewall_ports": [],
  "normal_response": {
    "status_code": 200,
    "server": "cloudflare",
    "content_type": "text/html; charset=UTF-8",
    "response_size_bytes": 4821,
    "elapsed_seconds": 0.318
  }
}
```

---

## 🛡️ WAF Coverage

| # | WAF / CDN Product | Detection Vectors |
|---|---|---|
| 1 | **Cloudflare** | Headers, Cookies, Server, Body, Status |
| 2 | **AWS WAF** | Headers, Cookies, Body, Status |
| 3 | **AWS CloudFront** | Headers, Cookies, Server, Status |
| 4 | **Akamai** | Headers, Cookies, Server, Status |
| 5 | **Imperva / Incapsula** | Headers, Cookies, Server, Body, Status |
| 6 | **Sucuri CloudProxy** | Headers, Cookies, Server, Body, Status |
| 7 | **F5 BIG-IP ASM** | Headers, Cookies, Server, Body, Status |
| 8 | **ModSecurity** | Headers, Server, Body, Status |
| 9 | **Citrix NetScaler** | Headers, Cookies, Server, Body, Status |
| 10 | **Barracuda WAF** | Headers, Cookies, Server, Body, Status |
| 11 | **Palo Alto NGFW** | Headers, Cookies, Server, Body, Status |
| 12 | **Fortinet FortiWeb** | Headers, Cookies, Server, Body, Status |
| 13 | **Wordfence** | Headers, Cookies, Body, Status |
| 14 | **StackPath** | Headers, Cookies, Server, Body, Status |
| 15 | **Varnish Cache** | Headers, Server, Body, Status |

### Port Fingerprinting

| Port | Indicated Product |
|---|---|
| `22` | SSH Filtering |
| `443` | SSL Inspection |
| `8080` | Proxy Firewall |
| `8443` | SSL Inspection |
| `5000` | UPnP Firewall |
| `5900` | VNC Filtering |
| `31337` | Norton Personal Firewall |
| `32764` | Linksys Firewall |
| `41121` | Panda Security |

---

## ⚙️ Architecture

```
main.py
  │
  ├── build_arg_parser()        # argparse configuration & type validators
  ├── validate_target()         # RFC-compliant URL/hostname sanitization
  │
  ├── collect_probes()          # ThreadPoolExecutor — parallel HTTP probing
  │     ├── fetch_probe()       # Single probe: payload or header variant
  │     └── Progress bar        # Live rich TUI progress (suppressed in -q)
  │
  ├── detect_wafs()             # Orchestrates analysis pipeline
  │     ├── analyze_headers()   # Header + cookie + server matching
  │     ├── analyze_body()      # Response body + status code matching
  │     └── consolidate_findings()  # Dedup, merge, confidence scoring
  │
  ├── check_firewall_ports()    # Parallel TCP port probing
  │
  ├── build_json_report()       # Structured report assembly
  │
  └── render_*()                # Rich TUI rendering (tables, panels, rules)
```

---

## 🔒 Ethical Use

This tool is intended **exclusively** for:

- Authorized penetration testing engagements
- Security assessment of infrastructure you own or have explicit written permission to test
- Academic and CTF research environments
- Red team operations within defined scope

**Do not use this tool against systems you do not own or have explicit authorization to test.** Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, GDPR provisions, and equivalent legislation in your jurisdiction.

The authors assume **zero liability** for misuse. You are solely responsible for ensuring your usage is lawful.

---

## 📁 Project Structure

```
waf-detector/
├── main.py            # Core tool — all logic, CLI, TUI, detection engine
├── requirements.txt   # Python dependencies
├── README.md          # This file
├── .gitignore         # Python + scan output exclusions
└── LICENSE            # MIT License
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-waf-signature`
3. Commit your changes: `git commit -m 'Add Fastly WAF signatures'`
4. Push to the branch: `git push origin feature/new-waf-signature`
5. Open a Pull Request

When adding new WAF signatures, follow the existing `WAF_SIGNATURES` dict schema in `main.py` and include at least 3 detection vectors.

---

## 📄 License

Released under the **MIT License** — see [LICENSE](LICENSE) for full terms.

---

<div align="center">

Built with precision by **ICAT Project** · [Linxploit.xyz](https://linxploit.xyz)

*For authorized security research only.*

</div>