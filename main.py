#!/usr/bin/env python3

from __future__ import annotations

Thurruruurur

import argparse
import asyncio
import ipaddress
import json
import logging
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console(stderr=False)

WAF_SIGNATURES: dict[str, dict[str, list]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "cloudflare"],
        "cookies": ["__cfduid", "__cfruid"],
        "response": ["cloudflare", "cf-ray", "attention required"],
        "server": ["cloudflare"],
        "block_codes": [403, 503, 520, 521, 522, 523, 524],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amzn-errortype", "x-amz-cf-id", "x-amz-cf-pop"],
        "cookies": ["AWSALB", "AWSALBCORS"],
        "response": ["amazon", "aws", "waf"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-cloudfront-request-id"],
        "cookies": ["CloudFront-Policy", "CloudFront-Signature"],
        "server": ["CloudFront", "Amazon"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "Akamai": {
        "headers": ["x-akamai-request-id", "x-akamai-session-info", "x-akamai-transformed"],
        "cookies": ["akaalb", "ak_bmsc", "bm_sz"],
        "server": ["Akamai", "AkamaiGHost"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "Imperva/Incapsula": {
        "headers": ["x-cdn", "x-iinfo", "incap_s", "visid_incap"],
        "cookies": ["incap_ses_", "visid_incap_", "incap_visid_"],
        "server": ["Imperva", "Incapsula"],
        "response": ["incapsula", "imperva"],
        "block_codes": [403, 404, 500, 502, 503, 508],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
        "cookies": ["sucuri_cloudproxy"],
        "server": ["Sucuri"],
        "response": ["sucuri", "cloudproxy"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-wa-info", "x-asm-request-id", "x-f5-new-authenticated"],
        "cookies": ["TS", "BIGipServer", "ASM"],
        "server": ["BIG-IP", "F5"],
        "response": ["the requested url was rejected", "please consult with your administrator"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "ModSecurity": {
        "headers": ["x-mod-security", "x-mod-sec-req-id"],
        "cookies": [],
        "server": ["modsecurity", "mod_security"],
        "response": ["mod_security", "modsecurity", "web application firewall", "request blocked"],
        "block_codes": [403, 406, 500],
    },
    "Citrix NetScaler": {
        "headers": ["x-netscaler-request-id", "via"],
        "cookies": ["NSC_", "citrix"],
        "server": ["NetScaler", "Citrix"],
        "response": ["netscaler", "citrix"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "Barracuda": {
        "headers": ["x-barracuda-request-id", "x-barracuda-block"],
        "cookies": ["barra"],
        "server": ["Barracuda"],
        "response": ["barracuda", "blocked by"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "Palo Alto": {
        "headers": ["x-paloalto-request-id"],
        "cookies": ["PAN"],
        "server": ["PaloAlto", "PAN"],
        "response": ["palo alto", "blocked"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "Fortinet": {
        "headers": ["x-fortinet-request-id"],
        "cookies": ["Forti"],
        "server": ["Fortinet", "FortiWeb"],
        "response": ["fortinet", "fortiweb"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "Wordfence": {
        "headers": ["x-wordfence"],
        "cookies": ["wfvt_", "wordfence_"],
        "server": [],
        "response": ["wordfence", "blocked by wordfence"],
        "block_codes": [403, 404, 500],
    },
    "StackPath": {
        "headers": ["x-stackpath-request-id"],
        "cookies": ["stackpath"],
        "server": ["StackPath"],
        "response": ["stackpath"],
        "block_codes": [403, 404, 500, 502, 503],
    },
    "Varnish": {
        "headers": ["x-varnish", "via"],
        "cookies": [],
        "server": ["Varnish"],
        "response": ["varnish"],
        "block_codes": [403, 404, 500, 502, 503],
    },
}

FIREWALL_PORTS: dict[int, str] = {
    22: "SSH Filtering",
    443: "SSL Inspection",
    8080: "Proxy Firewall",
    8443: "SSL Inspection",
    31337: "Norton Personal Firewall",
    32764: "Linksys Firewall",
    41121: "Panda Security",
    5000: "UPnP Firewall",
    5900: "VNC Filtering",
}

PROBE_PAYLOADS: list[str] = [
    "",
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "?id=1 UNION SELECT * FROM users",
    "?page=../../../../etc/passwd",
    "?id=1 AND 1=1",
    "?id=1 AND 1=2",
    "?q='><script>alert('XSS')</script>",
    "?q={{7*7}}",
]

PROBE_HEADERS: list[dict[str, str]] = [
    {"User-Agent": "Mozilla/5.0"},
    {"User-Agent": '() { :; }; /bin/bash -c "echo vulnerable"'},
    {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "127.0.0.1"},
    {"User-Agent": "Mozilla/5.0", "Referer": "https://evil.com"},
    {"User-Agent": "Mozilla/5.0", "X-Originating-IP": "127.0.0.1"},
    {"User-Agent": "Mozilla/5.0", "X-Remote-IP": "127.0.0.1"},
    {"User-Agent": "Mozilla/5.0", "X-Remote-Addr": "127.0.0.1"},
    {"User-Agent": "Mozilla/5.0", "X-Forwarded-Host": "127.0.0.1"},
]


@dataclass
class Finding:
    waf: str
    evidence: str
    confidence: str
    source: str


@dataclass
class ConsolidatedWAF:
    waf: str
    evidence: list[str] = field(default_factory=list)
    confidence: str = "LOW"
    sources: list[str] = field(default_factory=list)


@dataclass
class ProbeResult:
    key: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed: float


@dataclass
class ScanResult:
    scan_id: str
    target: str
    domain: str
    timestamp: str
    duration: float
    detected_wafs: list[dict]
    open_firewall_ports: list[dict]
    normal_response: Optional[dict]


def setup_logging(verbose: bool, quiet: bool) -> logging.Logger:
    level = logging.WARNING
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.CRITICAL

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=Console(stderr=True), rich_tracebacks=True, show_path=False)],
    )
    return logging.getLogger("waf_detector")


def validate_target(target: str) -> str:
    cleaned = target.strip()

    if re.search(r"[\x00-\x1f\x7f]", cleaned):
        raise argparse.ArgumentTypeError(f"Target contains invalid control characters: {target!r}")

    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"

    try:
        parsed = urlparse(cleaned)
    except Exception as exc:
        raise argparse.ArgumentTypeError(f"Malformed URL: {target!r}") from exc

    host = parsed.hostname or ""

    if not host:
        raise argparse.ArgumentTypeError(f"Cannot extract hostname from: {target!r}")

    if len(host) > 253:
        raise argparse.ArgumentTypeError(f"Hostname too long: {host!r}")

    try:
        ipaddress.ip_address(host)
        return cleaned
    except ValueError:
        pass

    label_pattern = re.compile(r"^(?!-)[A-Za-z0-9\-]{1,63}(?<!-)$")
    labels = host.rstrip(".").split(".")
    if not all(label_pattern.match(lbl) for lbl in labels):
        raise argparse.ArgumentTypeError(f"Invalid hostname: {host!r}")

    return cleaned


def validate_output_path(path: str) -> str:
    import os

    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise argparse.ArgumentTypeError(f"Output directory does not exist: {directory!r}")
    if not os.access(directory, os.W_OK):
        raise argparse.ArgumentTypeError(f"Output directory is not writable: {directory!r}")
    return path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="waf-detector",
        description="WAF/Firewall Detector — signature-based fingerprinting for 15+ WAFs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  waf-detector https://example.com\n"
            "  waf-detector https://example.com -o report.json\n"
            "  waf-detector https://example.com --timeout 15 --workers 10 -v\n"
            "  waf-detector https://example.com -q\n"
        ),
    )

    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        metavar="URL",
        help="Target URL to scan (e.g. https://example.com)",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        type=validate_output_path,
        default=None,
        help="Export JSON report to FILE",
    )
    parser.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--workers",
        metavar="N",
        type=int,
        default=8,
        help="Concurrent worker threads (default: 8)",
    )
    parser.add_argument(
        "--no-port-scan",
        action="store_true",
        default=False,
        help="Skip firewall port scanning",
    )
    parser.add_argument(
        "--port-timeout",
        metavar="SECONDS",
        type=float,
        default=1.0,
        help="Per-port connect timeout (default: 1.0)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable debug logging",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress all output except raw JSON (implies --output to stdout)",
    )

    return parser


def fetch_probe(
    session: requests.Session,
    url: str,
    key: str,
    headers: dict[str, str],
    timeout: float,
    logger: logging.Logger,
) -> Optional[ProbeResult]:
    try:
        resp = session.get(url, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
        logger.debug("Probe [%s] → %s %d (%.3fs)", key, url, resp.status_code, resp.elapsed.total_seconds())
        return ProbeResult(
            key=key,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text[:8192],
            elapsed=resp.elapsed.total_seconds(),
        )
    except requests.exceptions.Timeout:
        logger.debug("Probe [%s] timed out", key)
        return None
    except requests.exceptions.ConnectionError as exc:
        logger.debug("Probe [%s] connection error: %s", key, exc)
        return None
    except Exception as exc:
        logger.debug("Probe [%s] unexpected error: %s", key, exc)
        return None


def collect_probes(
    url: str,
    timeout: float,
    max_workers: int,
    logger: logging.Logger,
    quiet: bool,
) -> list[ProbeResult]:
    tasks: list[tuple[str, str, dict[str, str]]] = []

    tasks.append(("normal", url, {"User-Agent": "Mozilla/5.0"}))

    for i, payload in enumerate(PROBE_PAYLOADS[:6]):
        tasks.append((f"payload_{i}", url + payload, {"User-Agent": "Mozilla/5.0"}))

    for i, hdrs in enumerate(PROBE_HEADERS[:6]):
        tasks.append((f"header_{i}", url, hdrs))

    session = requests.Session()
    results: list[ProbeResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(fetch_probe, session, task_url, key, hdrs, timeout, logger): key
            for key, task_url, hdrs in tasks
        }

        if not quiet:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Probing[/bold cyan] {task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task_id = progress.add_task("sending requests…", total=len(futures))
                for future in as_completed(futures):
                    result = future.result()
                    if result is not None:
                        results.append(result)
                    progress.advance(task_id)
        else:
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)

    session.close()
    return results


def analyze_headers(headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []

    for waf_name, sigs in WAF_SIGNATURES.items():
        for sig in sigs.get("headers", []):
            for header_name, header_val in headers.items():
                if sig.lower() in header_name.lower() or sig.lower() in header_val.lower():
                    findings.append(Finding(waf_name, f"Header: {header_name}: {header_val}", "HIGH", "header"))
                    break

        cookie_val = headers.get("Set-Cookie", "")
        for sig in sigs.get("cookies", []):
            if sig.lower() in cookie_val.lower():
                findings.append(Finding(waf_name, f"Cookie: {sig}", "HIGH", "cookie"))
                break

        server_val = headers.get("Server", "")
        for sig in sigs.get("server", []):
            if sig.lower() in server_val.lower():
                findings.append(Finding(waf_name, f"Server: {server_val}", "MEDIUM", "server"))
                break

    return findings


def analyze_body(body: str, status_code: int) -> list[Finding]:
    findings: list[Finding] = []
    body_lower = body.lower() if body else ""

    for waf_name, sigs in WAF_SIGNATURES.items():
        for sig in sigs.get("response", []):
            if sig.lower() in body_lower:
                findings.append(Finding(waf_name, f"Response body contains: {sig!r}", "HIGH", "response_body"))
                break

        if status_code in sigs.get("block_codes", []):
            findings.append(Finding(waf_name, f"Block status code: {status_code}", "MEDIUM", "status_code"))

    return findings


def consolidate_findings(raw: list[Finding]) -> list[ConsolidatedWAF]:
    index: dict[str, ConsolidatedWAF] = {}

    for f in raw:
        if f.waf not in index:
            index[f.waf] = ConsolidatedWAF(waf=f.waf)
        entry = index[f.waf]

        if f.evidence not in entry.evidence:
            entry.evidence.append(f.evidence)
        if f.source not in entry.sources:
            entry.sources.append(f.source)

        count = len(entry.evidence)
        if count > 2:
            entry.confidence = "VERY HIGH"
        elif count > 1:
            entry.confidence = "HIGH"
        else:
            entry.confidence = f.confidence

    return list(index.values())


def detect_wafs(probes: list[ProbeResult]) -> list[ConsolidatedWAF]:
    raw_findings: list[Finding] = []

    for probe in probes:
        raw_findings.extend(analyze_headers(probe.headers))
        raw_findings.extend(analyze_body(probe.body, probe.status_code))

    return consolidate_findings(raw_findings)


def check_firewall_ports(
    host: str,
    port_timeout: float,
    max_workers: int,
    logger: logging.Logger,
) -> list[dict]:
    open_ports: list[dict] = []

    def probe_port(port: int, description: str) -> Optional[dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(port_timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                logger.debug("Port %d (%s) is open on %s", port, description, host)
                return {"port": port, "description": description, "state": "open"}
            return None
        except OSError as exc:
            logger.debug("Port scan error on %d: %s", port, exc)
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe_port, port, desc): port for port, desc in FIREWALL_PORTS.items()}
        for future in as_completed(futures):
            outcome = future.result()
            if outcome is not None:
                open_ports.append(outcome)

    return sorted(open_ports, key=lambda x: x["port"])


def confidence_color(confidence: str) -> str:
    mapping = {
        "VERY HIGH": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }
    return mapping.get(confidence, "white")


def render_waf_table(wafs: list[ConsolidatedWAF]) -> Table:
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
        title="[bold cyan]WAF / Firewall Detection Results[/bold cyan]",
    )
    table.add_column("WAF / Product", style="bold white", min_width=20)
    table.add_column("Confidence", justify="center", min_width=12)
    table.add_column("Evidence", min_width=40)
    table.add_column("Sources", min_width=20)

    for waf in wafs:
        color = confidence_color(waf.confidence)
        evidence_text = "\n".join(f"• {e}" for e in waf.evidence[:5])
        sources_text = ", ".join(sorted(set(waf.sources)))
        table.add_row(
            waf.waf,
            Text(waf.confidence, style=color),
            evidence_text,
            sources_text,
        )

    return table


def render_port_table(ports: list[dict]) -> Table:
    table = Table(
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold yellow",
        title="[bold yellow]Open Firewall Ports[/bold yellow]",
    )
    table.add_column("Port", justify="right", style="bold white")
    table.add_column("Description", style="white")
    table.add_column("State", justify="center")

    for p in ports:
        table.add_row(str(p["port"]), p["description"], Text("OPEN", style="bold green"))

    return table


def render_probe_table(normal: Optional[ProbeResult], probes: list[ProbeResult]) -> Table:
    table = Table(
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        header_style="bold white",
        title="[bold white]Response Analysis[/bold white]",
    )
    table.add_column("Probe", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Elapsed (s)", justify="right")
    table.add_column("Flag")

    if normal is None:
        return table

    normal_elapsed = normal.elapsed

    for probe in sorted(probes, key=lambda p: p.key):
        flag = ""
        elapsed_color = "green"
        if probe.elapsed > normal_elapsed * 2 and probe.key != "normal":
            elapsed_color = "red"
            flag = "[red]⚠ Suspicious delay[/red]"

        status_color = "green" if probe.status_code < 400 else "red"
        table.add_row(
            probe.key,
            Text(str(probe.status_code), style=status_color),
            Text(f"{probe.elapsed:.3f}", style=elapsed_color),
            flag,
        )

    return table


def render_header(url: str, domain: str, scan_id: str) -> None:
    banner = Text()
    banner.append("  WAF / FIREWALL DETECTOR\n", style="bold red")
    banner.append(f"  Target : {url}\n", style="white")
    banner.append(f"  Domain : {domain}\n", style="white")
    banner.append(f"  Scan ID: {scan_id}", style="dim")
    console.print(Panel(banner, border_style="red", expand=False))


def render_recommendations(wafs: list[ConsolidatedWAF]) -> None:
    console.rule("[bold cyan]Recommendations[/bold cyan]")
    waf_names = {w.waf for w in wafs}

    if not wafs:
        console.print("\n[bold red][!][/bold red] No WAF detected — target may be unprotected.")
        console.print("    Consider: [white]Cloudflare, AWS WAF, or ModSecurity + OWASP CRS[/white]")
        return

    if "Cloudflare" in waf_names:
        console.print("[bold green][✓][/bold green] Cloudflare — verify WAF rules are set to an appropriate security level.")
    if waf_names & {"AWS WAF", "CloudFront"}:
        console.print("[bold green][✓][/bold green] AWS WAF — verify rate limiting and SQLi/XSS rules are active.")
    if "ModSecurity" in waf_names:
        console.print("[bold yellow][!][/bold yellow] ModSecurity — confirm OWASP CRS is enabled and current.")

    if waf_names & {"Cloudflare", "AWS WAF", "Akamai"}:
        console.print("\n[bold cyan]Pentest Notes:[/bold cyan] IP rotation, payload obfuscation, rate-limit evasion")
    if "ModSecurity" in waf_names:
        console.print("[bold cyan]Pentest Notes:[/bold cyan] HTTP parameter pollution, comment injection, case manipulation")
    if "Imperva/Incapsula" in waf_names:
        console.print("[bold cyan]Pentest Notes:[/bold cyan] HTTP verb tampering, encoded payloads, boundary confusion")


def build_json_report(
    scan_id: str,
    url: str,
    domain: str,
    start_time: datetime,
    duration: float,
    wafs: list[ConsolidatedWAF],
    ports: list[dict],
    normal: Optional[ProbeResult],
) -> dict:
    return {
        "scan_id": scan_id,
        "target": url,
        "domain": domain,
        "timestamp": start_time.isoformat(),
        "duration_seconds": round(duration, 3),
        "detected_wafs": [asdict(w) for w in wafs],
        "open_firewall_ports": ports,
        "normal_response": (
            {
                "status_code": normal.status_code,
                "server": normal.headers.get("Server", ""),
                "content_type": normal.headers.get("Content-Type", ""),
                "response_size_bytes": len(normal.body),
                "elapsed_seconds": normal.elapsed,
            }
            if normal
            else None
        ),
    }


def export_json(report: dict, path: str, quiet: bool) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        if not quiet:
            console.print(f"\n[bold green][✓][/bold green] Report saved → [cyan]{path}[/cyan]")
    except OSError as exc:
        console.print(f"[bold red][✗][/bold red] Export failed: {exc}", highlight=False)
        sys.exit(1)


def run_scan(args: argparse.Namespace, logger: logging.Logger) -> int:
    try:
        url = validate_target(args.target)
    except argparse.ArgumentTypeError as exc:
        console.print(f"[bold red][✗] Invalid target:[/bold red] {exc}")
        return 2

    parsed = urlparse(url)
    domain = parsed.hostname or parsed.netloc
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not args.quiet:
        render_header(url, domain, scan_id)

    start = time.monotonic()
    start_dt = datetime.now()

    logger.debug("Starting probe collection against %s", url)
    probes = collect_probes(url, args.timeout, args.workers, logger, args.quiet)

    if not probes:
        console.print("[bold red][✗][/bold red] All probes failed — target may be unreachable.")
        return 1

    logger.debug("Received %d probe responses, running WAF analysis", len(probes))
    wafs = detect_wafs(probes)
    logger.debug("Detection complete: %d WAF(s) identified", len(wafs))

    ports: list[dict] = []
    if not args.no_port_scan:
        logger.debug("Starting port scan against %s", domain)
        ports = check_firewall_ports(domain, args.port_timeout, args.workers, logger)
        logger.debug("Port scan complete: %d open port(s)", len(ports))

    duration = time.monotonic() - start

    normal = next((p for p in probes if p.key == "normal"), None)

    report = build_json_report(scan_id, url, domain, start_dt, duration, wafs, ports, normal)

    if args.quiet:
        print(json.dumps(report, indent=2, default=str))
        if args.output:
            export_json(report, args.output, quiet=True)
        return 0

    console.print()

    if wafs:
        console.print(render_waf_table(wafs))
    else:
        console.print(
            Panel(
                "[bold green]No WAF signatures matched.[/bold green]\n"
                "[yellow]Target may be unprotected or using a non-standard solution.[/yellow]",
                border_style="green",
            )
        )

    if ports:
        console.print()
        console.print(render_port_table(ports))

    if normal:
        console.print()
        console.print(render_probe_table(normal, probes))

    console.print()
    render_recommendations(wafs)

    console.rule()
    console.print(
        f"[dim]Scan ID:[/dim] [white]{scan_id}[/white]  "
        f"[dim]Duration:[/dim] [white]{duration:.2f}s[/white]  "
        f"[dim]Probes sent:[/dim] [white]{len(probes)}[/white]  "
        f"[dim]WAFs found:[/dim] [white]{len(wafs)}[/white]"
    )

    if args.output:
        export_json(report, args.output, quiet=False)

    return 0


def interactive_prompt() -> str:
    console.print(
        Panel(
            "[bold red]WAF / FIREWALL DETECTOR[/bold red]\n"
            "[dim]Signature-based detection for 15+ WAF products[/dim]",
            border_style="red",
            expand=False,
        )
    )
    try:
        target = console.input("[bold yellow][?][/bold yellow] Enter target URL: ").strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Aborted.[/yellow]")
        sys.exit(0)

    if not target:
        console.print("[bold red][✗][/bold red] No target provided.")
        sys.exit(2)

    return target


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.verbose and args.quiet:
        parser.error("--verbose and --quiet are mutually exclusive")

    logger = setup_logging(args.verbose, args.quiet)

    if args.target is None:
        if args.quiet:
            parser.error("--quiet requires a target URL as a positional argument")
        args.target = interactive_prompt()

    exit_code = run_scan(args, logger)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
