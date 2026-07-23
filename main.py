#!/usr/bin/env python3
"""bountyFlow — authorized web-asset reconnaissance.

Created by M-Abdullah-lab. This tool is intentionally limited to low-impact,
read-only collection by default. A small common-port connect scan is opt-in and
requires an explicit authorization acknowledgement.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import socket
import sys
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.dns_lookup import get_dns_records
from modules.port_scanner import run_port_scan, run_udp_scan
from modules.http_client import fetch_target_context
from modules.report_generator import generate_reports
from modules.security_headers import analyze_headers
from modules.ssl_checker import get_ssl_info
from modules.tech_detector import detect_technologies
from modules.whois_lookup import get_whois_info

APP_NAME = "bountyFlow"
VERSION = "2.1.0"
AUTHOR = "M-Abdullah-lab"
console = Console()


def normalize_target(value: str) -> str:
    """Accept a hostname or URL and return a safe hostname for socket APIs."""
    raw = value.strip()
    if not raw:
        raise ValueError("Target cannot be empty.")
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Provide only a hostname or a root URL (no path, query, or credentials).")
    host = parsed.hostname
    if not host:
        raise ValueError("Could not read a hostname from the target.")
    try:
        return host.encode("idna").decode("ascii").rstrip(".").lower()
    except UnicodeError as error:
        raise ValueError(f"Invalid hostname: {error}") from error


def resolve_host(host: str) -> dict[str, Any]:
    result: dict[str, Any] = {"ipv4": [], "ipv6": [], "hostname": "No reverse DNS", "error": None}
    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in addresses:
            address = sockaddr[0]
            key = "ipv6" if family == socket.AF_INET6 else "ipv4"
            if address not in result[key]:
                result[key].append(address)
        if result["ipv4"]:
            try:
                result["hostname"] = socket.gethostbyaddr(result["ipv4"][0])[0]
            except OSError:
                pass
    except socket.gaierror as error:
        result["error"] = f"DNS resolution failed: {error}"
    return result


def run_collection(target: str, include_ports: bool, include_udp: bool = False) -> dict[str, Any]:
    """Collect independent signals concurrently and share one root HTTP response."""
    collected: dict[str, Any] = {
        "tool": {"name": APP_NAME, "version": VERSION, "author": AUTHOR},
        "target": target, "scan_time": datetime.now(timezone.utc).isoformat(),
        "ip_info": {}, "headers": {}, "ssl": {}, "dns": {}, "whois": {}, "tech": {},
        "ports": {"skipped": not include_ports, "reason": "TCP port scan not requested" if not include_ports else None},
        "udp": {"skipped": not include_udp, "reason": "UDP probe not requested" if not include_udp else None},
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            "ip_info": executor.submit(resolve_host, target),
            "http": executor.submit(fetch_target_context, target),
            "ssl": executor.submit(get_ssl_info, target),
            "dns": executor.submit(get_dns_records, target),
            "whois": executor.submit(get_whois_info, target),
        }
        # Schedule network scans immediately after address resolution rather than
        # waiting for unrelated WHOIS/TLS/HTTP tasks to complete.
        try:
            collected["ip_info"] = futures["ip_info"].result()
        except Exception as error:
            collected["ip_info"] = {"error": str(error), "ipv4": []}
        address = (collected["ip_info"].get("ipv4") or [None])[0]
        scan_futures: dict[str, Any] = {}
        if address:
            if include_ports:
                scan_futures["ports"] = executor.submit(run_port_scan, address)
            if include_udp:
                scan_futures["udp"] = executor.submit(run_udp_scan, address)
        elif include_ports or include_udp:
            reason = "No IPv4 address resolved"
            if include_ports: collected["ports"] = {"skipped": True, "reason": reason, "open": [], "closed": []}
            if include_udp: collected["udp"] = {"skipped": True, "reason": reason, "responding": [], "no_response": []}

        try:
            context = futures["http"].result()
        except Exception as error:
            context = None
            collected["headers"] = {"error": str(error)}
            collected["tech"] = {"error": str(error)}
        if context is not None:
            scan_futures["headers"] = executor.submit(analyze_headers, target, context)
            scan_futures["tech"] = executor.submit(detect_technologies, target, context)

        for name in ("ssl", "dns", "whois"):
            try: collected[name] = futures[name].result()
            except Exception as error: collected[name] = {"error": str(error)}
        for name, future in scan_futures.items():
            try: collected[name] = future.result()
            except Exception as error: collected[name] = {"error": str(error)}
    return collected

def print_banner() -> None:
    console.print(Panel.fit(
        f"[bold cyan]{APP_NAME}[/bold cyan] [dim]v{VERSION}[/dim]\n"
        "[white]Authorization-first asset reconnaissance[/white]\n"
        f"[dim]Created by {AUTHOR}[/dim]",
        border_style="cyan",
    ))


def show_results(data: dict[str, Any]) -> None:
    ip = data.get("ip_info", {})
    overview = Table(title="Target overview", box=box.ROUNDED, border_style="cyan")
    overview.add_column("Field", style="bold cyan", width=18)
    overview.add_column("Value")
    overview.add_row("Target", data["target"])
    overview.add_row("IPv4", ", ".join(ip.get("ipv4", [])) or "Not resolved")
    overview.add_row("IPv6", ", ".join(ip.get("ipv6", [])) or "Not resolved")
    overview.add_row("PTR", ip.get("hostname", "N/A"))
    overview.add_row("Collected (UTC)", data["scan_time"])
    console.print(overview)

    headers = data.get("headers", {})
    score = headers.get("security_score", 0)
    color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    http = Table(title="HTTP & security headers", box=box.ROUNDED, border_style=color)
    http.add_column("Field", style="bold cyan", width=22)
    http.add_column("Value")
    http.add_row("Final URL", str(headers.get("url", "Unavailable")))
    http.add_row("Status", str(headers.get("status_code", "N/A")))
    http.add_row("Server", str(headers.get("server", "Not disclosed")))
    http.add_row("Header score", f"[{color}]{score}/100[/{color}]")
    http.add_row("Missing controls", ", ".join(headers.get("missing_headers", {}).keys()) or "None detected")
    http.add_row("CORS probe", str(headers.get("cors", {}).get("assessment", "Not tested")))
    console.print(http)

    ssl_data = data.get("ssl", {})
    tls = Table(title="TLS certificate", box=box.ROUNDED, border_style="green" if ssl_data.get("valid") else "yellow")
    tls.add_column("Field", style="bold cyan", width=18)
    tls.add_column("Value")
    for label, key in (("Valid", "valid"), ("TLS", "tls_version"), ("Issuer", "issuer"), ("Subject", "subject"), ("Expires", "expires_on"), ("Days remaining", "days_remaining")):
        tls.add_row(label, str(ssl_data.get(key, "N/A")))
    wildcards = ssl_data.get("wildcard_san", [])
    if wildcards:
        tls.add_row("Wildcard SANs", f"[yellow]{', '.join(wildcards)}[/yellow]")
    console.print(tls)

    dns = data.get("dns", {})
    dns_table = Table(title="DNS records", box=box.ROUNDED, border_style="magenta")
    dns_table.add_column("Type", style="bold cyan", width=10)
    dns_table.add_column("Values")
    for record_type, values in dns.items():
        dns_table.add_row(record_type, "\n".join(values[:8]) if values else "—")
    console.print(dns_table)

    tech = data.get("tech", {})
    tech_table = Table(title="Technology signals", box=box.ROUNDED, border_style="blue")
    tech_table.add_column("Category", style="bold cyan", width=22)
    tech_table.add_column("Detected")
    if tech.get("generator"):
        tech_table.add_row("Generator", str(tech["generator"]))
    for category, values in tech.get("technologies", {}).items():
        tech_table.add_row(category, ", ".join(values))
    if not tech.get("technologies") and not tech.get("generator"):
        tech_table.add_row("Result", "No signals detected")
    console.print(tech_table)

    whois = data.get("whois", {})
    registration = Table(title="Domain registration", box=box.ROUNDED, border_style="yellow")
    registration.add_column("Field", style="bold cyan", width=18)
    registration.add_column("Value")
    for label, key in (("Registrar", "registrar"), ("Organization", "org"), ("Created", "creation_date"), ("Expires", "expiry_date"), ("DNSSEC", "dnssec")):
        registration.add_row(label, str(whois.get(key, "Unavailable")))
    if whois.get("error"):
        registration.add_row("Note", f"[yellow]{whois['error']}[/yellow]")
    console.print(registration)

    ports = data.get("ports", {})
    if ports.get("skipped"):
        console.print(Panel(f"[dim]Port scan skipped: {ports.get('reason', 'not requested')}[/dim]", title="Ports", border_style="dim"))
    else:
        open_ports = ports.get("open", [])
        message = "\n".join(
            f"[green]OPEN[/green] {item['port']}/tcp — {item['service']}" + (f" [dim]{item['banner']}[/dim]" if item.get("banner") else "")
            for item in open_ports
        ) or "No open ports in the small common-port set."
        console.print(Panel(message, title="TCP ports (authorized scan)", border_style="red" if open_ports else "green"))

    udp = data.get("udp", {})
    if udp.get("skipped"):
        console.print(Panel(f"[dim]UDP probe skipped: {udp.get('reason', 'not requested')}[/dim]", title="UDP", border_style="dim"))
    else:
        responding = udp.get("responding", [])
        message = "\n".join(f"[green]RESPONDING[/green] {item['port']}/udp — {item['service']}" for item in responding) or "No response; UDP silence is ambiguous."
        console.print(Panel(message, title="UDP probes (authorized scan)", border_style="yellow"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="bountyFlow: authorization-first web-asset reconnaissance")
    parser.add_argument("target", nargs="?", help="Hostname or root URL to assess")
    parser.add_argument("--authorized", action="store_true", help="Confirm you own the target or have explicit permission")
    parser.add_argument("--ports", action="store_true", help="Run a small TCP connect scan with bounded banner reads (requires --authorized)")
    parser.add_argument("--udp", action="store_true", help="Run minimal UDP response probes for DNS and NTP (requires --authorized)")
    parser.add_argument("--output", default="reports", help="Report directory (default: reports)")
    parser.add_argument("--no-report", action="store_true", help="Display results without writing JSON/TXT reports")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    print_banner()
    target_input = args.target or console.input("[bold cyan]Target hostname or root URL:[/bold cyan] ")
    try:
        target = normalize_target(target_input)
    except ValueError as error:
        console.print(f"[red]Invalid target:[/red] {error}")
        return 2

    if not args.authorized:
        console.print("[red]Refusing to run without --authorized.[/red] Confirm you own the target or have explicit permission.")
        return 2
    if (args.ports or args.udp) and not args.authorized:  # defensive guard if parser behavior changes
        console.print("[red]--ports and --udp require --authorized.[/red]")
        return 2

    console.print(f"[dim]Collecting read-only signals for {target}…[/dim]")
    data = run_collection(target, args.ports, args.udp)
    show_results(data)
    if not args.no_report:
        paths = generate_reports(target, data, args.output)
        console.print(f"[green]Reports saved:[/green] {paths['json']} and {paths['txt']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
