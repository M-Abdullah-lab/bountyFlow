"""Small, authorization-gated TCP/UDP service exposure checks.

The module only performs connect-style TCP checks and tiny, read-only UDP probes.
It does not authenticate, enumerate directories, or attempt exploitation.
"""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any

PORT_INFO: dict[int, dict[str, str]] = {
    21: {"service": "FTP", "risk": "Cleartext file transfer exposure"},
    22: {"service": "SSH", "risk": "Remote administration exposure"},
    23: {"service": "Telnet", "risk": "Cleartext remote administration"},
    25: {"service": "SMTP", "risk": "Mail service exposure"},
    53: {"service": "DNS", "risk": "Authoritative or recursive DNS exposure"},
    80: {"service": "HTTP", "risk": "Unencrypted web service"},
    110: {"service": "POP3", "risk": "Mail retrieval exposure"},
    143: {"service": "IMAP", "risk": "Mail access exposure"},
    443: {"service": "HTTPS", "risk": "Web service exposure"},
    445: {"service": "SMB", "risk": "File-sharing exposure"},
    3306: {"service": "MySQL", "risk": "Database exposure"},
    3389: {"service": "RDP", "risk": "Remote desktop exposure"},
    5432: {"service": "PostgreSQL", "risk": "Database exposure"},
    6379: {"service": "Redis", "risk": "Cache/database exposure"},
    8080: {"service": "HTTP-Alt", "risk": "Alternate web service"},
    8443: {"service": "HTTPS-Alt", "risk": "Alternate TLS web service"},
    8888: {"service": "HTTP-Dev", "risk": "Development web service"},
    9200: {"service": "Elasticsearch", "risk": "Search service exposure"},
    27017: {"service": "MongoDB", "risk": "Database exposure"},
}
DEFAULT_PORTS = list(PORT_INFO)
UDP_PORT_INFO = {
    53: {"service": "DNS", "risk": "DNS service exposure"},
    123: {"service": "NTP", "risk": "Time service exposure"},
}
HTTP_PORTS = {80, 8080, 8888}


def _safe_banner(data: bytes) -> str | None:
    """Make a small printable banner safe for terminal and JSON output."""
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")
    return " ".join(text.split())[:240] or None


def _grab_banner(sock: socket.socket, port: int) -> str | None:
    """Read an unsolicited greeting; HTTP receives a minimal HEAD request only."""
    try:
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        return _safe_banner(sock.recv(1024))
    except (socket.timeout, OSError):
        return None


def scan_port(ip: str, port: int, timeout: float = 1.5) -> dict[str, Any]:
    """Perform one TCP connect check and a bounded, non-authenticating banner read."""
    service = PORT_INFO.get(port, {}).get("service", "Unknown")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return {"port": port, "open": True, "service": service, "banner": _grab_banner(sock, port)}
    except OSError:
        return {"port": port, "open": False, "service": service, "banner": None}


def run_port_scan(ip: str, ports: list[int] | None = None, max_workers: int = 20) -> dict[str, list[dict[str, Any]]]:
    """Scan a deliberately small TCP port set concurrently."""
    ports = DEFAULT_PORTS if ports is None else ports
    open_ports: list[dict[str, Any]] = []
    closed_ports: list[dict[str, Any]] = []
    if not ports:
        return {"open": open_ports, "closed": closed_ports}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as executor:
        for outcome in executor.map(lambda port: scan_port(ip, port), ports):
            entry = {**outcome, "risk": PORT_INFO.get(outcome["port"], {}).get("risk", "Unknown")}
            (open_ports if outcome["open"] else closed_ports).append(entry)
    return {"open": sorted(open_ports, key=lambda item: item["port"]), "closed": sorted(closed_ports, key=lambda item: item["port"])}


def _udp_probe(port: int) -> bytes:
    """Return a tiny, protocol-shaped UDP probe."""
    if port == 123:  # NTP client request, 48 bytes, no state-changing fields.
        return b"\x1b" + (b"\0" * 47)
    if port == 53:  # Minimal DNS header; a response indicates a reachable listener.
        return b"\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    return b"\x00"  # Reserved fallback for explicitly supplied custom UDP ports.


def scan_udp_port(ip: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
    """Send one minimal UDP probe and report only a response or no response.

    UDP silence is inherently ambiguous (closed, filtered, or non-responsive), so
    it is never labelled as a closed port.
    """
    service = UDP_PORT_INFO.get(port, {}).get("service", "Unknown")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(_udp_probe(port), (ip, port))
            data, _ = sock.recvfrom(1024)
            return {"port": port, "service": service, "state": "responding", "response": _safe_banner(data)}
    except (socket.timeout, OSError):
        return {"port": port, "service": service, "state": "no_response", "response": None}


def run_udp_scan(ip: str, ports: list[int] | None = None, max_workers: int = 3) -> dict[str, list[dict[str, Any]]]:
    """Run a small UDP response check for DNS and NTP."""
    ports = list(UDP_PORT_INFO) if ports is None else ports
    if not ports:
        return {"responding": [], "no_response": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as executor:
        results = list(executor.map(lambda port: scan_udp_port(ip, port), ports))
    return {"responding": [item for item in results if item["state"] == "responding"], "no_response": [item for item in results if item["state"] == "no_response"]}
