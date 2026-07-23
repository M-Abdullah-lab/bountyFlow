"""TLS certificate inspection for authorized web-asset assessments."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def get_ssl_info(domain: str, port: int = 443) -> dict[str, Any]:
    """Retrieve certificate metadata and separately surface wildcard DNS SANs."""
    result: dict[str, Any] = {
        "valid": False, "issuer": "Unknown", "subject": "Unknown",
        "issued_on": "Unknown", "expires_on": "Unknown", "days_remaining": None,
        "san": [], "wildcard_san": [], "tls_version": "Unknown", "error": None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_socket:
                cert = tls_socket.getpeercert()
                result["tls_version"] = tls_socket.version() or "Unknown"
                issuer = dict(item[0] for item in cert.get("issuer", []))
                subject = dict(item[0] for item in cert.get("subject", []))
                result["issuer"] = issuer.get("organizationName", "Unknown")
                result["subject"] = subject.get("commonName", domain)

                not_before, not_after = cert.get("notBefore", ""), cert.get("notAfter", "")
                if not_before:
                    result["issued_on"] = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["expires_on"] = expiry.strftime("%Y-%m-%d")
                    result["days_remaining"] = (expiry - datetime.now(timezone.utc)).days
                    result["valid"] = result["days_remaining"] >= 0

                sans = [f"{kind}: {value}" for kind, value in cert.get("subjectAltName", [])]
                # A wildcard DNS SAN can cover additional in-scope hostnames. It is a
                # prioritization signal, not a finding or permission to enumerate it.
                wildcards = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS" and value.startswith("*.")]
                result["san"] = sans[:30]
                result["wildcard_san"] = wildcards[:30]
    except ssl.SSLCertVerificationError as error:
        result["error"] = f"Certificate verification failed: {error}"
    except ssl.SSLError as error:
        result["error"] = f"TLS error: {error}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = f"Connection refused on port {port}"
    except OSError as error:
        result["error"] = f"Connection failed: {error}"
    return result
