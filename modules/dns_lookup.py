"""Low-impact DNS record collection for authorized asset inventory."""

from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA")


def _format_record(record_type: str, rdata: Any) -> str:
    """Return consistently readable output for records with structured fields."""
    if record_type == "MX":
        return f"{rdata.preference} {rdata.exchange}"
    if record_type == "CAA":
        # CAA is flags, tag (issue/issuewild/iodef), and issuer/property value.
        value = rdata.value.decode("utf-8", errors="replace") if isinstance(rdata.value, bytes) else str(rdata.value)
        tag = rdata.tag.decode("ascii", errors="replace") if isinstance(rdata.tag, bytes) else str(rdata.tag)
        return f"flags={rdata.flags}; {tag} {value}"
    return str(rdata)


def get_dns_records(domain: str) -> dict[str, list[str]]:
    """Collect common DNS records, including IPv6 (AAAA) and CAA policy records."""
    results: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type, lifetime=5, raise_on_no_answer=False)
            results[record_type] = [_format_record(record_type, rdata) for rdata in answers] if answers.rrset else []
        except dns.resolver.NXDOMAIN:
            results[record_type] = ["[NXDOMAIN - domain does not exist]"]
        except dns.resolver.NoNameservers as error:
            results[record_type] = [f"[No nameserver response: {error}]"]
        except dns.resolver.Timeout:
            results[record_type] = ["[Timeout - DNS server did not respond]"]
        except dns.exception.DNSException as error:
            results[record_type] = [f"[DNS error: {error}]"]
    return results

