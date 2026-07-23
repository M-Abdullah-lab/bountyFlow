"""
security_headers.py
--------------------
Analyzes HTTP response headers for the presence/absence of security controls.

WHY SECURITY HEADERS MATTER:
- Content-Security-Policy (CSP): Prevents XSS by whitelisting allowed content sources
- Strict-Transport-Security (HSTS): Forces HTTPS, prevents SSL stripping attacks
- X-Frame-Options: Blocks clickjacking attacks by preventing iframe embedding
- X-Content-Type-Options: Prevents MIME-type sniffing attacks
- Referrer-Policy: Controls what info leaks via the Referer header
- Permissions-Policy: Restricts browser features (camera, mic, geolocation)
- X-XSS-Protection: Legacy XSS filter (mostly deprecated but still checked)

MISSING HEADERS = Attack surface for bug bounty findings
Analysts check these to estimate the security maturity of a target.
"""

from typing import Dict, Any

# Security headers to check with explanations
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Prevents XSS attacks by defining trusted content sources",
        "severity": "HIGH",
    },
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (prevents SSL stripping)",
        "severity": "HIGH",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking via iframe embedding",
        "severity": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing attacks",
        "severity": "MEDIUM",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "LOW",
    },
    "Permissions-Policy": {
        "description": "Restricts browser feature access (camera, mic, etc.)",
        "severity": "MEDIUM",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still informative)",
        "severity": "LOW",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context against cross-origin attacks",
        "severity": "MEDIUM",
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Controls cross-origin resource embedding",
        "severity": "LOW",
    },
}

# Headers that should NOT be present (information disclosure)
LEAKY_HEADERS = [
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "Server",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
]



from modules.http_client import TargetContext, fetch_target_context, probe_cors


def analyze_headers(domain: str, context: TargetContext | None = None) -> Dict[str, Any]:
    """Analyze security controls from the shared root HTTP response.

    A context can be supplied by the orchestrator to ensure technology
    fingerprinting and header analysis do not fetch the root page twice.
    """
    context = context or fetch_target_context(domain)
    result: Dict[str, Any] = {
        "url": context.final_url, "status_code": context.status_code,
        "server": "Unknown", "content_type": "Unknown", "present_headers": {},
        "missing_headers": {}, "leaky_headers": {}, "all_headers": dict(context.headers),
        "security_score": 0, "cors": probe_cors(context), "error": context.error,
    }
    if context.error:
        return result

    headers = {key.lower(): value for key, value in context.headers.items()}
    result["server"] = headers.get("server", "Not disclosed")
    result["content_type"] = headers.get("content-type", "Unknown")
    for header, meta in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if value is not None:
            result["present_headers"][header] = {
                "value": value[:120] + "..." if len(value) > 120 else value,
                "description": meta["description"], "severity": meta["severity"],
            }
        else:
            result["missing_headers"][header] = dict(meta)
    for header in LEAKY_HEADERS:
        if header.lower() in headers:
            result["leaky_headers"][header] = headers[header.lower()]

    weights = {"HIGH": 25, "MEDIUM": 15, "LOW": 10}
    earned = sum(weights[item["severity"]] for item in result["present_headers"].values())
    maximum = sum(weights[item["severity"]] for item in SECURITY_HEADERS.values())
    result["security_score"] = int((earned / maximum) * 100) if maximum else 0
    return result
