"""Shared, single-fetch HTTP context for bountyFlow collectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import requests

USER_AGENT = "bountyFlow/2.1 (authorized security assessment)"


@dataclass(frozen=True)
class TargetContext:
    """Immutable root-response data shared by header and technology collectors."""

    target: str
    requested_url: str = ""
    final_url: str = ""
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    error: str | None = None


def fetch_target_context(target: str, timeout: float = 12) -> TargetContext:
    """Fetch the root response once, preferring HTTPS and using verified TLS."""
    last_error: str | None = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            response = requests.get(
                url, timeout=timeout, allow_redirects=True, verify=True,
                headers={"User-Agent": USER_AGENT},
            )
            return TargetContext(
                target=target, requested_url=url, final_url=response.url,
                status_code=response.status_code, headers=dict(response.headers),
                body=response.text[:50_000], cookies={cookie.name: cookie.value for cookie in response.cookies},
            )
        except requests.RequestException as error:
            last_error = str(error)
    return TargetContext(target=target, error=f"HTTP(S) request failed: {last_error or 'unknown error'}")


def probe_cors(context: TargetContext, timeout: float = 10) -> dict[str, Any]:
    """Send one explicit CORS policy probe; this intentionally is a second request."""
    probe_origin = "https://bountyflow.invalid"
    result: dict[str, Any] = {"tested": True, "probe_origin": probe_origin, "allow_origin": None,
                              "allow_credentials": False, "assessment": "No permissive ACAO response observed"}
    if context.error or not context.final_url:
        return {**result, "tested": False, "assessment": "CORS probe skipped: no root HTTP response"}
    try:
        response = requests.get(
            context.final_url, timeout=timeout, allow_redirects=True, verify=True,
            headers={"User-Agent": USER_AGENT, "Origin": probe_origin},
        )
        allowed_origin = response.headers.get("Access-Control-Allow-Origin")
        credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        result.update({"allow_origin": allowed_origin, "allow_credentials": credentials})
        if allowed_origin == probe_origin and credentials:
            result["assessment"] = "Credentialed Origin reflection observed — review endpoint behavior"
        elif allowed_origin == probe_origin:
            result["assessment"] = "Origin reflection observed — review endpoint behavior"
        elif allowed_origin == "*":
            result["assessment"] = "Wildcard ACAO observed — confirm no sensitive unauthenticated data is exposed"
        elif allowed_origin:
            result["assessment"] = "Restricted ACAO response observed"
    except requests.RequestException as error:
        result.update({"tested": False, "assessment": f"CORS probe failed: {error}"})
    return result
