"""Evidence-based technology fingerprinting with externally managed rules."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from modules.http_client import TargetContext, fetch_target_context

SIGNATURES_FILE = Path(__file__).with_name("signatures.json")
REQUIRED_SIGNATURE_FIELDS = {"type", "header", "pattern", "technology", "category"}


def load_signatures(path: Path = SIGNATURES_FILE) -> list[dict[str, Any]]:
    """Load and validate user-editable fingerprint rules without executing code."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not load signature rules from {path.name}: {error}") from error
    if not isinstance(payload, list):
        raise ValueError("Signature rules must be a JSON array.")
    valid: list[dict[str, Any]] = []
    for index, rule in enumerate(payload, start=1):
        if not isinstance(rule, dict) or not REQUIRED_SIGNATURE_FIELDS.issubset(rule):
            raise ValueError(f"Invalid signature rule at index {index}.")
        if rule["type"] not in {"header", "body", "cookie"}:
            raise ValueError(f"Unsupported signature type at index {index}.")
        if rule["pattern"] is not None:
            try:
                re.compile(rule["pattern"], re.IGNORECASE)
            except (TypeError, re.error) as error:
                raise ValueError(f"Invalid regex in signature rule {index}: {error}") from error
        valid.append(rule)
    return valid


def detect_technologies(domain: str, context: TargetContext | None = None) -> dict[str, Any]:
    """Fingerprint the shared root response; no additional root request is made."""
    result: dict[str, Any] = {"technologies": {}, "raw_signals": [], "generator": None, "error": None}
    try:
        signatures = load_signatures()
    except ValueError as error:
        result["error"] = str(error)
        return result
    context = context or fetch_target_context(domain)
    if context.error:
        result["error"] = context.error
        return result

    headers = {key.lower(): value for key, value in context.headers.items()}
    body, cookies = context.body, "; ".join(f"{name}={value}" for name, value in context.cookies.items())
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
    if generator:
        result["generator"] = generator.group(1)
    detected: dict[str, str] = {}
    for rule in signatures:
        source = headers.get(str(rule["header"]).lower(), "") if rule["type"] == "header" else body if rule["type"] == "body" else cookies
        pattern = rule["pattern"]
        matched = bool(source) if pattern is None else bool(re.search(pattern, source, re.I))
        if matched and rule["technology"] not in detected:
            detected[rule["technology"]] = rule["category"]
            result["raw_signals"].append(f"{rule['type'].upper()} → {rule['technology']}")
    for technology, category in detected.items():
        result["technologies"].setdefault(category, []).append(technology)
    return result
