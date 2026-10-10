from __future__ import annotations

import re
from typing import Any

from ids_parser.models import NormalizedEvent


def normalize_domain(domain: str | None) -> str | None:
    if not domain:
        return domain
    return domain.strip().lower().rstrip(".")


def normalize_uri_path(path: str | None) -> str | None:
    if not path:
        return path
    stripped = path.strip()
    prefix = ""
    rest = stripped
    if stripped.startswith("http://"):
        prefix = "http://"
        rest = stripped[7:]
    elif stripped.startswith("https://"):
        prefix = "https://"
        rest = stripped[8:]

    normalized = re.sub(r"/+", "/", rest)
    if not prefix and not normalized.startswith("/"):
        normalized = "/" + normalized

    return prefix + normalized


def normalize_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    if not headers:
        return {}
    return {str(k).strip().lower(): v for k, v in headers.items()}


def preprocess_event(event: NormalizedEvent) -> NormalizedEvent:
    if event.network_protocol:
        net_proto = event.network_protocol.strip().upper()
        event.network_protocol = "IPv4" if net_proto == "IPV4" else net_proto

    if event.transport_protocol:
        event.transport_protocol = event.transport_protocol.strip().upper()

    if event.application_protocol:
        event.application_protocol = event.application_protocol.strip().upper()

    if event.src_ip:
        event.src_ip = event.src_ip.strip().lower()

    if event.dst_ip:
        event.dst_ip = event.dst_ip.strip().lower()

    try:
        event.timestamp = float(event.timestamp)
    except (ValueError, TypeError):
        pass

    if isinstance(event.application_data, dict):
        if "headers" in event.application_data:
            event.application_data["headers"] = normalize_headers(event.application_data["headers"])

        if "domain" in event.application_data:
            event.application_data["domain"] = normalize_domain(event.application_data["domain"])

        if "target" in event.application_data:
            event.application_data["target"] = normalize_uri_path(event.application_data["target"])

        if "raw_uri" in event.application_data:
            event.application_data["raw_uri"] = event.application_data["raw_uri"].strip()

        if "decoded_uri" in event.application_data:
            event.application_data["decoded_uri"] = normalize_uri_path(event.application_data["decoded_uri"])

        if "answers" in event.application_data and isinstance(event.application_data["answers"], list):
            for ans in event.application_data["answers"]:
                if isinstance(ans, dict) and "name" in ans:
                    ans["name"] = normalize_domain(ans["name"])

    return event

