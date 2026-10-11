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


def sanitize_missing_fields(event: NormalizedEvent) -> NormalizedEvent:
    if event.application_data is None or not isinstance(event.application_data, dict):
        event.application_data = {}

    if not event.application_protocol:
        event.application_protocol = "UNKNOWN"

    app_proto = event.application_protocol.upper()

    if app_proto == "HTTP":
        if "headers" not in event.application_data or event.application_data["headers"] is None:
            event.application_data["headers"] = {}
        if "body" not in event.application_data or event.application_data["body"] is None:
            event.application_data["body"] = ""

    elif app_proto == "DNS":
        if "answers" not in event.application_data or event.application_data["answers"] is None:
            event.application_data["answers"] = []
        if "domain" not in event.application_data:
            event.application_data["domain"] = None

    elif app_proto == "SMTP":
        if "headers" not in event.application_data or event.application_data["headers"] is None:
            event.application_data["headers"] = {}
        if "body" not in event.application_data or event.application_data["body"] is None:
            event.application_data["body"] = ""

    return event


def validate_event(event: NormalizedEvent) -> NormalizedEvent:
    if event.parser_status and event.parser_status != "ok":
        if event.parser_status.startswith("error:") or "unsupported" in event.parser_status:
            event.preprocess_status = "invalid"
            event.processing_action = "drop"
            event.reason = event.parser_status
            return event
        elif event.parser_status == "partial" or event.parser_status.startswith("application parse error:"):
            event.preprocess_status = "partial"
            event.processing_action = "flag"
            event.reason = event.parser_status

    if not isinstance(event.packet_id, int) or event.packet_id <= 0:
        event.preprocess_status = "invalid"
        event.processing_action = "drop"
        event.reason = f"invalid packet_id: {event.packet_id}"
        return event

    try:
        ts = float(event.timestamp)
        if ts < 0:
            event.preprocess_status = "invalid"
            event.processing_action = "drop"
            event.reason = f"negative timestamp: {event.timestamp}"
            return event
        event.timestamp = ts
    except (ValueError, TypeError):
        event.preprocess_status = "invalid"
        event.processing_action = "drop"
        event.reason = f"invalid timestamp: {event.timestamp}"
        return event

    if event.network_protocol:
        net_proto = str(event.network_protocol).strip().upper()
        if net_proto not in ("IPV4", "IPV6"):
            event.preprocess_status = "invalid"
            event.processing_action = "drop"
            event.reason = f"unsupported network protocol: {event.network_protocol}"
            return event

    if event.transport_protocol:
        trans_proto = str(event.transport_protocol).strip().upper()
        if trans_proto not in ("TCP", "UDP"):
            event.preprocess_status = "invalid"
            event.processing_action = "drop"
            event.reason = f"unsupported transport protocol: {event.transport_protocol}"
            return event

    if event.src_port is not None:
        if not isinstance(event.src_port, int) or not (0 <= event.src_port <= 65535):
            event.preprocess_status = "invalid"
            event.processing_action = "drop"
            event.reason = f"invalid src_port: {event.src_port}"
            return event

    if event.dst_port is not None:
        if not isinstance(event.dst_port, int) or not (0 <= event.dst_port <= 65535):
            event.preprocess_status = "invalid"
            event.processing_action = "drop"
            event.reason = f"invalid dst_port: {event.dst_port}"
            return event

    if isinstance(event.application_data, dict):
        if event.application_data.get("char_decode_status") == "partial" or event.application_data.get("decode_status") == "error":
            if event.preprocess_status == "valid":
                event.preprocess_status = "partial"
                event.processing_action = "flag"
                event.reason = "character decode error or partial"

    return event


def preprocess_event(event: NormalizedEvent) -> NormalizedEvent:
    try:
        event = sanitize_missing_fields(event)
        event = validate_event(event)

        if event.preprocess_status == "invalid":
            return event

        if event.network_protocol:
            net_proto = str(event.network_protocol).strip().upper()
            event.network_protocol = "IPv4" if net_proto == "IPV4" else net_proto

        if event.transport_protocol:
            event.transport_protocol = str(event.transport_protocol).strip().upper()

        if event.application_protocol:
            event.application_protocol = str(event.application_protocol).strip().upper()

        if event.src_ip:
            event.src_ip = str(event.src_ip).strip().lower()

        if event.dst_ip:
            event.dst_ip = str(event.dst_ip).strip().lower()

        if isinstance(event.application_data, dict):
            if "headers" in event.application_data:
                event.application_data["headers"] = normalize_headers(event.application_data["headers"])

            if "domain" in event.application_data:
                event.application_data["domain"] = normalize_domain(event.application_data["domain"])

            if "target" in event.application_data:
                event.application_data["target"] = normalize_uri_path(event.application_data["target"])

            if "raw_uri" in event.application_data and isinstance(event.application_data["raw_uri"], str):
                event.application_data["raw_uri"] = event.application_data["raw_uri"].strip()

            if "decoded_uri" in event.application_data and isinstance(event.application_data["decoded_uri"], str):
                event.application_data["decoded_uri"] = normalize_uri_path(event.application_data["decoded_uri"])

            if "answers" in event.application_data and isinstance(event.application_data["answers"], list):
                for ans in event.application_data["answers"]:
                    if isinstance(ans, dict) and "name" in ans and isinstance(ans["name"], str):
                        ans["name"] = normalize_domain(ans["name"])

    except Exception as exc:
        event.preprocess_status = "invalid"
        event.processing_action = "drop"
        event.reason = f"preprocessor error: {exc}"

    return event
