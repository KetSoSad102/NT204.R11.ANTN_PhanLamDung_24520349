from __future__ import annotations

import urllib.parse
from typing import Any

from ids_parser.models import NormalizedEvent


def decode_url(data: str) -> str:

    if not data:
        return data
    return urllib.parse.unquote(data)


def decode_http_data(app_data: dict[str, Any]) -> dict[str, Any]:

    decoded = dict(app_data)

    target = decoded.get("target") or decoded.get("uri")
    if target:
        decoded["raw_uri"] = target
        decoded["decoded_uri"] = decode_url(target)

    headers = decoded.get("headers", {})
    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = v.lower()
            break

    body = decoded.get("body", "")
    if isinstance(body, str) and ("application/x-www-form-urlencoded" in content_type or "%" in body):
        decoded["raw_body"] = body
        decoded["decoded_body"] = decode_url(body)

    return decoded


def decode_event(event: NormalizedEvent) -> NormalizedEvent:

    if event.application_protocol == "HTTP" and event.application_data:
        try:
            event.application_data = decode_http_data(event.application_data)
        except Exception as exc:
            event.parser_status = f"decoder error: {exc}"

    return event

