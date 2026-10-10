from __future__ import annotations

import html
import urllib.parse
from typing import Any

from ids_parser.models import NormalizedEvent


def decode_url(data: str) -> str:
    """
    Decode percent-encoded string.
    Ví dụ: %27%20OR%201%3D1 -> ' OR 1=1
    """
    if not data:
        return data
    return urllib.parse.unquote(data)


def decode_html_entities(text: str) -> str:
    """
    Decode HTML entities cho dữ liệu text phù hợp.
    Ví dụ: &lt;script&gt; -> <script>
    """
    if not text:
        return text
    try:
        return html.unescape(text)
    except Exception:
        return text


def decode_http_data(app_data: dict[str, Any]) -> dict[str, Any]:
    """
    Decode HTTP application data:
    - Lưu raw_uri và tạo decoded_uri (hỗ trợ percent-encoding và HTML entities).
    - Hỗ trợ giải mã form urlencoded và HTML entities trong body text.
    """
    decoded = dict(app_data)

    target = decoded.get("target") or decoded.get("uri")
    if target:
        decoded["raw_uri"] = target
        # Decode URL trước, sau đó unescape HTML entities
        url_decoded = decode_url(target)
        decoded["decoded_uri"] = decode_html_entities(url_decoded)

    headers = decoded.get("headers", {})
    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = v.lower()
            break

    body = decoded.get("body", "")
    if isinstance(body, str) and body:
        decoded["raw_body"] = body

        # Giải mã URL nếu là form-urlencoded hoặc chứa %
        body_text = body
        if "application/x-www-form-urlencoded" in content_type or "%" in body:
            body_text = decode_url(body)

        # Giải mã HTML entities (ví dụ: &lt;script&gt; -> <script>)
        decoded["decoded_body"] = decode_html_entities(body_text)

    return decoded


def decode_event(event: NormalizedEvent) -> NormalizedEvent:

    if event.application_protocol == "HTTP" and event.application_data:
        try:
            event.application_data = decode_http_data(event.application_data)
        except Exception as exc:
            event.parser_status = f"decoder error: {exc}"

    return event

