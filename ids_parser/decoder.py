from __future__ import annotations

import base64
import html
import quopri
import urllib.parse
from typing import Any

from ids_parser.models import NormalizedEvent


def decode_bytes_safe(data: bytes) -> tuple[str, str]:
    if not data:
        return "", "ok"
    try:
        return data.decode("utf-8"), "ok"
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8", errors="replace"), "partial"
        except Exception as exc:
            return str(data), f"error: {exc}"


def decode_url(data: str) -> str:
    if not data:
        return data
    try:
        return urllib.parse.unquote(data, errors="replace")
    except Exception:
        return data


def decode_html_entities(text: str) -> str:
    if not text:
        return text
    try:
        return html.unescape(text)
    except Exception:
        return text


def decode_mime(data: str, encoding: str) -> tuple[str, str]:
    if not data:
        return "", "ok"
    enc = encoding.lower().strip()
    try:
        if enc == "base64":
            clean_b64 = "".join(data.split())
            decoded_bytes = base64.b64decode(clean_b64)
            return decoded_bytes.decode("utf-8", errors="replace"), "ok"
        elif enc in ("quoted-printable", "quopri"):
            decoded_bytes = quopri.decodestring(data.encode("latin1"))
            return decoded_bytes.decode("utf-8", errors="replace"), "ok"
        return data, "unsupported_encoding"
    except Exception as exc:
        return data, f"error: {exc}"


def decode_http_data(app_data: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(app_data)

    target = decoded.get("target") or decoded.get("uri")
    if target:
        decoded["raw_uri"] = target
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

        body_text = body
        if "application/x-www-form-urlencoded" in content_type or "%" in body:
            body_text = decode_url(body)

        decoded["decoded_body"] = decode_html_entities(body_text)

    return decoded


def decode_smtp_data(app_data: dict[str, Any], raw_payload: bytes | None = None) -> dict[str, Any]:
    decoded = dict(app_data)
    text = ""
    if "body" in decoded and isinstance(decoded["body"], str):
        text = decoded["body"]
    elif raw_payload:
        text = raw_payload.decode("utf-8", errors="replace")
    elif "argument" in decoded and isinstance(decoded["argument"], str):
        text = decoded["argument"]

    if not text:
        return decoded

    headers: dict[str, str] = {}
    body = text

    if "\r\n\r\n" in text:
        header_part, body = text.split("\r\n\r\n", 1)
        for line in header_part.split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
    elif "\n\n" in text:
        header_part, body = text.split("\n\n", 1)
        for line in header_part.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

    encoding = headers.get("content-transfer-encoding")
    if not encoding:
        for k, v in decoded.get("headers", {}).items():
            if k.lower() == "content-transfer-encoding":
                encoding = v
                break

    if encoding:
        decoded_body, decode_status = decode_mime(body, encoding)
        decoded["raw_body"] = body
        decoded["decoded_body"] = decoded_body
        decoded["decode_status"] = decode_status
        decoded["encoding"] = encoding

    return decoded


def decode_event(event: NormalizedEvent) -> NormalizedEvent:
    if event.payload_b64:
        try:
            raw_payload = base64.b64decode(event.payload_b64)
            _, char_status = decode_bytes_safe(raw_payload)
            if char_status == "partial":
                if not isinstance(event.application_data, dict):
                    event.application_data = {}
                event.application_data["char_decode_status"] = "partial"
                if event.parser_status == "ok":
                    event.parser_status = "partial"
        except Exception:
            if not isinstance(event.application_data, dict):
                event.application_data = {}
            event.application_data["char_decode_status"] = "error"
            if event.parser_status == "ok":
                event.parser_status = "error"

    if event.application_protocol == "HTTP" and event.application_data:
        try:
            event.application_data = decode_http_data(event.application_data)
        except Exception as exc:
            event.parser_status = f"decoder error: {exc}"
    elif event.application_protocol == "SMTP":
        try:
            raw_payload = None
            if event.payload_b64:
                raw_payload = base64.b64decode(event.payload_b64)
            event.application_data = decode_smtp_data(event.application_data, raw_payload)
            if "decoded_body" in event.application_data:
                event.parser_status = "ok"
        except Exception as exc:
            event.parser_status = f"decoder error: {exc}"

    return event
